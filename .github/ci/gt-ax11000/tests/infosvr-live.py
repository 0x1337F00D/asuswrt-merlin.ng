#!/usr/bin/env python3
"""Read-only LAN smoke test for the GT-AX11000 infosvr protocol.

The router's replies contain deployment-specific values (SSID, MAC and
firmware information), so this test deliberately validates them without ever
printing packet contents.
"""

import ipaddress
import socket
import sys
import time


PDU_LEN = 512
PORT = 9999
SERVICE_IBOX_INFO = 12
PACKET_COMMAND = 21
PACKET_RESPONSE = 22
CMD_GETINFO = 31
CMD_GETINFO_EX2 = 53
CMD_FIND_CAP = 54
GROUP_ID_TYPE = 1
RESPONSE_TIMEOUT = 3.0
SILENCE_TIMEOUT = 0.75
FIND_CAP_GAP = 2.1


class TestFailure(Exception):
    """A safe, deliberately non-sensitive test failure."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def packet(opcode, length=PDU_LEN, transaction=None):
    data = bytearray(max(PDU_LEN, length))
    data[0] = SERVICE_IBOX_INFO
    data[1] = PACKET_COMMAND
    data[2:4] = opcode.to_bytes(2, "little")
    if transaction is not None:
        data[4:8] = transaction
        # The all-FF target is accepted by the daemon without revealing the
        # router's MAC address.
        data[8:14] = b"\xff" * 6
    return bytes(data[:length])


def drain(sock):
    """Remove already queued broadcasts before starting a new transaction."""
    old_timeout = sock.gettimeout()
    sock.settimeout(0.0)
    try:
        while True:
            try:
                sock.recvfrom(PDU_LEN + 1)
            except (BlockingIOError, socket.timeout):
                return
    finally:
        sock.settimeout(old_timeout)


def send(sock, router_ip, data, code):
    try:
        sock.sendto(data, (router_ip, PORT))
    except OSError:
        raise TestFailure(code)


def recv_from_router(sock, router_ip, timeout, code):
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TestFailure(code)
        sock.settimeout(remaining)
        try:
            data, source = sock.recvfrom(PDU_LEN + 1)
        except socket.timeout:
            raise TestFailure(code)
        except OSError:
            raise TestFailure("RECEIVE_ERROR")
        if source[0] == router_ip:
            return data


def expect_silence(sock, router_ip, code):
    deadline = time.monotonic() + SILENCE_TIMEOUT
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        sock.settimeout(remaining)
        try:
            data, source = sock.recvfrom(PDU_LEN + 1)
        except socket.timeout:
            return
        except OSError:
            raise TestFailure("RECEIVE_ERROR")
        if source[0] == router_ip:
            # Any router datagram is a failure here; its contents are not
            # printed because they may contain identifying configuration.
            del data
            raise TestFailure(code)


def check_response_header(data, opcode, code):
    if len(data) != PDU_LEN:
        raise TestFailure(code + "_LENGTH")
    if data[0:2] != bytes((SERVICE_IBOX_INFO, PACKET_RESPONSE)):
        raise TestFailure(code + "_HEADER")
    if int.from_bytes(data[2:4], "little") != opcode:
        raise TestFailure(code + "_OPCODE")


def find_group_id(data):
    """Extract the type-1, exactly 20-byte group ID from FIND_CAP TLVs."""
    cursor = 12
    while cursor + 2 <= PDU_LEN:
        kind = data[cursor]
        value_len = data[cursor + 1]
        cursor += 2
        end = cursor + value_len
        if end > PDU_LEN:
            raise TestFailure("FIND_CAP_TLV_BOUNDS")
        if kind == GROUP_ID_TYPE and value_len == 20:
            return data[cursor:end]
        cursor = end
        if kind == 0 and value_len == 0:
            break
    raise TestFailure("FIND_CAP_GROUP_ID_MISSING")


def validate_router_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise TestFailure("INVALID_ROUTER_IP")
    if address.version != 4:
        raise TestFailure("ROUTER_IP_NOT_IPV4")
    return str(address)


def run(router_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("0.0.0.0", 0))
    try:
        # A normal GETINFO request must produce one exact-size response.
        drain(sock)
        send(sock, router_ip, packet(CMD_GETINFO), "SEND_GETINFO_ERROR")
        getinfo = recv_from_router(sock, router_ip, RESPONSE_TIMEOUT, "GETINFO_TIMEOUT")
        check_response_header(getinfo, CMD_GETINFO, "GETINFO_RESPONSE")
        print("GETINFO_LEN=512")

        # The daemon accepts only exact 512-byte PDUs and implemented opcodes.
        drain(sock)
        send(sock, router_ip, packet(0xFFFF), "SEND_INVALID_OPCODE_ERROR")
        expect_silence(sock, router_ip, "INVALID_OPCODE_RESPONDED")
        print("INVALID_OPCODE=PASS")

        drain(sock)
        send(sock, router_ip, packet(CMD_GETINFO, 511), "SEND_511_ERROR")
        expect_silence(sock, router_ip, "INVALID_LEN_511_RESPONDED")
        print("INVALID_LEN_511=PASS")

        drain(sock)
        send(sock, router_ip, packet(CMD_GETINFO, 513), "SEND_513_ERROR")
        expect_silence(sock, router_ip, "INVALID_LEN_513_RESPONDED")
        print("INVALID_LEN_513=PASS")

        transaction = bytes((0x13, 0x37, 0xC0, 0xDE))
        drain(sock)
        send(
            sock,
            router_ip,
            packet(CMD_GETINFO_EX2, transaction=transaction),
            "SEND_GETINFO_EX2_ERROR",
        )
        getinfo_ex2 = recv_from_router(
            sock, router_ip, RESPONSE_TIMEOUT, "GETINFO_EX2_TIMEOUT"
        )
        check_response_header(getinfo_ex2, CMD_GETINFO_EX2, "GETINFO_EX2_RESPONSE")
        if getinfo_ex2[4:8] != transaction:
            raise TestFailure("GETINFO_EX2_TRANSACTION_MISMATCH")
        print("GETINFO_EX2_TRANSACTION=PASS")

        drain(sock)
        send(sock, router_ip, packet(CMD_FIND_CAP), "SEND_FIND_CAP_1_ERROR")
        first = recv_from_router(sock, router_ip, RESPONSE_TIMEOUT, "FIND_CAP_1_TIMEOUT")
        first_received = time.monotonic()
        check_response_header(first, CMD_FIND_CAP, "FIND_CAP_1_RESPONSE")
        first_group = find_group_id(first)
        # Discard duplicate broadcasts from the first request before waiting.
        drain(sock)

        wait = FIND_CAP_GAP - (time.monotonic() - first_received)
        if wait > 0:
            time.sleep(wait)
        send(sock, router_ip, packet(CMD_FIND_CAP), "SEND_FIND_CAP_2_ERROR")
        second = recv_from_router(sock, router_ip, RESPONSE_TIMEOUT, "FIND_CAP_2_TIMEOUT")
        second_received = time.monotonic()
        check_response_header(second, CMD_FIND_CAP, "FIND_CAP_2_RESPONSE")
        second_group = find_group_id(second)
        gap_ms = int(round((second_received - first_received) * 1000))
        if gap_ms <= 2000:
            raise TestFailure("FIND_CAP_GAP_TOO_SHORT")
        if first_group != second_group:
            raise TestFailure("FIND_CAP_GROUP_ID_MISMATCH")
        print("FIND_CAP_GAP_MS={}".format(gap_ms))
        print("FIND_CAP_GROUP_ID_LEN=20")
        print("FIND_CAP_GROUP_ID_MATCH=PASS")
    finally:
        sock.close()


def main(argv):
    if len(argv) != 2:
        print("RESULT=FAIL")
        print("ERROR=USAGE")
        print("USAGE=infosvr-live.py ROUTER_IP")
        return 2

    try:
        router_ip = validate_router_ip(argv[1])
        print("ROUTER_IP={}".format(router_ip))
        run(router_ip)
    except TestFailure as error:
        print("RESULT=FAIL")
        print("ERROR={}".format(error.code))
        return 1
    except OSError:
        print("RESULT=FAIL")
        print("ERROR=SOCKET_SETUP")
        return 1
    except KeyboardInterrupt:
        print("RESULT=FAIL")
        print("ERROR=INTERRUPTED")
        return 1

    print("RESULT=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
