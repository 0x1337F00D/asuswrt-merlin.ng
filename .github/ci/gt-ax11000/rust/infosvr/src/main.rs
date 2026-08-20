#[cfg(not(target_arch = "arm"))]
use infosvr::calculate_capabilities;
use infosvr::{
    build_response, decode_group_id, parse_mac, parse_request, DeviceState, Request, PDU_LEN,
    SERVER_PORT,
};
use std::collections::VecDeque;
use std::env;
#[cfg(target_arch = "arm")]
use std::ffi::{c_char, CStr};
use std::ffi::{c_int, c_void, CString};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::Command;
#[cfg(any(target_arch = "arm", test))]
use std::sync::OnceLock;
use std::time::{Duration, Instant};
#[cfg(target_arch = "arm")]
use std::time::{SystemTime, UNIX_EPOCH};

const SOL_SOCKET: c_int = 1;
const SO_BINDTODEVICE: c_int = 25;
const MAX_INTERFACES: usize = 5;
const DUPLICATE_WINDOW: Duration = Duration::from_secs(2);
const MAX_RECENT_REQUESTS: usize = 64;
const EXTEND_CAP_AAE_BASIC: u16 = 0x0010;
const GT_AX11000_APP_API_LEVEL: u8 = 2;
const AIHOME_API_LEVEL: u8 = 23;

#[cfg(target_arch = "arm")]
#[link(name = "nvram")]
extern "C" {
    fn nvram_get(name: *const c_char) -> *const c_char;
    #[link_name = "get_discovery_ssid"]
    fn platform_get_discovery_ssid(buffer: *mut c_char, size: c_int) -> c_int;
    #[link_name = "get_extend_cap"]
    fn platform_get_extend_cap() -> u16;
}

extern "C" {
    #[cfg(target_arch = "arm")]
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    #[cfg(target_arch = "arm")]
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    #[cfg(target_arch = "arm")]
    fn dlclose(handle: *mut c_void) -> c_int;
    #[cfg(target_arch = "arm")]
    fn free(pointer: *mut c_void);
}

extern "C" {
    fn setsockopt(
        socket: c_int,
        level: c_int,
        option_name: c_int,
        option_value: *const c_void,
        option_len: u32,
    ) -> c_int;
}

trait Config {
    fn get(&self, key: &str) -> String;

    fn get_i32(&self, key: &str) -> i32 {
        self.get(key).parse().unwrap_or(0)
    }

    fn enabled(&self, key: &str) -> bool {
        self.get_i32(key) != 0
    }
}

struct Nvram;

#[cfg(target_arch = "arm")]
impl Config for Nvram {
    fn get(&self, key: &str) -> String {
        let Ok(key) = CString::new(key) else {
            return String::new();
        };
        // SAFETY: `key` is NUL-terminated for the call. Asuswrt's nvram_get
        // returns either null or a stable NUL-terminated string; the value is
        // copied immediately into an owned String.
        let value = unsafe { nvram_get(key.as_ptr()) };
        if value.is_null() {
            return String::new();
        }
        // SAFETY: a non-null nvram_get result is NUL-terminated by its API.
        unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned()
    }
}

#[cfg(not(target_arch = "arm"))]
impl Config for Nvram {
    fn get(&self, key: &str) -> String {
        let env_key = format!("INFOSVR_{}", key.to_ascii_uppercase());
        env::var(env_key).unwrap_or_default()
    }
}

#[derive(Clone, Debug)]
struct RecentRequest {
    source: IpAddr,
    opcode: u16,
    seen: Instant,
}

#[derive(Default)]
struct DuplicateGuard {
    recent: VecDeque<RecentRequest>,
}

impl DuplicateGuard {
    fn should_drop(&mut self, source: IpAddr, opcode: u16, lan_ip: IpAddr) -> bool {
        let now = Instant::now();
        while self
            .recent
            .front()
            .is_some_and(|entry| now.duration_since(entry.seen) >= DUPLICATE_WINDOW)
        {
            self.recent.pop_front();
        }

        if source == lan_ip {
            return false;
        }

        if self
            .recent
            .iter()
            .any(|entry| entry.source == source && entry.opcode == opcode)
        {
            return true;
        }

        if self.recent.len() == MAX_RECENT_REQUESTS {
            self.recent.pop_front();
        }
        self.recent.push_back(RecentRequest {
            source,
            opcode,
            seen: now,
        });
        false
    }
}

fn main() -> io::Result<()> {
    let interfaces = parse_interfaces(env::args().skip(1))?;
    write_pid_file()?;

    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, SERVER_PORT))?;
    socket.set_broadcast(true)?;
    // One extra byte distinguishes an exact PDU from a truncated oversized
    // UDP datagram; recv_from otherwise reports only the destination length.
    let mut packet = [0_u8; PDU_LEN + 1];
    let mut duplicate_guard = DuplicateGuard::default();
    let config = Nvram;

    eprintln!("infosvr-rs: listening on UDP/{SERVER_PORT} via {interfaces:?}");
    loop {
        let (received, source) = match socket.recv_from(&mut packet) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if received != PDU_LEN {
            continue;
        }

        let mac = parse_mac(&config.get("lan_hwaddr")).unwrap_or([0; 6]);
        let packet = &packet[..received];
        let Some(request) = parse_request(packet, mac) else {
            continue;
        };
        let opcode = u16::from_le_bytes([packet[2], packet[3]]);
        let lan_ip = parse_ipv4(&config.get("lan_ipaddr"));
        let lan_netmask = parse_ipv4(&config.get("lan_netmask"));
        if !source_is_on_lan(source.ip(), lan_ip, lan_netmask) {
            continue;
        }
        if duplicate_guard.should_drop(source.ip(), opcode, IpAddr::V4(lan_ip)) {
            continue;
        }

        let state = load_state(&config, request);
        let response = build_response(request, &state);
        send_broadcast(&socket, &interfaces, source.port(), &response);
    }
}

fn parse_interfaces(arguments: impl Iterator<Item = String>) -> io::Result<Vec<String>> {
    let interfaces: Vec<String> = arguments.take(MAX_INTERFACES + 1).collect();
    if interfaces.is_empty() || interfaces.len() > MAX_INTERFACES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: infosvr <network-interface> [network-interface ...]",
        ));
    }
    for interface in &interfaces {
        if interface.is_empty()
            || interface.len() > 15
            || !interface.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid network interface: {interface:?}"),
            ));
        }
    }
    Ok(interfaces)
}

fn write_pid_file() -> io::Result<()> {
    fs::write("/var/run/infosvr.pid", std::process::id().to_string())
}

fn load_state(config: &impl Config, request: Request) -> DeviceState {
    let printer_manufacturer = config.get("u2ec_mfg");
    let printer_device = config.get("u2ec_device");
    let printer_info = if printer_manufacturer.is_empty() || printer_device.is_empty() {
        String::new()
    } else if printer_device.contains(printer_manufacturer.as_str()) {
        printer_device
    } else {
        format!("{printer_manufacturer} {printer_device}")
    };

    let mac = parse_mac(&config.get("lan_hwaddr")).unwrap_or([0; 6]);
    let label_mac = parse_mac(&config.get("label_mac")).unwrap_or(mac);
    let product_id = nonempty_or(config.get("odmpid"), config.get("productid"));
    let firmware_version = format_firmware(config);
    let ssid = discovery_ssid(config);
    let sw_mode = ui_sw_mode(config);
    let enable_webdav = config.enabled("enable_webdav");
    let capabilities = extend_capabilities(config);
    let aae_supported = capabilities & EXTEND_CAP_AAE_BASIC != 0;
    let enable_aae = aae_supported && config.enabled("aae_enable");
    let primary_wan = config.get_i32("wan_primary").clamp(0, 1);

    DeviceState {
        printer_info,
        ssid,
        netmask: nonempty_or(config.get("lan_netmask"), "255.255.255.0".into()),
        product_id,
        firmware_version,
        mac,
        label_mac,
        sw_mode,
        wave_info: read_wave_info(),
        disk_status: if matches!(request, Request::GetInfoEx2 { .. }) {
            disk_status(&config.get("usb_mnt_first_path"))
        } else {
            String::new()
        },
        extend_capabilities: capabilities,
        enable_webdav,
        webdav_mode: config.get_i32("st_webdav_mode").clamp(0, u8::MAX as i32) as u8,
        webdav_http_port: port(config, "webdav_http_port"),
        webdav_https_port: port(config, "webdav_https_port"),
        enable_ddns: config.enabled("ddns_enable_x"),
        ddns_hostname: config.get("ddns_hostname_x"),
        wan_ip: parse_ipv4(&config.get(&format!("wan{primary_wan}_ipaddr"))),
        is_not_default: config.enabled("x_Setting"),
        app_http_port: port(config, "dm_http_port"),
        app_api_level: GT_AX11000_APP_API_LEVEL,
        enable_aae,
        aae_device_id: if aae_supported {
            config.get("aae_deviceid")
        } else {
            String::new()
        },
        ai_home_api_level: AIHOME_API_LEVEL,
        cfg_group: platform_group_id(config),
    }
}

fn nonempty_or(primary: String, fallback: String) -> String {
    if primary.is_empty() {
        fallback
    } else {
        primary
    }
}

fn format_firmware(config: &impl Config) -> String {
    let firmware = config.get("firmver");
    let build = config.get("buildno");
    match (firmware.is_empty(), build.is_empty()) {
        (false, false) => format!("{firmware}.{build}"),
        (false, true) => firmware,
        (true, false) => build,
        (true, true) => String::new(),
    }
}

#[cfg(target_arch = "arm")]
fn discovery_ssid(_config: &impl Config) -> String {
    let mut buffer = [0_u8; 32];
    // SAFETY: the helper receives a writable 32-byte buffer and its exact
    // length. The C implementation uses bounded copies for this API.
    unsafe { platform_get_discovery_ssid(buffer.as_mut_ptr().cast(), buffer.len() as c_int) };
    let length = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..length]).into_owned()
}

#[cfg(not(target_arch = "arm"))]
fn discovery_ssid(config: &impl Config) -> String {
    let sw_mode = config.get_i32("sw_mode");
    let express = config.get_i32("wlc_express");
    if sw_mode == 2 {
        let key = match express {
            1 => "wl1.1_ssid",
            2 => "wl2.1_ssid",
            _ => "wl0.1_ssid",
        };
        let repeater_ssid = config.get(key);
        if !repeater_ssid.is_empty() {
            return repeater_ssid;
        }
    }
    nonempty_or(config.get("wl0_ssid"), config.get("productid"))
}

fn ui_sw_mode(config: &impl Config) -> u8 {
    let psta = config.get_i32("wlc_psta");
    let express = config.get_i32("wlc_express");
    match config.get_i32("sw_mode") {
        1 => 1,
        2 if psta == 0 && express == 1 => 6,
        2 if psta == 0 && express == 2 => 7,
        2 if psta == 0 => 2,
        2 => 4,
        3 if psta == 0 => 3,
        3 => 4,
        4 => 5,
        _ => 0,
    }
}

#[cfg(target_arch = "arm")]
fn extend_capabilities(_config: &impl Config) -> u16 {
    // SAFETY: get_extend_cap takes no pointers and returns a value. It only
    // reads compile-time feature flags, NVRAM and feature-presence files.
    unsafe { platform_get_extend_cap() }
}

#[cfg(not(target_arch = "arm"))]
fn extend_capabilities(config: &impl Config) -> u16 {
    calculate_capabilities(
        config.enabled("enable_webdav") || Path::new("/opt/etc/init.d/S50aicloud").exists(),
        config.enabled("aae_enable") || !config.get("aae_deviceid").is_empty(),
        !config.enabled("amas_disable") && config.get_i32("sw_mode") != 2,
        config.enabled("amas_bdl"),
        config.enabled("cfg_master"),
        config.enabled("elink_enable") && config.enabled("amas_disable"),
    )
}

fn port(config: &impl Config, key: &str) -> u16 {
    config.get(key).parse::<u16>().unwrap_or(0)
}

fn parse_ipv4(value: &str) -> Ipv4Addr {
    value.parse().unwrap_or(Ipv4Addr::UNSPECIFIED)
}

fn source_is_on_lan(source: IpAddr, lan_ip: Ipv4Addr, netmask: Ipv4Addr) -> bool {
    let IpAddr::V4(source) = source else {
        return false;
    };
    let mask = u32::from(netmask);
    mask != 0 && (u32::from(source) & mask) == (u32::from(lan_ip) & mask)
}

#[cfg(target_arch = "arm")]
fn platform_group_id(_config: &impl Config) -> Option<[u8; 20]> {
    static GROUP_ID: OnceLock<[u8; 20]> = OnceLock::new();

    cached_group_id(&GROUP_ID, generate_platform_group_id)
}

#[cfg(any(target_arch = "arm", test))]
fn cached_group_id(
    cache: &OnceLock<[u8; 20]>,
    generate: impl FnOnce() -> Option<[u8; 20]>,
) -> Option<[u8; 20]> {
    if let Some(group_id) = cache.get() {
        return Some(*group_id);
    }

    let generated = generate()?;
    let _ = cache.set(generated);
    cache.get().copied()
}

#[cfg(target_arch = "arm")]
fn generate_platform_group_id() -> Option<[u8; 20]> {
    type GenVsieId = unsafe extern "C" fn(c_int, *mut usize) -> *mut c_char;
    const RTLD_NOW: c_int = 2;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs()
        .min(c_int::MAX as u64) as c_int;
    let library = CString::new("libamas-utils.so").ok()?;
    // SAFETY: the name is NUL-terminated and the handle is checked before use.
    let handle = unsafe { dlopen(library.as_ptr(), RTLD_NOW) };
    if handle.is_null() {
        return None;
    }
    let symbol_name = c"gen_vsie_id";
    // SAFETY: handle is live and the symbol name is NUL-terminated.
    let symbol = unsafe { dlsym(handle, symbol_name.as_ptr()) };
    if symbol.is_null() {
        // SAFETY: handle is a successful dlopen result and is closed once.
        unsafe { dlclose(handle) };
        return None;
    }
    // SAFETY: the named firmware symbol has this stable C ABI, matching the
    // declaration used by the legacy infosvr implementation.
    let generate: GenVsieId = unsafe { std::mem::transmute(symbol) };
    let mut length = 0_usize;
    // SAFETY: gen_vsie_id is the firmware's AiMesh helper. It returns either
    // null or a malloc-owned byte string and writes its length to `length`.
    let pointer = unsafe { generate(timestamp, &mut length) };
    if pointer.is_null() {
        // SAFETY: handle is a successful dlopen result and is closed once.
        unsafe { dlclose(handle) };
        return None;
    }
    let group_id = if length == 40 {
        // SAFETY: the helper reported the allocation length. Only the bounded
        // 40-byte hexadecimal payload is read before the allocation is freed.
        let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) };
        std::str::from_utf8(bytes).ok().and_then(decode_group_id)
    } else {
        None
    };
    // SAFETY: the firmware helper allocates this pointer with malloc.
    unsafe { free(pointer.cast()) };
    // SAFETY: no code or data from the library is used after this close.
    unsafe { dlclose(handle) };
    group_id
}

#[cfg(not(target_arch = "arm"))]
fn platform_group_id(config: &impl Config) -> Option<[u8; 20]> {
    decode_group_id(&config.get("cfg_group"))
}

fn read_wave_info() -> Option<[u8; 16]> {
    let content = fs::read("/tmp/waveserver.info").ok()?;
    if content.len() < 20 {
        return None;
    }
    let process_id = i32::from_ne_bytes(content[16..20].try_into().ok()?);
    if process_id <= 0 || !Path::new(&format!("/proc/{process_id}")).is_dir() {
        return None;
    }
    content[..16].try_into().ok()
}

fn disk_status(mount_path: &str) -> String {
    if !valid_mount_path(mount_path) {
        return "0:0!$".into();
    }
    let output = Command::new("stat")
        .args(["-f", "-c", "%t:%f:%S", mount_path])
        .output();
    let Ok(output) = output else {
        return "0:0!$".into();
    };
    if !output.status.success() {
        return "0:0!$".into();
    }
    parse_statfs_output(&output.stdout).unwrap_or_else(|| "0:0!$".into())
}

fn parse_statfs_output(output: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(output).ok()?.trim();
    let mut fields = text.split(':');
    let filesystem_type = fields.next()?;
    let free_blocks = fields.next()?.parse::<u64>().ok()?;
    let block_size = fields.next()?.parse::<u64>().ok()?;
    if fields.next().is_some()
        || filesystem_type.is_empty()
        || !filesystem_type.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let free_mib = free_blocks.saturating_mul(block_size) / (1024 * 1024);
    Some(format!("{filesystem_type}:{free_mib}!$"))
}

fn valid_mount_path(path: &str) -> bool {
    !path.is_empty()
        && path.starts_with('/')
        && path.len() <= 255
        && !path
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
}

fn send_broadcast(socket: &UdpSocket, interfaces: &[String], port: u16, packet: &[u8]) {
    let destination = SocketAddr::from((Ipv4Addr::BROADCAST, port));
    for interface in interfaces {
        if let Err(error) = bind_to_device(socket, Some(interface)) {
            eprintln!("infosvr-rs: cannot bind to {interface}: {error}");
            continue;
        }
        if let Err(error) = socket.send_to(packet, destination) {
            eprintln!("infosvr-rs: send on {interface} failed: {error}");
        }
    }
    let _ = bind_to_device(socket, None);
}

fn bind_to_device(socket: &UdpSocket, interface: Option<&str>) -> io::Result<()> {
    let name = CString::new(interface.unwrap_or_default())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface contains NUL"))?;
    // SAFETY: `name` remains alive for the call, its pointer references
    // `as_bytes_with_nul().len()` initialized bytes, and the socket FD is valid.
    let result = unsafe {
        setsockopt(
            socket.as_raw_fd(),
            SOL_SOCKET,
            SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.as_bytes_with_nul().len() as u32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct TestConfig(HashMap<String, String>);

    impl TestConfig {
        fn with(mut self, key: &str, value: &str) -> Self {
            self.0.insert(key.into(), value.into());
            self
        }
    }

    impl Config for TestConfig {
        fn get(&self, key: &str) -> String {
            self.0.get(key).cloned().unwrap_or_default()
        }
    }

    #[test]
    fn validates_interfaces() {
        assert_eq!(
            parse_interfaces(["br0".to_string()].into_iter()).unwrap(),
            ["br0"]
        );
        assert!(parse_interfaces(["br0;reboot".to_string()].into_iter()).is_err());
        assert!(parse_interfaces(std::iter::empty()).is_err());
    }

    #[test]
    fn validates_mount_paths_without_shell_interpretation() {
        assert!(valid_mount_path("/tmp/mnt/disk one"));
        assert!(!valid_mount_path("-rf"));
        assert!(!valid_mount_path("/tmp\n/path"));
    }

    #[test]
    fn parses_legacy_statfs_shape_and_free_blocks() {
        assert_eq!(
            parse_statfs_output(b"ef53:4096:4096\n"),
            Some("ef53:16!$".into())
        );
        assert_eq!(parse_statfs_output(b"ef53:not-a-number:4096"), None);
    }

    #[test]
    fn rejects_discovery_requests_outside_the_lan_subnet() {
        let lan = Ipv4Addr::new(192, 168, 50, 1);
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        assert!(source_is_on_lan(
            IpAddr::V4(Ipv4Addr::new(192, 168, 50, 22)),
            lan,
            mask
        ));
        assert!(!source_is_on_lan(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 22)),
            lan,
            mask
        ));
    }

    #[test]
    fn group_id_cache_retries_failures_and_keeps_the_first_success() {
        let cache = OnceLock::new();
        assert_eq!(cached_group_id(&cache, || None), None);

        let first = [0x11; 20];
        assert_eq!(cached_group_id(&cache, || Some(first)), Some(first));

        let mut generated_again = false;
        assert_eq!(
            cached_group_id(&cache, || {
                generated_again = true;
                Some([0x22; 20])
            }),
            Some(first)
        );
        assert!(!generated_again);
    }

    #[test]
    fn loads_gt_ax11000_protocol_levels_and_primary_wan() {
        let config = TestConfig::default()
            .with("lan_hwaddr", "00:11:22:33:44:55")
            .with("wan_primary", "1")
            .with("wan1_ipaddr", "192.0.2.10")
            .with("aae_enable", "1")
            .with("aae_deviceid", "device-id")
            .with("sw_mode", "1");
        let state = load_state(&config, Request::GetInfo);

        assert_eq!(state.app_api_level, GT_AX11000_APP_API_LEVEL);
        assert_eq!(state.ai_home_api_level, AIHOME_API_LEVEL);
        assert_eq!(state.wan_ip, Ipv4Addr::new(192, 0, 2, 10));
        assert!(state.enable_aae);
        assert_eq!(state.aae_device_id, "device-id");
        assert!(state.disk_status.is_empty());
    }

    #[test]
    fn maps_hotspot_ui_mode() {
        let config = TestConfig::default().with("sw_mode", "4");
        assert_eq!(ui_sw_mode(&config), 5);
    }
}
