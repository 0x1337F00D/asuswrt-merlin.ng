#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt::Write as _;

pub const INTERVAL: i64 = 30;
pub const MAX_NSPEED: usize = 2_880;
pub const MAX_NDAILY: usize = 62;
pub const MAX_NMONTHLY: usize = 25;
pub const MAX_SPEED_IF: usize = 35;
pub const HISTORY_V0_LEN: usize = 1_800;
pub const HISTORY_V1_LEN: usize = 2_112;
pub const SPEED_RECORD_LEN: usize = 46_120;
pub const ID_V0: u32 = 0x3030_5352;
pub const ID_V1: u32 = 0x3130_5352;
pub const MAX_ROLLOVER: u64 = 1_024 * 30 / 8 * 1_024 * 1_024;

const DATA_LEN: usize = 24;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Data {
    pub xtime: u32,
    pub counter: [u64; 2],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct History {
    pub daily: [Data; MAX_NDAILY],
    pub daily_tail: usize,
    pub monthly: [Data; MAX_NMONTHLY],
    pub monthly_tail: usize,
}

impl Default for History {
    fn default() -> Self {
        Self {
            daily: [Data::default(); MAX_NDAILY],
            daily_tail: 0,
            monthly: [Data::default(); MAX_NMONTHLY],
            monthly_tail: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Speed {
    pub ifname: String,
    pub uptime: i32,
    pub samples: Vec<[u64; 2]>,
    pub last: [u64; 2],
    pub tail: usize,
    pub sync: i32,
}

impl Speed {
    pub fn new(ifname: &str, uptime: i64) -> Result<Self, CodecError> {
        if !valid_description(ifname) {
            return Err(CodecError::InvalidInterface);
        }
        Ok(Self {
            ifname: ifname.to_owned(),
            uptime: clamp_i32(uptime),
            samples: vec![[0; 2]; MAX_NSPEED],
            last: [0; 2],
            tail: 0,
            sync: 1,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    InvalidLength,
    InvalidId,
    InvalidIndex,
    InvalidInterface,
    InvalidBase64,
}

pub fn encode_history(history: &History) -> Vec<u8> {
    let mut output = vec![0; HISTORY_V1_LEN];
    put_u32(&mut output, 0, ID_V1);
    for (index, data) in history.daily.iter().enumerate() {
        encode_data(&mut output, 8 + index * DATA_LEN, *data);
    }
    put_i32(&mut output, 1_496, history.daily_tail as i32);
    for (index, data) in history.monthly.iter().enumerate() {
        encode_data(&mut output, 1_504 + index * DATA_LEN, *data);
    }
    put_i32(&mut output, 2_104, history.monthly_tail as i32);
    output
}

pub fn decode_history(input: &[u8]) -> Result<History, CodecError> {
    match input.len() {
        HISTORY_V1_LEN if get_u32(input, 0)? == ID_V1 => {
            let mut history = History::default();
            for (index, slot) in history.daily.iter_mut().enumerate() {
                *slot = decode_data(input, 8 + index * DATA_LEN)?;
            }
            history.daily_tail = decode_index(input, 1_496, MAX_NDAILY)?;
            for (index, slot) in history.monthly.iter_mut().enumerate() {
                *slot = decode_data(input, 1_504 + index * DATA_LEN)?;
            }
            history.monthly_tail = decode_index(input, 2_104, MAX_NMONTHLY)?;
            Ok(history)
        }
        HISTORY_V0_LEN if get_u32(input, 0)? == ID_V0 => {
            let mut history = History::default();
            for (index, slot) in history.daily.iter_mut().enumerate() {
                *slot = decode_data(input, 8 + index * DATA_LEN)?;
            }
            history.daily_tail = decode_index(input, 1_496, MAX_NDAILY)?;
            for index in 0..12 {
                history.monthly[index] = decode_data(input, 1_504 + index * DATA_LEN)?;
            }
            history.monthly_tail = decode_index(input, 1_792, 12)?;
            Ok(history)
        }
        HISTORY_V0_LEN | HISTORY_V1_LEN => Err(CodecError::InvalidId),
        _ => Err(CodecError::InvalidLength),
    }
}

pub fn encode_speeds(speeds: &[Speed]) -> Result<Vec<u8>, CodecError> {
    if speeds.len() > MAX_SPEED_IF {
        return Err(CodecError::InvalidLength);
    }
    let mut output = vec![0; SPEED_RECORD_LEN * speeds.len()];
    for (record_index, speed) in speeds.iter().enumerate() {
        if !valid_description(&speed.ifname)
            || speed.samples.len() != MAX_NSPEED
            || speed.tail >= MAX_NSPEED
        {
            return Err(CodecError::InvalidInterface);
        }
        let base = record_index * SPEED_RECORD_LEN;
        output[base..base + speed.ifname.len()].copy_from_slice(speed.ifname.as_bytes());
        put_i32(&mut output, base + 12, speed.uptime);
        for (index, sample) in speed.samples.iter().enumerate() {
            put_u64(&mut output, base + 16 + index * 16, sample[0]);
            put_u64(&mut output, base + 24 + index * 16, sample[1]);
        }
        put_u64(&mut output, base + 46_096, speed.last[0]);
        put_u64(&mut output, base + 46_104, speed.last[1]);
        put_i32(&mut output, base + 46_112, speed.tail as i32);
        put_i32(&mut output, base + 46_116, speed.sync);
    }
    Ok(output)
}

pub fn decode_speeds(input: &[u8]) -> Result<Vec<Speed>, CodecError> {
    if input.len() % SPEED_RECORD_LEN != 0 || input.len() / SPEED_RECORD_LEN > MAX_SPEED_IF {
        return Err(CodecError::InvalidLength);
    }
    let mut speeds = Vec::with_capacity(input.len() / SPEED_RECORD_LEN);
    for record_index in 0..input.len() / SPEED_RECORD_LEN {
        let base = record_index * SPEED_RECORD_LEN;
        let name_field = &input[base..base + 12];
        let name_end = name_field
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(CodecError::InvalidInterface)?;
        let ifname = std::str::from_utf8(&name_field[..name_end])
            .map_err(|_| CodecError::InvalidInterface)?;
        if !valid_description(ifname) {
            return Err(CodecError::InvalidInterface);
        }
        let tail = decode_index(input, base + 46_112, MAX_NSPEED)?;
        let mut samples = vec![[0; 2]; MAX_NSPEED];
        for (index, sample) in samples.iter_mut().enumerate() {
            sample[0] = get_u64(input, base + 16 + index * 16)?;
            sample[1] = get_u64(input, base + 24 + index * 16)?;
        }
        speeds.push(Speed {
            ifname: ifname.to_owned(),
            uptime: get_i32(input, base + 12)?,
            samples,
            last: [
                get_u64(input, base + 46_096)?,
                get_u64(input, base + 46_104)?,
            ],
            tail,
            sync: get_i32(input, base + 46_116)?,
        });
    }
    Ok(speeds)
}

fn encode_data(output: &mut [u8], offset: usize, data: Data) {
    put_u32(output, offset, data.xtime);
    put_u64(output, offset + 8, data.counter[0]);
    put_u64(output, offset + 16, data.counter[1]);
}

fn decode_data(input: &[u8], offset: usize) -> Result<Data, CodecError> {
    Ok(Data {
        xtime: get_u32(input, offset)?,
        counter: [get_u64(input, offset + 8)?, get_u64(input, offset + 16)?],
    })
}

fn decode_index(input: &[u8], offset: usize, maximum: usize) -> Result<usize, CodecError> {
    let value = get_i32(input, offset)?;
    if value < 0 || value as usize >= maximum {
        Err(CodecError::InvalidIndex)
    } else {
        Ok(value as usize)
    }
}

fn get_u32(input: &[u8], offset: usize) -> Result<u32, CodecError> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or(CodecError::InvalidLength)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("length checked"),
    ))
}

fn get_i32(input: &[u8], offset: usize) -> Result<i32, CodecError> {
    Ok(get_u32(input, offset)? as i32)
}

fn get_u64(input: &[u8], offset: usize) -> Result<u64, CodecError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(CodecError::InvalidLength)?;
    Ok(u64::from_le_bytes(
        bytes.try_into().expect("length checked"),
    ))
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_i32(output: &mut [u8], offset: usize, value: i32) {
    put_u32(output, offset, value as u32);
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn parse_proc_net_dev(input: &str) -> Vec<NetDev> {
    input
        .lines()
        .filter_map(|line| {
            let (name, counters) = line.split_once(':')?;
            let ifname = name.trim();
            if !valid_kernel_ifname(ifname) || ifname == "lo" {
                return None;
            }
            let fields: Vec<&str> = counters.split_ascii_whitespace().collect();
            if fields.len() < 9 {
                return None;
            }
            Some(NetDev {
                ifname: ifname.to_owned(),
                rx: fields[0].parse().ok()?,
                tx: fields[8].parse().ok()?,
            })
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetDev {
    pub ifname: String,
    pub rx: u64,
    pub tx: u64,
}

pub fn move_wan_interfaces_last(devices: &mut Vec<NetDev>, wan0: &str, wan1: &str) {
    for wan in [wan0, wan1] {
        if wan.is_empty() {
            continue;
        }
        if let Some(index) = devices.iter().position(|device| device.ifname == wan) {
            let device = devices.remove(index);
            devices.push(device);
        }
    }
}

pub fn contains_word(words: &str, needle: &str) -> bool {
    words.split_ascii_whitespace().any(|word| word == needle)
}

pub fn valid_kernel_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

pub fn valid_description(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 12
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'.')
        && description_order(name).is_some()
}

pub fn description_order(name: &str) -> Option<u16> {
    match name {
        "INTERNET" => Some(0),
        "INTERNET1" => Some(1),
        "INTERNET50" => Some(2),
        "INTERNET51" => Some(3),
        "INTERNET52" => Some(4),
        "INTERNET53" => Some(5),
        "WIRED" => Some(6),
        "BRIDGE" => Some(7),
        _ => wireless_order(name)
            .or_else(|| numbered_order(name, "LACP", 1, 8, 40))
            .or_else(|| numbered_order(name, "WAGGR", 0, 8, 50))
            .or_else(|| numbered_order(name, "WAGGR", 30, 31, 59))
            .or_else(|| numbered_order(name, "LACPW", 1, 2, 62)),
    }
}

fn wireless_order(name: &str) -> Option<u16> {
    let rest = name.strip_prefix("WIRELESS")?;
    let (band, subunit) = match rest.split_once('.') {
        Some((band, subunit)) => (
            band.parse::<u16>().ok()?,
            Some(subunit.parse::<u16>().ok()?),
        ),
        None => (rest.parse::<u16>().ok()?, None),
    };
    if band > 3 || subunit.is_some_and(|value| value > 6) {
        return None;
    }
    Some(8 + band * 7 + subunit.map_or(0, |value| value + 1))
}

fn numbered_order(name: &str, prefix: &str, minimum: u16, maximum: u16, base: u16) -> Option<u16> {
    let value = name.strip_prefix(prefix)?.parse::<u16>().ok()?;
    (minimum..=maximum)
        .contains(&value)
        .then_some(base + value - minimum)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct IfStat {
    inode: u64,
    last: [u64; 2],
    shift: [u64; 2],
}

#[derive(Default)]
pub struct CounterTracker {
    interfaces: HashMap<String, IfStat>,
}

impl CounterTracker {
    pub fn normalize(&mut self, ifname: &str, inode: u64, current: [u64; 2]) -> [u64; 2] {
        let entry = self.interfaces.entry(ifname.to_owned()).or_insert(IfStat {
            inode,
            last: current,
            shift: [0; 2],
        });
        if entry.inode != 0 && inode != 0 && entry.inode != inode {
            entry.inode = inode;
            for (index, value) in current.iter().enumerate() {
                entry.shift[index] = value
                    .wrapping_sub(entry.last[index])
                    .wrapping_add(entry.shift[index]);
            }
        }
        entry.last = current;
        [
            current[0].wrapping_sub(entry.shift[0]),
            current[1].wrapping_sub(entry.shift[1]),
        ]
    }
}

pub fn counter_delta(current: u64, previous: u64) -> u64 {
    let delta = current.wrapping_sub(previous);
    if current < previous && delta > MAX_ROLLOVER {
        0
    } else {
        delta
    }
}

pub fn advance_speed(speed: &mut Speed, uptime: i64, current: [u64; 2]) -> [u64; 2] {
    if speed.sync != 0 {
        speed.sync = -1;
        speed.last = current;
        return [0; 2];
    }
    let elapsed = uptime.saturating_sub(i64::from(speed.uptime));
    let slots = (elapsed / INTERVAL).max(0) as usize;
    if slots == 0 {
        return [0; 2];
    }
    speed.sync = -1;
    speed.uptime = speed
        .uptime
        .saturating_add(clamp_i32((slots as i64) * INTERVAL));
    let deltas = [
        counter_delta(current[0], speed.last[0]),
        counter_delta(current[1], speed.last[1]),
    ];
    speed.last = current;
    let per_slot = [deltas[0] / slots as u64, deltas[1] / slots as u64];
    if slots >= MAX_NSPEED {
        speed.samples.fill(per_slot);
        speed.tail = (speed.tail + slots % MAX_NSPEED) % MAX_NSPEED;
    } else {
        for _ in 0..slots {
            speed.tail = (speed.tail + 1) % MAX_NSPEED;
            speed.samples[speed.tail] = per_slot;
        }
    }
    deltas
}

pub fn bump(data: &mut [Data], tail: &mut usize, xtime: u32, counters: [u64; 2]) {
    let mut index = *tail;
    if data[index].xtime != xtime {
        if let Some(found) = data.iter().position(|slot| slot.xtime == xtime) {
            index = found;
        } else {
            *tail = (*tail + 1) % data.len();
            index = *tail;
            data[index] = Data {
                xtime,
                counter: [0; 2],
            };
        }
    }
    for (destination, value) in data[index].counter.iter_mut().zip(counters) {
        *destination = destination.wrapping_add(value);
    }
}

pub fn daily_key(tm_year: i32, tm_mon: i32, tm_mday: i32) -> u32 {
    ((tm_year as u32) << 16) | ((tm_mon as u32) << 8) | tm_mday as u32
}

pub fn monthly_key(tm_year: i32, tm_mon: i32) -> u32 {
    ((tm_year as u32) << 16) | ((tm_mon as u32) << 8)
}

pub fn speed_javascript(speeds: &[Speed], next: i64) -> String {
    let mut output = String::from("\nspeed_history = {\n");
    for (index, speed) in speeds.iter().enumerate() {
        if index != 0 {
            output.push_str(" },\n");
        }
        let _ = writeln!(output, "'{}': {{", speed.ifname);
        for counter_index in 0..2 {
            let mut total = 0_u64;
            let mut maximum = 0_u64;
            output.push_str(if counter_index == 0 {
                " rx: ["
            } else {
                ",\n tx: ["
            });
            let mut position = speed.tail;
            for sample_index in 0..MAX_NSPEED {
                position = (position + 1) % MAX_NSPEED;
                let value = speed.samples[position][counter_index];
                if sample_index != 0 {
                    output.push(',');
                }
                let _ = write!(output, "{value}");
                total = total.wrapping_add(value);
                maximum = maximum.max(value);
            }
            output.push_str("],\n");
            let prefix = if counter_index == 0 { 'r' } else { 't' };
            let _ = write!(
                output,
                " {prefix}x_avg: {},\n {prefix}x_max: {maximum},\n {prefix}x_total: {total}",
                total / MAX_NSPEED as u64
            );
        }
    }
    if speeds.is_empty() {
        let _ = writeln!(output, "_next: {}}};", next.max(1));
    } else {
        let _ = writeln!(output, "}},\n_next: {}}};", next.max(1));
    }
    output
}

pub fn history_javascript(history: &History) -> String {
    let mut output = String::new();
    history_series(&mut output, "daily", &history.daily, history.daily_tail);
    history_series(
        &mut output,
        "monthly",
        &history.monthly,
        history.monthly_tail,
    );
    output
}

fn history_series(output: &mut String, name: &str, data: &[Data], tail: usize) {
    let _ = write!(output, "\n{name}_history = [\n");
    let mut position = tail;
    let mut emitted = false;
    for _ in 0..data.len() {
        position = (position + 1) % data.len();
        let slot = data[position];
        if slot.xtime == 0 {
            continue;
        }
        if emitted {
            output.push(',');
        }
        let _ = write!(
            output,
            "[0x{:x},0x{:x},0x{:x}]",
            slot.xtime,
            slot.counter[0] / 1_024,
            slot.counter[1] / 1_024
        );
        emitted = true;
    }
    output.push_str("];\n");
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(BASE64[((value >> 18) & 0x3f) as usize] as char);
        output.push(BASE64[((value >> 12) & 0x3f) as usize] as char);
        output.push(if chunk.len() > 1 {
            BASE64[((value >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            BASE64[(value & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

pub fn base64_decode(input: &str, maximum: usize) -> Result<Vec<u8>, CodecError> {
    let compact: Vec<u8> = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if compact.len() % 4 != 0 || compact.len() / 4 * 3 > maximum.saturating_add(2) {
        return Err(CodecError::InvalidBase64);
    }
    let mut output = Vec::with_capacity(compact.len() / 4 * 3);
    for (chunk_index, chunk) in compact.chunks_exact(4).enumerate() {
        let final_chunk = chunk_index + 1 == compact.len() / 4;
        let padding = usize::from(chunk[3] == b'=') + usize::from(chunk[2] == b'=');
        if padding > 2 || (!final_chunk && padding != 0) || (chunk[2] == b'=' && chunk[3] != b'=') {
            return Err(CodecError::InvalidBase64);
        }
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c = if chunk[2] == b'=' {
            0
        } else {
            base64_value(chunk[2])?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            base64_value(chunk[3])?
        };
        let value =
            (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6) | u32::from(d);
        output.push((value >> 16) as u8);
        if padding < 2 {
            output.push((value >> 8) as u8);
        }
        if padding == 0 {
            output.push(value as u8);
        }
        if output.len() > maximum {
            return Err(CodecError::InvalidBase64);
        }
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Result<u8, CodecError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(CodecError::InvalidBase64),
    }
}

fn clamp_i32(value: i64) -> i32 {
    value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_v1_round_trip_and_arm_offsets() {
        let mut history = History::default();
        history.daily[0] = Data {
            xtime: 0x007c_071f,
            counter: [0x1122_3344_5566_7788, 0x99aa_bbcc_ddee_ff00],
        };
        history.daily_tail = 61;
        history.monthly[24] = history.daily[0];
        history.monthly_tail = 24;
        let encoded = encode_history(&history);
        assert_eq!(encoded.len(), HISTORY_V1_LEN);
        assert_eq!(&encoded[0..4], &ID_V1.to_le_bytes());
        assert_eq!(&encoded[4..8], &[0; 4]);
        assert_eq!(&encoded[8..12], &0x007c_071f_u32.to_le_bytes());
        assert_eq!(&encoded[16..24], &0x1122_3344_5566_7788_u64.to_le_bytes());
        assert_eq!(&encoded[1_496..1_500], &61_i32.to_le_bytes());
        assert_eq!(&encoded[2_104..2_108], &24_i32.to_le_bytes());
        assert_eq!(decode_history(&encoded), Ok(history));
    }

    #[test]
    fn history_v0_is_migrated_without_guessing_padding() {
        let mut encoded = vec![0; HISTORY_V0_LEN];
        put_u32(&mut encoded, 0, ID_V0);
        encode_data(
            &mut encoded,
            1_504 + 11 * DATA_LEN,
            Data {
                xtime: 7,
                counter: [8, 9],
            },
        );
        put_i32(&mut encoded, 1_792, 11);
        let history = decode_history(&encoded).unwrap();
        assert_eq!(history.monthly[11].counter, [8, 9]);
        assert_eq!(history.monthly[12], Data::default());
        assert_eq!(history.monthly_tail, 11);
    }

    #[test]
    fn codecs_reject_bad_ids_indices_and_lengths() {
        assert_eq!(decode_history(&[]), Err(CodecError::InvalidLength));
        let mut history = encode_history(&History::default());
        history[0] = 0;
        assert_eq!(decode_history(&history), Err(CodecError::InvalidId));
        let mut history = encode_history(&History::default());
        put_i32(&mut history, 1_496, 62);
        assert_eq!(decode_history(&history), Err(CodecError::InvalidIndex));
        assert_eq!(decode_speeds(&[0]), Err(CodecError::InvalidLength));
    }

    #[test]
    fn speed_round_trip_uses_exact_arm_layout() {
        let mut speed = Speed::new("INTERNET", 123).unwrap();
        speed.samples[2] = [3, 4];
        speed.last = [5, 6];
        speed.tail = 2;
        speed.sync = -1;
        let encoded = encode_speeds(&[speed.clone()]).unwrap();
        assert_eq!(encoded.len(), SPEED_RECORD_LEN);
        assert_eq!(&encoded[12..16], &123_i32.to_le_bytes());
        assert_eq!(&encoded[48..56], &3_u64.to_le_bytes());
        assert_eq!(&encoded[46_096..46_104], &5_u64.to_le_bytes());
        assert_eq!(&encoded[46_112..46_116], &2_i32.to_le_bytes());
        assert_eq!(decode_speeds(&encoded), Ok(vec![speed]));
    }

    #[test]
    fn speed_decoder_accepts_partial_legacy_files() {
        let speed = Speed::new("WIRED", 0).unwrap();
        let encoded = encode_speeds(&[speed.clone(), speed]).unwrap();
        assert_eq!(decode_speeds(&encoded).unwrap().len(), 2);
    }

    #[test]
    fn proc_parser_is_bounded_and_uses_byte_columns() {
        let input = "Inter-| Receive\n face |bytes\n lo: 1 0 0 0 0 0 0 0 2\n eth0: 10 1 2 3 4 5 6 7 20 9\n bad iface: 8 0 0 0 0 0 0 0 9\n";
        assert_eq!(
            parse_proc_net_dev(input),
            vec![NetDev {
                ifname: "eth0".into(),
                rx: 10,
                tx: 20
            }]
        );
    }

    #[test]
    fn wan_interfaces_are_moved_last_in_declared_order() {
        let mut devices = vec![
            NetDev {
                ifname: "eth0".into(),
                rx: 0,
                tx: 0,
            },
            NetDev {
                ifname: "vlan1".into(),
                rx: 0,
                tx: 0,
            },
            NetDev {
                ifname: "eth1".into(),
                rx: 0,
                tx: 0,
            },
        ];
        move_wan_interfaces_last(&mut devices, "eth0", "eth1");
        assert_eq!(
            devices
                .iter()
                .map(|d| d.ifname.as_str())
                .collect::<Vec<_>>(),
            ["vlan1", "eth0", "eth1"]
        );
    }

    #[test]
    fn inode_change_preserves_monotonic_counter() {
        let mut tracker = CounterTracker::default();
        assert_eq!(tracker.normalize("eth0", 1, [100, 200]), [100, 200]);
        assert_eq!(tracker.normalize("eth0", 1, [150, 260]), [150, 260]);
        assert_eq!(tracker.normalize("eth0", 2, [10, 20]), [150, 260]);
        assert_eq!(tracker.normalize("eth0", 2, [20, 40]), [160, 280]);
    }

    #[test]
    fn rollover_is_bounded() {
        assert_eq!(counter_delta(8, u64::MAX - 7), 16);
        assert_eq!(counter_delta(8, 9_000_000_000), 0);
    }

    #[test]
    fn speed_advance_splits_missed_intervals() {
        let mut speed = Speed::new("INTERNET", 0).unwrap();
        advance_speed(&mut speed, 30, [100, 200]);
        speed.sync = 0;
        advance_speed(&mut speed, 90, [160, 320]);
        assert_eq!(speed.samples[1], [20, 40]);
        assert_eq!(speed.samples[2], [20, 40]);
        assert_eq!(speed.samples[3], [20, 40]);
    }

    #[test]
    fn speed_advance_bounds_work_after_a_long_suspend() {
        let mut speed = Speed::new("INTERNET", 0).unwrap();
        speed.sync = 0;
        let slots = MAX_NSPEED + 7;
        let delta = advance_speed(&mut speed, slots as i64 * INTERVAL, [slots as u64, 0]);
        assert_eq!(delta, [slots as u64, 0]);
        assert_eq!(speed.tail, 7);
        assert!(speed.samples.iter().all(|sample| *sample == [1, 0]));
    }

    #[test]
    fn bump_reuses_existing_date_or_rotates() {
        let mut data = [Data::default(); 3];
        let mut tail = 0;
        bump(&mut data, &mut tail, 7, [1, 2]);
        assert_eq!(tail, 1);
        bump(&mut data, &mut tail, 7, [3, 4]);
        assert_eq!(data[1].counter, [4, 6]);
        data[2].xtime = 8;
        bump(&mut data, &mut tail, 8, [5, 6]);
        assert_eq!(tail, 1);
        assert_eq!(data[2].counter, [5, 6]);
    }

    #[test]
    fn descriptions_are_strict_and_stably_ordered() {
        assert_eq!(description_order("WIRELESS2.6"), Some(29));
        assert!(valid_description("INTERNET"));
        assert!(!valid_description("INTERNET';alert(1)//"));
        assert!(!valid_description("WIRELESS4"));
    }

    #[test]
    fn javascript_has_valid_hex_literals() {
        let mut history = History::default();
        history.daily[1] = Data {
            xtime: 0x7c071f,
            counter: [1024, 2048],
        };
        let js = history_javascript(&history);
        assert!(js.contains("[0x7c071f,0x1,0x2]"));
        assert!(!js.contains("0x "));
    }

    #[test]
    fn base64_round_trip_and_limits() {
        for input in [b"".as_slice(), b"f", b"fo", b"foo", b"hello\0router"] {
            let encoded = base64_encode(input);
            assert_eq!(base64_decode(&encoded, input.len()).unwrap(), input);
        }
        assert_eq!(base64_decode("Zm9v!", 10), Err(CodecError::InvalidBase64));
        assert_eq!(base64_decode("Zm9v", 2), Err(CodecError::InvalidBase64));
    }
}
