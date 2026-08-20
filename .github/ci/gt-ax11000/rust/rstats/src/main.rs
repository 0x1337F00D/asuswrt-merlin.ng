#[cfg(target_arch = "arm")]
use rstats::valid_description;
use rstats::{
    advance_speed, base64_decode, base64_encode, bump, daily_key, decode_history, decode_speeds,
    description_order, encode_history, encode_speeds, history_javascript, monthly_key,
    move_wan_interfaces_last, parse_proc_net_dev, speed_javascript, valid_kernel_ifname,
    CounterTracker, History, NetDev, Speed, HISTORY_V1_LEN, INTERVAL, MAX_SPEED_IF,
    SPEED_RECORD_LEN,
};
use std::collections::{BTreeMap, HashSet};
use std::env;
#[cfg(target_arch = "arm")]
use std::ffi::CStr;
#[cfg(target_arch = "arm")]
use std::ffi::CString;
use std::ffi::{c_char, c_int, c_long};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

const HISTORY_BASE: &str = "/var/lib/misc/rstats-history";
const SPEED_BASE: &str = "/var/lib/misc/rstats-speed";
const STIME_FILE: &str = "/var/lib/misc/rstats-stime";
const SOURCE_FILE: &str = "/var/lib/misc/rstats-source";
const LOAD_MARKER: &str = "/var/tmp/rstats-load";
const SPEED_JS_TMP: &str = "/var/tmp/rstats-speed.js";
const SPEED_JS: &str = "/var/spool/rstats-speed.js";
const HISTORY_JS_TMP: &str = "/var/tmp/rstats-history.js";
const HISTORY_JS: &str = "/var/spool/rstats-history.js";
#[cfg(feature = "isp-meter")]
const ISP_METER_FILE: &str = "/jffs/isp_meter";
const MAX_GZIP_HISTORY: usize = HISTORY_V1_LEN;
const MAX_GZIP_SPEED: usize = SPEED_RECORD_LEN * MAX_SPEED_IF;
const MAX_NVRAM_ARCHIVE: usize = 20 * 1024;
const HI_BACK: usize = 5;

const SIGHUP: c_int = 1;
const SIGINT: c_int = 2;
const SIGUSR1: c_int = 10;
const SIGUSR2: c_int = 12;
const SIGTERM: c_int = 15;
const SIGTSTP: c_int = 20;
const FLAG_HUP: i32 = 1;
const FLAG_USER1: i32 = 2;
const FLAG_USER2: i32 = 4;
const FLAG_TERM: i32 = 8;
const FLAG_RESET_METER: i32 = 16;

static SIGNAL_FLAGS: AtomicI32 = AtomicI32::new(0);
static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);

#[cfg(target_arch = "arm")]
#[link(name = "nvram")]
extern "C" {
    fn nvram_get(name: *const c_char) -> *const c_char;
    fn nvram_set(name: *const c_char, value: *const c_char) -> c_int;
    fn nvram_commit() -> c_int;
}

#[cfg(target_arch = "arm")]
#[link(name = "shared")]
extern "C" {
    fn netdev_calc(
        ifname: *mut c_char,
        description: *mut c_char,
        rx: *mut u64,
        tx: *mut u64,
        description2: *mut c_char,
        rx2: *mut u64,
        tx2: *mut u64,
        lan_ifname: *mut c_char,
        lan_ifnames: *mut c_char,
    ) -> u32;
    fn wait_action_idle(seconds: c_int) -> c_int;
    #[cfg(feature = "isp-meter")]
    fn notify_rc_and_wait(event_name: *const c_char) -> c_int;
}

extern "C" {
    #[cfg(target_arch = "arm")]
    fn fork() -> c_int;
    fn signal(number: c_int, handler: usize) -> usize;
    fn sleep(seconds: u32) -> u32;
    fn time(timer: *mut c_long) -> c_long;
    fn localtime_r(timer: *const c_long, result: *mut Tm) -> *mut Tm;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Tm {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
    tm_gmtoff: c_long,
    tm_zone: *const c_char,
}

#[derive(Clone, Copy)]
struct LocalDate {
    year: i32,
    month: i32,
    day: i32,
    year_day: i32,
}

#[derive(Clone, Copy)]
struct Nvram;

impl Nvram {
    #[cfg(target_arch = "arm")]
    fn get(self, key: &str) -> String {
        let Ok(key) = CString::new(key) else {
            return String::new();
        };
        // SAFETY: the key is NUL-terminated. The platform returns null or a
        // NUL-terminated value, which is copied before another NVRAM call.
        let value = unsafe { nvram_get(key.as_ptr()) };
        if value.is_null() {
            String::new()
        } else {
            // SAFETY: non-null nvram_get values are NUL-terminated by its ABI.
            unsafe { CStr::from_ptr(value) }
                .to_string_lossy()
                .into_owned()
        }
    }

    #[cfg(not(target_arch = "arm"))]
    fn get(self, key: &str) -> String {
        env::var(format!("RSTATS_{}", key.to_ascii_uppercase())).unwrap_or_default()
    }

    fn get_i64(self, key: &str) -> i64 {
        self.get(key).parse().unwrap_or(0)
    }

    fn matches(self, key: &str, expected: &str) -> bool {
        self.get(key) == expected
    }

    #[cfg(target_arch = "arm")]
    fn set(self, key: &str, value: &str) -> io::Result<()> {
        let key = CString::new(key)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NVRAM key contains NUL"))?;
        let value = CString::new(value)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NVRAM value contains NUL"))?;
        // SAFETY: both arguments are valid NUL-terminated strings for the call.
        let result = unsafe { nvram_set(key.as_ptr(), value.as_ptr()) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(result))
        }
    }

    #[cfg(not(target_arch = "arm"))]
    fn set(self, _key: &str, _value: &str) -> io::Result<()> {
        Ok(())
    }

    #[cfg(target_arch = "arm")]
    fn commit(self) -> io::Result<()> {
        // SAFETY: nvram_commit takes no arguments.
        let result = unsafe { nvram_commit() };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(result))
        }
    }

    #[cfg(not(target_arch = "arm"))]
    fn commit(self) -> io::Result<()> {
        Ok(())
    }

    #[cfg(target_arch = "arm")]
    fn wait_idle(self, seconds: i32) -> bool {
        // SAFETY: the platform helper accepts a bounded integer timeout.
        unsafe { wait_action_idle(seconds) != 0 }
    }

    #[cfg(not(target_arch = "arm"))]
    fn wait_idle(self, _seconds: i32) -> bool {
        true
    }

    #[cfg(all(target_arch = "arm", feature = "isp-meter"))]
    fn notify(self, event: &str) {
        if let Ok(event) = CString::new(event) {
            // SAFETY: event is NUL-terminated for the call.
            unsafe {
                notify_rc_and_wait(event.as_ptr());
            }
        }
    }

    #[cfg(all(not(target_arch = "arm"), feature = "isp-meter"))]
    fn notify(self, event: &str) {
        eprintln!("rstats-rs: notify {event}");
    }

    #[cfg(target_arch = "arm")]
    fn classify(
        self,
        device: &NetDev,
        lan_ifname: &str,
        lan_ifnames: &str,
    ) -> Vec<(String, [u64; 2])> {
        let Ok(ifname) = CString::new(device.ifname.as_str()) else {
            return Vec::new();
        };
        let Ok(lan_ifname) = CString::new(lan_ifname) else {
            return Vec::new();
        };
        let Ok(lan_ifnames) = CString::new(lan_ifnames) else {
            return Vec::new();
        };
        let mut ifname = ifname.into_bytes_with_nul();
        let mut lan_ifname = lan_ifname.into_bytes_with_nul();
        let mut lan_ifnames = lan_ifnames.into_bytes_with_nul();
        let mut description = [0 as c_char; 12];
        let mut description2 = [0 as c_char; 12];
        let mut rx = device.rx;
        let mut tx = device.tx;
        let mut rx2 = 0_u64;
        let mut tx2 = 0_u64;
        // SAFETY: inputs are writable NUL-terminated C buffers. Description
        // buffers have the 12-byte size required by netdev_calc.
        let accepted = unsafe {
            netdev_calc(
                ifname.as_mut_ptr().cast(),
                description.as_mut_ptr(),
                &mut rx,
                &mut tx,
                description2.as_mut_ptr(),
                &mut rx2,
                &mut tx2,
                lan_ifname.as_mut_ptr().cast(),
                lan_ifnames.as_mut_ptr().cast(),
            )
        };
        if accepted == 0 {
            return Vec::new();
        }
        let mut result = Vec::with_capacity(2);
        if let Some(name) = description_from_c(&description) {
            result.push((name, [rx, tx]));
        }
        if let Some(name) = description_from_c(&description2) {
            result.push((name, [rx2, tx2]));
        }
        result
    }

    #[cfg(not(target_arch = "arm"))]
    fn classify(
        self,
        device: &NetDev,
        lan_ifname: &str,
        _lan_ifnames: &str,
    ) -> Vec<(String, [u64; 2])> {
        let name = if device.ifname == self.get("wan0_ifname") {
            "INTERNET"
        } else if device.ifname == lan_ifname {
            "BRIDGE"
        } else {
            "WIRED"
        };
        vec![(name.to_owned(), [device.rx, device.tx])]
    }
}

struct Daemon {
    config: Nvram,
    history: History,
    speeds: Vec<Speed>,
    tracker: CounterTracker,
    save_uptime: i64,
    save_path: String,
    current_uptime: i64,
    last_backup_day: Option<i32>,
}

impl Daemon {
    fn new() -> Self {
        Self {
            config: Nvram,
            history: History::default(),
            speeds: Vec::new(),
            tracker: CounterTracker::default(),
            save_uptime: 0,
            save_path: String::new(),
            current_uptime: uptime(),
            last_backup_day: None,
        }
    }

    fn load(&mut self, new_database: bool) -> io::Result<()> {
        self.current_uptime = uptime();
        self.save_path = resolve_save_path(self.config);
        self.save_uptime = read_i32_file(Path::new(STIME_FILE)).map_or(0, i64::from);
        let latest = self.current_uptime.saturating_add(self.save_interval());
        if self.save_uptime < self.current_uptime || self.save_uptime > latest {
            self.save_uptime = latest;
        }

        let speed_gzip = gzip_name(SPEED_BASE);
        if let Ok(bytes) = gzip_read_bounded(Path::new(&speed_gzip), MAX_GZIP_SPEED) {
            if let Ok(mut speeds) = decode_speeds(&bytes) {
                for speed in &mut speeds {
                    if i64::from(speed.uptime) > self.current_uptime {
                        speed.uptime = clamp_i32(self.current_uptime);
                        speed.sync = 1;
                    }
                }
                self.speeds = speeds;
            }
        }

        let history_gzip = gzip_name(HISTORY_BASE);
        if new_database {
            let _ = fs::remove_file(history_gzip);
            self.save_uptime = 0;
            return Ok(());
        }

        let source = read_text_bounded(Path::new(SOURCE_FILE), 256).unwrap_or_default();
        if source == self.save_path && self.load_history_file(Path::new(&history_gzip)) {
            return Ok(());
        }

        if self.save_path == "*nvram" {
            if !self.config.wait_idle(60) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "router action busy",
                ));
            }
            let encoded = self.config.get("rstats_data");
            if !encoded.is_empty() {
                if let Ok(gzip) = base64_decode(&encoded, MAX_NVRAM_ARCHIVE) {
                    atomic_write(Path::new(&history_gzip), &gzip)?;
                    self.load_history_file(Path::new(&history_gzip));
                }
            }
        } else if !self.save_path.is_empty() {
            let external = PathBuf::from(self.save_path.clone());
            let mut delay = 1_u32;
            loop {
                if self.config.wait_idle(10) {
                    let _ = fs::metadata(&external);
                    if self.load_history_file(&external) || self.try_backups(&external) {
                        atomic_write(Path::new(SOURCE_FILE), self.save_path.as_bytes())?;
                        break;
                    }
                }
                sleep_interruptible(delay);
                delay = delay.saturating_mul(2).min(900);
                if SIGNAL_FLAGS.load(Ordering::Relaxed) & FLAG_TERM != 0 {
                    self.save_path.clear();
                    break;
                }
                if delay > 180 {
                    eprintln!("rstats-rs: still waiting for {}", external.display());
                }
            }
        }
        Ok(())
    }

    fn load_history_file(&mut self, path: &Path) -> bool {
        gzip_read_bounded(path, MAX_GZIP_HISTORY)
            .ok()
            .and_then(|bytes| decode_history(&bytes).ok())
            .is_some_and(|history| {
                self.history = history;
                true
            })
    }

    fn try_backups(&mut self, path: &Path) -> bool {
        let mut found = false;
        for index in (1..=HI_BACK).rev() {
            found |= self.load_history_file(&backup_path(path, index));
        }
        found | self.load_history_file(path)
    }

    fn load_new(&mut self) {
        let path = PathBuf::from(format!("{}.gz.new", HISTORY_BASE));
        if self.load_history_file(&path) {
            if let Err(error) = self.save() {
                eprintln!("rstats-rs: save after import failed: {error}");
            }
        }
        let _ = fs::remove_file(path);
    }

    fn save_interval(&self) -> i64 {
        self.config.get_i64("rstats_stime").clamp(1, 8_760) * 3_600
    }

    fn save(&mut self) -> io::Result<()> {
        atomic_write(
            Path::new(STIME_FILE),
            &clamp_i32(self.save_uptime).to_le_bytes(),
        )?;
        let speed_bytes = encode_speeds(&self.speeds)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid speed state"))?;
        gzip_write_atomic(Path::new(&gzip_name(SPEED_BASE)), &speed_bytes)?;
        let history_bytes = encode_history(&self.history);
        let history_gzip = PathBuf::from(gzip_name(HISTORY_BASE));
        gzip_write_atomic(&history_gzip, &history_bytes)?;
        atomic_write(Path::new(SOURCE_FILE), self.save_path.as_bytes())?;

        if self.save_path == "*nvram" {
            if self.config.wait_idle(10) {
                let gzip = read_file_bounded(&history_gzip, MAX_NVRAM_ARCHIVE)?;
                self.config.set("rstats_data", &base64_encode(&gzip))?;
                if !self.config.matches("debug_nocommit", "1") {
                    self.config.commit()?;
                }
            }
        } else if !self.save_path.is_empty() {
            self.save_external(&history_gzip)?;
        }
        Ok(())
    }

    fn save_external(&mut self, history_gzip: &Path) -> io::Result<()> {
        let destination = PathBuf::from(self.save_path.clone());
        let mut last_error = None;
        for _ in 0..15 {
            if self.config.wait_idle(10) {
                match read_file_bounded(history_gzip, MAX_NVRAM_ARCHIVE)
                    .and_then(|bytes| write_temporary(&destination, &bytes))
                {
                    Ok(temporary) => {
                        self.rotate_backup(&destination);
                        match fs::rename(&temporary, &destination) {
                            Ok(()) => return Ok(()),
                            Err(error) => {
                                let _ = fs::remove_file(temporary);
                                last_error = Some(error);
                            }
                        }
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            sleep_interruptible(3);
            if SIGNAL_FLAGS.load(Ordering::Relaxed) & FLAG_TERM != 0 {
                break;
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "external stats path unavailable")
        }))
    }

    fn rotate_backup(&mut self, destination: &Path) {
        if self.config.matches("rstats_bak", "0") {
            return;
        }
        let Some(date) = local_date(unix_time()) else {
            return;
        };
        if self.last_backup_day == Some(date.year_day) {
            return;
        }
        for index in (1..HI_BACK).rev() {
            let _ = fs::rename(
                backup_path(destination, index),
                backup_path(destination, index + 1),
            );
        }
        if fs::copy(destination, backup_path(destination, 1)).is_ok() {
            self.last_backup_day = Some(date.year_day);
        }
    }

    fn calculate(&mut self) -> io::Result<()> {
        self.current_uptime = uptime();
        let input = fs::read_to_string("/proc/net/dev")?;
        let mut devices = parse_proc_net_dev(&input);
        let wan0 = self.config.get("wan0_ifname");
        let wan1 = self.config.get("wan1_ifname");
        move_wan_interfaces_last(&mut devices, &wan0, &wan1);
        let exclusions = self.config.get("rstats_exclude");
        let lan_ifname = self.config.get("lan_ifname");
        let lan_ifnames = self.config.get("lan_ifnames");
        let wan_ifnames = self.config.get("wan_ifnames");
        let mut vlan = [0_u64; 2];
        let mut aggregate: BTreeMap<(u16, String), [u64; 2]> = BTreeMap::new();

        for mut device in devices {
            if exclusions
                .split_ascii_whitespace()
                .any(|excluded| excluded == device.ifname)
            {
                continue;
            }
            if wan_ifnames.contains("eth0") {
                if lan_ifnames.contains(&device.ifname) && device.ifname.starts_with("vlan1") {
                    vlan[0] = vlan[0].wrapping_add(device.rx);
                    vlan[1] = vlan[1].wrapping_add(device.tx);
                }
                if device.ifname.starts_with("eth0") {
                    device.rx = device.rx.wrapping_sub(vlan[0]);
                    device.tx = device.tx.wrapping_sub(vlan[1]);
                }
            }
            let inode = interface_inode(&device.ifname);
            let normalized = self
                .tracker
                .normalize(&device.ifname, inode, [device.rx, device.tx]);
            device.rx = normalized[0];
            device.tx = normalized[1];
            for (description, counters) in self.config.classify(&device, &lan_ifname, &lan_ifnames)
            {
                let Some(order) = description_order(&description) else {
                    continue;
                };
                let entry = aggregate.entry((order, description)).or_insert([0; 2]);
                entry[0] = entry[0].wrapping_add(counters[0]);
                entry[1] = entry[1].wrapping_add(counters[1]);
            }
        }

        let mut seen = HashSet::new();
        let now = unix_time();
        for ((_order, description), counters) in aggregate.into_iter().take(MAX_SPEED_IF) {
            let index = match self
                .speeds
                .iter()
                .position(|speed| speed.ifname == description)
            {
                Some(index) => index,
                None => {
                    let Ok(speed) = Speed::new(&description, self.current_uptime) else {
                        continue;
                    };
                    self.speeds.push(speed);
                    self.speeds.len() - 1
                }
            };
            let delta = advance_speed(&mut self.speeds[index], self.current_uptime, counters);
            seen.insert(description.clone());
            if description == "INTERNET" && self.config.get_i64("ntp_ready") != 0 {
                self.bump_history(now, delta);
            }
        }

        self.speeds.retain_mut(|speed| {
            if seen.contains(&speed.ifname) {
                speed.sync = 0;
                true
            } else if self.current_uptime - i64::from(speed.uptime) > 600
                || exclusions
                    .split_ascii_whitespace()
                    .any(|excluded| excluded == speed.ifname)
            {
                false
            } else {
                speed.sync = 1;
                true
            }
        });

        if self.current_uptime >= self.save_uptime {
            self.save()?;
            self.save_uptime = self.current_uptime.saturating_add(self.save_interval());
        }
        Ok(())
    }

    fn bump_history(&mut self, now: i64, counters: [u64; 2]) {
        if let Some(date) = local_date(now) {
            bump(
                &mut self.history.daily,
                &mut self.history.daily_tail,
                daily_key(date.year, date.month, date.day),
                counters,
            );
        }
        let offset = self.config.get_i64("rstats_offset").clamp(1, 31);
        let shifted = now.saturating_add((1 - offset) * 86_400);
        if let Some(date) = local_date(shifted) {
            bump(
                &mut self.history.monthly,
                &mut self.history.monthly_tail,
                monthly_key(date.year, date.month),
                counters,
            );
        }
    }

    fn save_speed_js(&self, next: i64) -> io::Result<()> {
        atomic_replace(
            Path::new(SPEED_JS_TMP),
            Path::new(SPEED_JS),
            speed_javascript(&self.speeds, next).as_bytes(),
        )
    }

    fn save_history_js(&self) -> io::Result<()> {
        atomic_replace(
            Path::new(HISTORY_JS_TMP),
            Path::new(HISTORY_JS),
            history_javascript(&self.history).as_bytes(),
        )
    }
}

#[cfg(feature = "isp-meter")]
struct IspMeter {
    last_day: [u64; 2],
    last_month: [u64; 2],
    reset_month: [u64; 2],
    month: [u64; 2],
    last_connect_time: i64,
    current_connect_time: i64,
    total_connect_time: i64,
    reset_base_time: i64,
    saw_closed_connection: bool,
    last_write_uptime: i64,
}

#[cfg(feature = "isp-meter")]
impl IspMeter {
    fn new(config: Nvram, current_uptime: i64) -> Self {
        let mut meter = Self {
            last_day: [
                config.get_i64("isp_day_rx").max(0) as u64,
                config.get_i64("isp_day_tx").max(0) as u64,
            ],
            last_month: [
                config.get_i64("isp_month_rx").max(0) as u64,
                config.get_i64("isp_month_tx").max(0) as u64,
            ],
            reset_month: [0; 2],
            month: [0; 2],
            last_connect_time: config.get_i64("isp_connect_time"),
            current_connect_time: 0,
            total_connect_time: 0,
            reset_base_time: 0,
            saw_closed_connection: false,
            last_write_uptime: current_uptime,
        };
        if let Ok(contents) = read_text_bounded(Path::new(ISP_METER_FILE), 64) {
            if let Some((rx, tx, connection)) = parse_meter_file(&contents) {
                if rx > meter.last_month[0] && tx > meter.last_month[1] {
                    meter.last_month = [rx, tx];
                }
                meter.last_connect_time = meter.last_connect_time.max(connection);
            }
        }
        meter.month = meter.last_month;
        meter
    }

    fn reset(&mut self, config: Nvram, history: &History) {
        self.last_day = [0; 2];
        self.last_month = [0; 2];
        self.month = [0; 2];
        self.reset_month = [
            history.monthly[history.monthly_tail].counter[0] / 1_024,
            history.monthly[history.monthly_tail].counter[1] / 1_024,
        ];
        self.reset_base_time = self.current_connect_time;
        self.last_connect_time = 0;
        self.total_connect_time = 0;
        for key in ["isp_day_tx", "isp_day_rx", "isp_month_tx", "isp_month_rx"] {
            let _ = config.set(key, "0");
        }
        let _ = atomic_write(Path::new(ISP_METER_FILE), b"isp_meter:0,0,0,end");
        if !(config.matches("isp_meter", "disable")
            || config.matches("wan0_state_t", "2") && config.matches("wan0_auxstate_t", "0"))
        {
            config.notify("isp_meter up");
        }
    }

    fn tick(&mut self, config: Nvram, history: &History, current_uptime: i64) {
        let daily = history.daily[history.daily_tail].counter;
        let monthly = history.monthly[history.monthly_tail].counter;
        let today = [
            self.last_day[0].wrapping_add(daily[0] / 1_024),
            self.last_day[1].wrapping_add(daily[1] / 1_024),
        ];
        self.month = [
            self.last_month[0]
                .wrapping_add(monthly[0] / 1_024)
                .wrapping_sub(self.reset_month[0]),
            self.last_month[1]
                .wrapping_add(monthly[1] / 1_024)
                .wrapping_sub(self.reset_month[1]),
        ];
        let _ = config.set("isp_day_rx", &today[0].to_string());
        let _ = config.set("isp_day_tx", &today[1].to_string());
        let _ = config.set("isp_month_rx", &self.month[0].to_string());
        let _ = config.set("isp_month_tx", &self.month[1].to_string());
        self.update_connection_time();

        if !config.matches("isp_meter", "disable") {
            let limit = config.get_i64("isp_limit").max(0) as u64 * 1_000;
            if config.matches("wan0_state_t", "2") {
                let exceeded = if config.matches("isp_meter", "download") {
                    self.month[0] > limit
                } else if config.matches("isp_meter", "both") {
                    self.month[0].wrapping_add(self.month[1]) > limit
                } else if config.matches("isp_meter", "time") {
                    self.total_connect_time > config.get_i64("isp_limit_time") * 60
                } else {
                    false
                };
                if exceeded {
                    config.notify("isp_meter down");
                    self.current_connect_time = 0;
                }
            }
            if current_uptime - self.last_write_uptime >= 60 {
                let _ = config.commit();
                let contents = format!(
                    "isp_meter:{},{},{},end",
                    self.month[0], self.month[1], self.total_connect_time
                );
                let _ = atomic_write(Path::new(ISP_METER_FILE), contents.as_bytes());
                self.last_write_uptime = current_uptime;
            }
        }
    }

    fn update_connection_time(&mut self) {
        let Ok(contents) = read_text_bounded(Path::new("/var/pppd_time"), 64) else {
            return;
        };
        if let Some(value) = contents.strip_prefix("uptime:") {
            if let Ok(start) = value.trim().parse::<i64>() {
                self.current_connect_time = unix_time().saturating_sub(start);
                self.total_connect_time = self
                    .last_connect_time
                    .saturating_add(self.current_connect_time)
                    .saturating_sub(self.reset_base_time);
                self.saw_closed_connection = false;
            }
        } else if let Some(value) = contents.strip_prefix("conntime:") {
            if !self.saw_closed_connection {
                if let Ok(duration) = value.trim().parse::<i64>() {
                    self.last_connect_time = self
                        .last_connect_time
                        .saturating_add(duration)
                        .saturating_sub(self.reset_base_time);
                    self.total_connect_time = self.last_connect_time;
                    self.reset_base_time = 0;
                    self.saw_closed_connection = true;
                }
            }
        }
    }
}

#[cfg(not(feature = "isp-meter"))]
struct IspMeter;

#[cfg(not(feature = "isp-meter"))]
impl IspMeter {
    fn new(_config: Nvram, _current_uptime: i64) -> Self {
        Self
    }

    fn reset(&mut self, _config: Nvram, _history: &History) {}

    fn tick(&mut self, _config: Nvram, _history: &History, _current_uptime: i64) {}
}

fn main() -> io::Result<()> {
    println!("rstats\nCopyright (C) 2006-2009 Jonathan Zarate\n");
    #[cfg(target_arch = "arm")]
    {
        // SAFETY: fork is called before threads are created. The parent exits
        // immediately; the child owns the copied Rust state.
        if unsafe { fork() } != 0 {
            return Ok(());
        }
    }
    install_signal_handlers();
    let new_database = env::args().nth(1).as_deref() == Some("--new");
    let _ = fs::remove_file(LOAD_MARKER);
    let mut daemon = Daemon::new();
    daemon.load(new_database)?;
    let mut meter = IspMeter::new(daemon.config, daemon.current_uptime);
    let mut next = daemon.current_uptime;

    loop {
        daemon.current_uptime = uptime();
        while daemon.current_uptime < next {
            sleep_interruptible((next - daemon.current_uptime).min(u32::MAX as i64) as u32);
            handle_signals(&mut daemon, &mut meter, next)?;
            daemon.current_uptime = uptime();
        }
        if let Err(error) = daemon.calculate() {
            eprintln!("rstats-rs: sampling failed: {error}");
        }
        meter.tick(daemon.config, &daemon.history, daemon.current_uptime);
        next = next.saturating_add(INTERVAL);
    }
}

fn handle_signals(daemon: &mut Daemon, meter: &mut IspMeter, next: i64) -> io::Result<()> {
    let flags = SIGNAL_FLAGS.swap(0, Ordering::Relaxed);
    if flags & FLAG_HUP != 0 {
        if fs::remove_file(LOAD_MARKER).is_ok() {
            daemon.load_new();
        } else {
            daemon.save()?;
        }
    }
    if flags & FLAG_USER1 != 0 {
        daemon.save_speed_js((next - uptime()).max(1))?;
    }
    if flags & FLAG_USER2 != 0 {
        daemon.save_history_js()?;
    }
    if flags & FLAG_RESET_METER != 0 {
        meter.reset(daemon.config, &daemon.history);
    }
    if flags & FLAG_TERM != 0 {
        daemon.save()?;
        std::process::exit(0);
    }
    Ok(())
}

extern "C" fn signal_handler(number: c_int) {
    let flag = match number {
        SIGHUP => FLAG_HUP,
        SIGUSR1 => FLAG_USER1,
        SIGUSR2 => FLAG_USER2,
        SIGTERM | SIGINT => FLAG_TERM,
        SIGTSTP => FLAG_RESET_METER,
        _ => 0,
    };
    SIGNAL_FLAGS.fetch_or(flag, Ordering::Relaxed);
}

fn install_signal_handlers() {
    for number in [SIGHUP, SIGUSR1, SIGUSR2, SIGTERM, SIGINT, SIGTSTP] {
        // SAFETY: the handler only performs an async-signal-safe atomic store
        // and has the C ABI/signature required by signal(2).
        unsafe {
            signal(number, signal_handler as usize);
        }
    }
}

fn sleep_interruptible(seconds: u32) {
    // SAFETY: sleep has no pointer arguments; signals may shorten the wait.
    unsafe {
        sleep(seconds);
    }
}

fn uptime() -> i64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|contents| {
            contents
                .split_ascii_whitespace()
                .next()?
                .parse::<f64>()
                .ok()
        })
        .map_or(0, |seconds| seconds.max(0.0) as i64)
}

fn unix_time() -> i64 {
    // SAFETY: null asks time(2) to return the value directly.
    unsafe { time(std::ptr::null_mut()) as i64 }
}

fn local_date(timestamp: i64) -> Option<LocalDate> {
    #[cfg(target_pointer_width = "32")]
    let timestamp = timestamp.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as c_long;
    #[cfg(target_pointer_width = "64")]
    let timestamp = timestamp as c_long;
    // SAFETY: zero is a valid initial representation for C struct tm.
    let mut value: Tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers reference live, correctly aligned objects.
    if unsafe { localtime_r(&timestamp, &mut value) }.is_null() {
        None
    } else {
        Some(LocalDate {
            year: value.tm_year,
            month: value.tm_mon,
            day: value.tm_mday,
            year_day: value.tm_yday,
        })
    }
}

#[cfg(target_arch = "arm")]
fn description_from_c(buffer: &[c_char; 12]) -> Option<String> {
    let end = buffer.iter().position(|byte| *byte == 0)?;
    let bytes: Vec<u8> = buffer[..end].iter().map(|byte| *byte as u8).collect();
    let description = String::from_utf8(bytes).ok()?;
    valid_description(&description).then_some(description)
}

fn interface_inode(ifname: &str) -> u64 {
    if !valid_kernel_ifname(ifname) {
        return 0;
    }
    fs::metadata(format!("/sys/class/net/{ifname}"))
        .map(|metadata| metadata.ino())
        .unwrap_or(0)
}

fn resolve_save_path(config: Nvram) -> String {
    let mut path = config.get("rstats_path");
    if path.len() > 64 || path.bytes().any(|byte| byte == 0) {
        return String::new();
    }
    if path.ends_with('/') {
        let mac = parse_mac(&config.get("lan_hwaddr")).unwrap_or([0; 6]);
        path.push_str(&format!(
            "tomato_rstats_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.gz",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ));
    }
    path
}

fn parse_mac(input: &str) -> Option<[u8; 6]> {
    let mut output = [0; 6];
    let mut parts = input.split(':');
    for byte in &mut output {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    parts.next().is_none().then_some(output)
}

fn gzip_name(base: &str) -> String {
    format!("{base}.gz")
}

fn backup_path(path: &Path, index: usize) -> PathBuf {
    let mut base = path.to_string_lossy().into_owned();
    if base.ends_with(".gz") {
        base.truncate(base.len() - 3);
    }
    PathBuf::from(format!("{base}_{index}.bak"))
}

fn gzip_binary() -> &'static str {
    if Path::new("/bin/gzip").exists() {
        "/bin/gzip"
    } else {
        "/usr/bin/gzip"
    }
}

fn gzip_write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    ensure_parent(path)?;
    let temporary = temporary_path(path)?;
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let mut child = Command::new(gzip_binary())
        .args(["-c", "-n"])
        .stdin(Stdio::piped())
        .stdout(Stdio::from(output))
        .stderr(Stdio::null())
        .spawn()?;
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("gzip stdin unavailable"))?
        .write_all(contents);
    let status = child.wait()?;
    if write_result.is_err() || !status.success() {
        let _ = fs::remove_file(&temporary);
        return write_result.and_then(|()| Err(io::Error::other("gzip compression failed")));
    }
    fs::rename(temporary, path)
}

fn gzip_read_bounded(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    let input = File::open(path)?;
    let mut child = Command::new(gzip_binary())
        .args(["-d", "-c"])
        .stdin(Stdio::from(input))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("gzip stdout unavailable"))?;
    let mut output = Vec::with_capacity(maximum.min(64 * 1024));
    stdout.take(maximum as u64 + 1).read_to_end(&mut output)?;
    if output.len() > maximum {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gzip output exceeds component limit",
        ));
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid gzip archive",
        ));
    }
    Ok(output)
}

fn atomic_replace(temporary: &Path, destination: &Path, contents: &[u8]) -> io::Result<()> {
    ensure_parent(temporary)?;
    ensure_parent(destination)?;
    atomic_write(temporary, contents)?;
    fs::rename(temporary, destination)
}

fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    let temporary = write_temporary(path, contents)?;
    fs::rename(temporary, path)
}

fn write_temporary(path: &Path, contents: &[u8]) -> io::Result<PathBuf> {
    ensure_parent(path)?;
    let temporary = temporary_path(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    if let Err(error) = file.write_all(contents) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);
    Ok(temporary)
}

fn temporary_path(path: &Path) -> io::Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid output filename"))?;
    let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(".{name}.rstats-{}-{nonce}.tmp", std::process::id())))
}

fn ensure_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn read_file_bounded(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(maximum.min(64 * 1024));
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut output)?;
    if output.len() > maximum {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds component limit",
        ))
    } else {
        Ok(output)
    }
}

fn read_text_bounded(path: &Path, maximum: usize) -> io::Result<String> {
    let bytes = read_file_bounded(path, maximum)?;
    Ok(String::from_utf8_lossy(&bytes)
        .trim_end_matches(['\0', '\n', '\r'])
        .to_owned())
}

fn read_i32_file(path: &Path) -> Option<i32> {
    let bytes = read_file_bounded(path, 4).ok()?;
    (bytes.len() == 4).then(|| i32::from_le_bytes(bytes.try_into().expect("length checked")))
}

#[cfg(any(feature = "isp-meter", test))]
fn parse_meter_file(contents: &str) -> Option<(u64, u64, i64)> {
    let values = contents
        .trim()
        .strip_prefix("isp_meter:")?
        .strip_suffix(",end")?;
    let mut values = values.split(',');
    let rx = values.next()?.parse().ok()?;
    let tx = values.next()?.parse().ok()?;
    let connection = values.next()?.parse().ok()?;
    values.next().is_none().then_some((rx, tx, connection))
}

fn clamp_i32(value: i64) -> i32 {
    value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_path_rejects_oversized_nvram_and_appends_mac() {
        env::set_var("RSTATS_RSTATS_PATH", "/mnt/stats/");
        env::set_var("RSTATS_LAN_HWADDR", "00:11:22:aa:bb:cc");
        assert_eq!(
            resolve_save_path(Nvram),
            "/mnt/stats/tomato_rstats_001122aabbcc.gz"
        );
        env::set_var("RSTATS_RSTATS_PATH", "x".repeat(65));
        assert_eq!(resolve_save_path(Nvram), "");
    }

    #[test]
    fn backup_names_preserve_legacy_convention() {
        assert_eq!(
            backup_path(Path::new("/mnt/rstats.gz"), 3),
            PathBuf::from("/mnt/rstats_3.bak")
        );
        assert_eq!(
            backup_path(Path::new("/mnt/rstats"), 1),
            PathBuf::from("/mnt/rstats_1.bak")
        );
    }

    #[test]
    fn meter_parser_is_exact() {
        assert_eq!(parse_meter_file("isp_meter:1,2,3,end"), Some((1, 2, 3)));
        assert_eq!(parse_meter_file("isp_meter:1,2,end"), None);
        assert_eq!(parse_meter_file("x;rm -rf /"), None);
    }

    #[test]
    fn gzip_reader_round_trips_and_enforces_limit() {
        let directory = env::temp_dir().join(format!("rstats-test-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("state.gz");
        gzip_write_atomic(&path, b"bounded state").unwrap();
        assert_eq!(gzip_read_bounded(&path, 13).unwrap(), b"bounded state");
        assert!(gzip_read_bounded(&path, 12).is_err());
        let _ = fs::remove_file(path);
        let _ = fs::remove_dir(directory);
    }
}
