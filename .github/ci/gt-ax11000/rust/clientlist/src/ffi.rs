//! C ABI for `httpd/web.c`.
//!
//! Every entry point takes NUL-terminated C strings and writes a
//! NUL-terminated result into a caller-provided buffer; nothing allocated in
//! Rust is handed to C and no `json_object *` exists on either side of the
//! boundary. Return values are byte lengths (>= 0) or the negative sentinels
//! below.

use crate::amas;
use crate::cache;
use crate::json::Object;
use crate::model::{BuildInputs, ClientList};
use crate::nvram::{LocalTime, MultifilterInputs};
use crate::render::{self, DatabaseInputs, RenderError, MAX_DATABASE, MAX_OUTPUT};
use crate::shm::{self, ShmError};
use crate::snapshot::{Snapshot, SnapshotError};
use core::ffi::{c_char, c_int, CStr};
use core::{mem, ptr, slice};
use std::path::Path;

/// NULL required pointer or an invalid argument.
pub const CLIENTLIST_INVALID: c_int = -1;
/// A path, address or name argument is not valid UTF-8.
pub const CLIENTLIST_INVALID_UTF8: c_int = -2;
/// The model/segment size pair is neither known layout.
pub const CLIENTLIST_UNSUPPORTED_LAYOUT: c_int = -3;
/// The document does not fit the caller's buffer or the internal bound.
pub const CLIENTLIST_OVERFLOW: c_int = -4;
/// No shared-memory segment exists (networkmap has not published one).
pub const CLIENTLIST_NO_SEGMENT: c_int = -5;
/// The advisory lock or the attach failed.
pub const CLIENTLIST_LOCK_FAILED: c_int = -6;
/// A file could not be read or written.
pub const CLIENTLIST_IO: c_int = -7;
/// The cache exists but is not servable (regenerate).
pub const CLIENTLIST_CACHE_REJECTED: c_int = -8;

const DEFAULT_LOCK_DIRECTORY: &str = "/var/lock";

/// `is_re_node(mac, 1)` supplied by C; `NULL` means "no RE node".
pub type IsReNodeFn = unsafe extern "C" fn(*const c_char) -> c_int;

/// Inputs of the live list. Every string may be NULL (treated as empty,
/// like `nvram_safe_get()`); the NVRAM text lists are converted lossily.
#[repr(C)]
pub struct RustHttpdClientlistInputs {
    /// `SHMKEY_LAN`
    pub shm_key: c_int,
    pub productid: *const c_char,
    pub lan_ipaddr: *const c_char,
    pub login_ip_str: *const c_char,
    pub rog_clientlist: *const c_char,
    pub custom_clientlist: *const c_char,
    pub qos_rulelist: *const c_char,
    pub wtf_rulelist: *const c_char,
    /// `nvram_get_int("MULTIFILTER_ALL")`
    pub multifilter_all: c_int,
    pub multifilter_mac: *const c_char,
    pub multifilter_enable: *const c_char,
    pub multifilter_daytime: *const c_char,
    /// `is_amas_support()`
    pub amas_support: c_int,
    /// `/tmp/clientlist.json`; NULL disables RE details.
    pub amas_client_list_path: *const c_char,
    /// Directory of the vendor lock files; NULL means `/var/lock`.
    pub lock_dir: *const c_char,
    pub is_re_node: Option<IsReNodeFn>,
}

/// Inputs of the persistent-database view.
#[repr(C)]
pub struct RustHttpdClientlistDbInputs {
    /// `/jffs/nmp_cl_json.js`
    pub db_path: *const c_char,
    pub rog_clientlist: *const c_char,
    pub custom_clientlist: *const c_char,
    /// `MAC>CAP<MAC>RE<...` from `get_amas_info()`; NULL when unavailable.
    pub amas_node_types: *const c_char,
    pub is_re_node: Option<IsReNodeFn>,
}

/// # Safety
/// `pointer` is NULL or addresses a NUL-terminated string.
unsafe fn lossy_text<'a>(pointer: *const c_char) -> std::borrow::Cow<'a, str> {
    if pointer.is_null() {
        return std::borrow::Cow::Borrowed("");
    }
    // SAFETY: the caller contract requires a readable NUL-terminated string.
    unsafe { CStr::from_ptr(pointer) }.to_string_lossy()
}

/// # Safety
/// `pointer` is NULL or addresses a NUL-terminated string.
unsafe fn strict_text<'a>(pointer: *const c_char) -> Result<Option<&'a str>, c_int> {
    if pointer.is_null() {
        return Ok(None);
    }
    // SAFETY: the caller contract requires a readable NUL-terminated string.
    unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .map(Some)
        .map_err(|_| CLIENTLIST_INVALID_UTF8)
}

/// # Safety
/// `buffer` is NULL or addresses `capacity` writable bytes.
unsafe fn copy_out(buffer: *mut c_char, capacity: usize, text: &str) -> c_int {
    if buffer.is_null() || capacity == 0 {
        return CLIENTLIST_INVALID;
    }
    if text.len() >= capacity || text.len() > MAX_OUTPUT || text.len() > c_int::MAX as usize {
        return CLIENTLIST_OVERFLOW;
    }
    // SAFETY: the caller contract requires `capacity` writable bytes and
    // `text.len() + 1 <= capacity` was checked above.
    unsafe {
        ptr::copy_nonoverlapping(text.as_ptr(), buffer.cast::<u8>(), text.len());
        *buffer.add(text.len()) = 0;
    }
    text.len() as c_int
}

fn render_code(error: RenderError) -> c_int {
    match error {
        RenderError::Oversized => CLIENTLIST_OVERFLOW,
        RenderError::Serialize => CLIENTLIST_INVALID,
    }
}

fn shm_code(error: &ShmError) -> c_int {
    match error {
        ShmError::Lock(_) | ShmError::Attach(_) => CLIENTLIST_LOCK_FAILED,
        ShmError::NoSegment(_) => CLIENTLIST_NO_SEGMENT,
        ShmError::Stat(_) | ShmError::Unsupported(_) => CLIENTLIST_UNSUPPORTED_LAYOUT,
    }
}

fn local_time() -> LocalTime {
    // SAFETY: `time` accepts NULL; `localtime_r` writes a full `struct tm`
    // into the zeroed local and reads only the time value.
    unsafe {
        let now = libc::time(ptr::null_mut());
        let mut tm: libc::tm = mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return LocalTime {
                weekday: 0,
                hour: 0,
            };
        }
        LocalTime {
            weekday: tm.tm_wday,
            hour: tm.tm_hour,
        }
    }
}

struct ReNode(Option<IsReNodeFn>);

impl ReNode {
    fn check(&self, mac: &str) -> bool {
        let Some(function) = self.0 else {
            return false;
        };
        let Ok(mac) = std::ffi::CString::new(mac) else {
            return false;
        };
        // SAFETY: the C callback receives a valid NUL-terminated string that
        // outlives the call.
        unsafe { function(mac.as_ptr()) != 0 }
    }
}

/// Snapshot + build of the live list for `inputs`.
///
/// # Safety
/// `inputs` addresses a valid struct whose pointers follow the field contract.
unsafe fn build_live(inputs: &RustHttpdClientlistInputs) -> Result<ClientList, c_int> {
    // SAFETY: every string pointer follows the struct contract.
    let (
        productid,
        lan_ipaddr,
        login_ip_str,
        rog_clientlist,
        custom_clientlist,
        qos_rulelist,
        wtf_rulelist,
        multifilter_mac,
        multifilter_enable,
        multifilter_daytime,
        lock_dir,
    ) = unsafe {
        (
            lossy_text(inputs.productid),
            lossy_text(inputs.lan_ipaddr),
            lossy_text(inputs.login_ip_str),
            lossy_text(inputs.rog_clientlist),
            lossy_text(inputs.custom_clientlist),
            lossy_text(inputs.qos_rulelist),
            lossy_text(inputs.wtf_rulelist),
            lossy_text(inputs.multifilter_mac),
            lossy_text(inputs.multifilter_enable),
            lossy_text(inputs.multifilter_daytime),
            strict_text(inputs.lock_dir)?.unwrap_or(DEFAULT_LOCK_DIRECTORY),
        )
    };
    // SAFETY: as above.
    let re_details_path = unsafe { strict_text(inputs.amas_client_list_path)? };
    let lock_directory = Path::new(lock_dir);

    let segment =
        shm::read_segment(inputs.shm_key, lock_directory).map_err(|error| shm_code(&error))?;
    let snapshot = Snapshot::parse(&productid, &segment).map_err(|error| match error {
        SnapshotError::UnsupportedLayout(_) | SnapshotError::Truncated => {
            CLIENTLIST_UNSUPPORTED_LAYOUT
        }
    })?;

    let re_details = match re_details_path {
        Some(path) if inputs.amas_support != 0 => {
            // Fail soft to "no RE details" like the json-c reader.
            let document = shm::FileLock::acquire(lock_directory, "clientlist")
                .ok()
                .and_then(|_lock| {
                    cache::read_bounded(Path::new(path), amas::MAX_RE_CLIENT_FILE).ok()
                });
            document
                .map(|bytes| amas::parse_re_client_details(&bytes))
                .unwrap_or_default()
        }
        _ => Default::default(),
    };
    let re_node = ReNode(inputs.is_re_node);
    let is_re_node = |mac: &str| re_node.check(mac);

    Ok(ClientList::build(
        &snapshot,
        &BuildInputs {
            lan_ipaddr: &lan_ipaddr,
            login_ip_str: &login_ip_str,
            rog_clientlist: &rog_clientlist,
            custom_clientlist: &custom_clientlist,
            qos_rulelist: &qos_rulelist,
            wtf_rulelist: &wtf_rulelist,
            multifilter: MultifilterInputs {
                all: inputs.multifilter_all,
                mac: &multifilter_mac,
                enable: &multifilter_enable,
                daytime: &multifilter_daytime,
            },
            amas_support: inputs.amas_support != 0,
            now: local_time(),
            re_details: &re_details,
            is_re_node: &is_re_node,
        },
    ))
}

/// Render the live client list (`ej_get_clientlist()` document) into
/// `buffer`.
///
/// # Safety
/// `inputs` must be NULL or a valid struct per the field contract; `buffer`
/// must be NULL or address `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_clientlist_render(
    inputs: *const RustHttpdClientlistInputs,
    buffer: *mut c_char,
    capacity: usize,
) -> c_int {
    if inputs.is_null() || buffer.is_null() || capacity == 0 {
        return CLIENTLIST_INVALID;
    }
    // SAFETY: non-null per the check above and valid per the contract.
    let list = match unsafe { build_live(&*inputs) } {
        Ok(list) => list,
        Err(code) => return code,
    };
    match render::render_live(&list, capacity - 1) {
        // SAFETY: caller contract for `buffer`.
        Ok(text) => unsafe { copy_out(buffer, capacity, &text) },
        Err(error) => render_code(error),
    }
}

/// Atomically replace `path` with `json[..length]` (mode 0644).
///
/// # Safety
/// `path` must address a NUL-terminated string and `json` `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_clientlist_cache_write(
    path: *const c_char,
    json: *const c_char,
    length: usize,
) -> c_int {
    if path.is_null() || json.is_null() || length > MAX_OUTPUT {
        return CLIENTLIST_INVALID;
    }
    // SAFETY: caller contract.
    let path = match unsafe { strict_text(path) } {
        Ok(Some(path)) => path,
        _ => return CLIENTLIST_INVALID_UTF8,
    };
    // SAFETY: the caller contract requires `length` readable bytes.
    let bytes = unsafe { slice::from_raw_parts(json.cast::<u8>(), length) };
    if !cache::cache_is_servable(bytes) {
        return CLIENTLIST_CACHE_REJECTED;
    }
    match cache::write_atomic(Path::new(path), bytes) {
        Ok(()) => 0,
        Err(_) => CLIENTLIST_IO,
    }
}

/// Copy a servable cache document verbatim into `buffer`.
///
/// # Safety
/// `path` must address a NUL-terminated string; `buffer` must address
/// `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_clientlist_cache_read(
    path: *const c_char,
    buffer: *mut c_char,
    capacity: usize,
) -> c_int {
    if path.is_null() || buffer.is_null() || capacity == 0 {
        return CLIENTLIST_INVALID;
    }
    // SAFETY: caller contract.
    let path = match unsafe { strict_text(path) } {
        Ok(Some(path)) => path,
        _ => return CLIENTLIST_INVALID_UTF8,
    };
    let limit = (capacity - 1).min(MAX_OUTPUT);
    match cache::read_cache(Path::new(path), limit) {
        Ok(bytes) => match std::str::from_utf8(&bytes) {
            // SAFETY: caller contract for `buffer`.
            Ok(text) => unsafe { copy_out(buffer, capacity, text) },
            Err(_) => CLIENTLIST_CACHE_REJECTED,
        },
        Err(cache::CacheError::Io(_)) => CLIENTLIST_IO,
        Err(cache::CacheError::Oversized) => CLIENTLIST_OVERFLOW,
        Err(cache::CacheError::Rejected) => CLIENTLIST_CACHE_REJECTED,
    }
}

/// `get_client_name()`: resolve `ip` in a rendered document. Returns 1 when
/// found (name copied), 0 when absent (`name` cleared).
///
/// # Safety
/// `json` must address `length` readable bytes, `ip` a NUL-terminated string
/// and `name` `name_capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_clientlist_name_for_ip(
    json: *const c_char,
    length: usize,
    ip: *const c_char,
    name: *mut c_char,
    name_capacity: usize,
) -> c_int {
    if json.is_null() || ip.is_null() || name.is_null() || name_capacity == 0 || length > MAX_OUTPUT
    {
        return CLIENTLIST_INVALID;
    }
    // SAFETY: caller contract.
    unsafe { *name = 0 };
    // SAFETY: caller contract.
    let ip = match unsafe { strict_text(ip) } {
        Ok(Some(ip)) => ip,
        _ => return CLIENTLIST_INVALID_UTF8,
    };
    // SAFETY: the caller contract requires `length` readable bytes.
    let document = unsafe { slice::from_raw_parts(json.cast::<u8>(), length) };
    let Some(found) = render::name_for_ip(document, ip) else {
        return 0;
    };
    // strlcpy(): keep the longest prefix that fits with its terminator.
    let mut end = found.len().min(name_capacity - 1);
    while end > 0 && !found.is_char_boundary(end) {
        end -= 1;
    }
    // SAFETY: `end < name_capacity` and the caller contract for `name`.
    unsafe {
        ptr::copy_nonoverlapping(found.as_ptr(), name.cast::<u8>(), end);
        *name.add(end) = 0;
    }
    1
}

/// `get_sdn_client_num()`: add online clients per `sdn_idx` into `counts`.
///
/// # Safety
/// `json` must address `length` readable bytes and `counts`
/// `count_capacity` writable ints.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_clientlist_sdn_client_count(
    json: *const c_char,
    length: usize,
    counts: *mut c_int,
    count_capacity: usize,
) -> c_int {
    if json.is_null() || counts.is_null() || count_capacity == 0 || length > MAX_OUTPUT {
        return CLIENTLIST_INVALID;
    }
    // SAFETY: caller contract for both buffers.
    let (document, counts) = unsafe {
        (
            slice::from_raw_parts(json.cast::<u8>(), length),
            slice::from_raw_parts_mut(counts, count_capacity),
        )
    };
    if render::sdn_client_counts(document, counts) {
        0
    } else {
        CLIENTLIST_INVALID
    }
}

/// # Safety
/// `path` addresses a NUL-terminated string or is NULL.
unsafe fn load_database(path: *const c_char) -> Result<Option<Object>, c_int> {
    // SAFETY: caller contract.
    let Some(path) = (unsafe { strict_text(path)? }) else {
        return Err(CLIENTLIST_INVALID);
    };
    Ok(cache::read_bounded(Path::new(path), MAX_DATABASE)
        .ok()
        .and_then(|bytes| render::parse_database(&bytes)))
}

/// `ej_get_clientlist_from_json_database()` document.
///
/// # Safety
/// `inputs` must be NULL or valid per the field contract; `buffer` must
/// address `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_clientlist_database_render(
    inputs: *const RustHttpdClientlistDbInputs,
    buffer: *mut c_char,
    capacity: usize,
) -> c_int {
    if inputs.is_null() || buffer.is_null() || capacity == 0 {
        return CLIENTLIST_INVALID;
    }
    // SAFETY: non-null per the check above and valid per the contract.
    let inputs = unsafe { &*inputs };
    // SAFETY: field contract.
    let database = match unsafe { load_database(inputs.db_path) } {
        Ok(database) => database,
        Err(code) => return code,
    };
    // SAFETY: field contract.
    let (rog_clientlist, custom_clientlist, amas_node_types) = unsafe {
        (
            lossy_text(inputs.rog_clientlist),
            lossy_text(inputs.custom_clientlist),
            lossy_text(inputs.amas_node_types),
        )
    };
    let re_node = ReNode(inputs.is_re_node);
    let is_re_node = |mac: &str| re_node.check(mac);
    let result = render::render_database(
        database,
        &DatabaseInputs {
            rog_clientlist: &rog_clientlist,
            custom_clientlist: &custom_clientlist,
            amas_node_types: &amas_node_types,
            is_re_node: &is_re_node,
        },
        capacity - 1,
    );
    match result {
        // SAFETY: caller contract for `buffer`.
        Ok(text) => unsafe { copy_out(buffer, capacity, &text) },
        Err(error) => render_code(error),
    }
}

/// `ej_get_all_basic_clientlist()` pairs; `CLIENTLIST_IO` when the database
/// is missing or unparseable (C writes `[]`).
///
/// # Safety
/// `db_path` must address a NUL-terminated string, `custom_clientlist` NULL
/// or one, and `buffer` `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_clientlist_all_basic_render(
    db_path: *const c_char,
    custom_clientlist: *const c_char,
    buffer: *mut c_char,
    capacity: usize,
) -> c_int {
    if db_path.is_null() || buffer.is_null() || capacity == 0 {
        return CLIENTLIST_INVALID;
    }
    // SAFETY: caller contract.
    let database = match unsafe { load_database(db_path) } {
        Ok(Some(database)) => database,
        Ok(None) => return CLIENTLIST_IO,
        Err(code) => return code,
    };
    // SAFETY: caller contract.
    let custom_clientlist = unsafe { lossy_text(custom_clientlist) };
    match render::render_all_basic(&database, &custom_clientlist, capacity - 1) {
        // SAFETY: caller contract for `buffer`.
        Ok(text) => unsafe { copy_out(buffer, capacity, &text) },
        Err(error) => render_code(error),
    }
}

/// `get_basic_clientlist_info()` for `opt` 0..=3. `networkmap_alive` is the
/// `pids("networkmap")` gate; the live list is also treated as absent when
/// the segment cannot be decoded.
///
/// # Safety
/// `inputs` must be NULL or valid per the field contract; `db_path` NULL or
/// a NUL-terminated string; `buffer` must address `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_clientlist_basic_render(
    inputs: *const RustHttpdClientlistInputs,
    networkmap_alive: c_int,
    db_path: *const c_char,
    opt: c_int,
    buffer: *mut c_char,
    capacity: usize,
) -> c_int {
    if inputs.is_null() || buffer.is_null() || capacity == 0 || !(0..=3).contains(&opt) {
        return CLIENTLIST_INVALID;
    }
    let live = if networkmap_alive != 0 {
        // SAFETY: non-null per the check above and valid per the contract.
        unsafe { build_live(&*inputs) }.ok()
    } else {
        None
    };
    let database = if opt == 3 && !db_path.is_null() {
        // SAFETY: caller contract.
        match unsafe { load_database(db_path) } {
            Ok(database) => database,
            Err(code) => return code,
        }
    } else {
        None
    };
    match render::render_basic(live.as_ref(), database.as_ref(), opt, capacity - 1) {
        // SAFETY: caller contract for `buffer`.
        Ok(text) => unsafe { copy_out(buffer, capacity, &text) },
        Err(error) => render_code(error),
    }
}

/// `search_device_name_in_clientlist()`: newline-terminated MACs of DB
/// records named `name`; returns the match count.
///
/// # Safety
/// `db_path` and `name` must address NUL-terminated strings,
/// `custom_clientlist` NULL or one, and `buffer` `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_clientlist_search_name(
    db_path: *const c_char,
    custom_clientlist: *const c_char,
    name: *const c_char,
    buffer: *mut c_char,
    capacity: usize,
) -> c_int {
    if db_path.is_null() || name.is_null() || buffer.is_null() || capacity == 0 {
        return CLIENTLIST_INVALID;
    }
    // SAFETY: caller contract.
    let name = match unsafe { strict_text(name) } {
        Ok(Some(name)) => name,
        _ => return CLIENTLIST_INVALID_UTF8,
    };
    // SAFETY: caller contract.
    let database = match unsafe { load_database(db_path) } {
        Ok(Some(database)) => database,
        Ok(None) => return CLIENTLIST_IO,
        Err(code) => return code,
    };
    // SAFETY: caller contract.
    let custom_clientlist = unsafe { lossy_text(custom_clientlist) };
    let matches = render::search_device_name(&database, &custom_clientlist, name);
    let mut text = String::new();
    for mac in &matches {
        text.push_str(mac);
        text.push('\n');
    }
    // SAFETY: caller contract for `buffer`.
    let copied = unsafe { copy_out(buffer, capacity, &text) };
    if copied < 0 {
        return copied;
    }
    matches.len().min(c_int::MAX as usize) as c_int
}
