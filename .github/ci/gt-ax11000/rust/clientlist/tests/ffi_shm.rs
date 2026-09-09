//! End-to-end C ABI test against a real SysV segment with a private key.

use clientlist::ffi::{
    rust_httpd_clientlist_basic_render, rust_httpd_clientlist_cache_read,
    rust_httpd_clientlist_cache_write, rust_httpd_clientlist_name_for_ip,
    rust_httpd_clientlist_render, RustHttpdClientlistInputs, CLIENTLIST_CACHE_REJECTED,
    CLIENTLIST_INVALID, CLIENTLIST_NO_SEGMENT, CLIENTLIST_OVERFLOW, CLIENTLIST_UNSUPPORTED_LAYOUT,
};
use clientlist::layout::Layout;
use clientlist::snapshot::builder::SegmentBuilder;
use std::ffi::{c_char, c_int, CString};
use std::path::PathBuf;
use std::ptr;

struct Segment {
    id: c_int,
}

impl Segment {
    fn create(key: c_int, bytes: &[u8]) -> Segment {
        // SAFETY: plain system calls; the segment is written once here.
        unsafe {
            let id = libc::shmget(key, bytes.len(), libc::IPC_CREAT | libc::IPC_EXCL | 0o600);
            assert!(id != -1, "shmget: {}", std::io::Error::last_os_error());
            let address = libc::shmat(id, ptr::null(), 0);
            assert!(address as isize != -1);
            ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len());
            libc::shmdt(address);
            Segment { id }
        }
    }
}

impl Drop for Segment {
    fn drop(&mut self) {
        // SAFETY: `id` names the segment created above.
        unsafe { libc::shmctl(self.id, libc::IPC_RMID, ptr::null_mut()) };
    }
}

fn private_key(salt: c_int) -> c_int {
    0x4300_0000 | ((std::process::id() as c_int & 0x000f_ffff) << 4) | (salt & 0xf)
}

fn scratch() -> PathBuf {
    let directory = std::env::temp_dir().join(format!("clientlist-ffi-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

unsafe extern "C" fn re_node_f1(mac: *const c_char) -> c_int {
    // SAFETY: the callee contract passes a NUL-terminated string.
    let mac = unsafe { std::ffi::CStr::from_ptr(mac) }.to_str().unwrap();
    c_int::from(mac == "AA:BB:CC:DD:EE:F1")
}

struct Owned {
    productid: CString,
    lan: CString,
    login: CString,
    rog: CString,
    custom: CString,
    empty: CString,
    lock_dir: CString,
    inputs: RustHttpdClientlistInputs,
}

fn inputs(key: c_int, productid: &str, lock_dir: &str) -> Box<Owned> {
    let mut owned = Box::new(Owned {
        productid: CString::new(productid).unwrap(),
        lan: CString::new("192.168.50.1").unwrap(),
        login: CString::new("192.168.50.20").unwrap(),
        rog: CString::new("<AA:BB:CC:DD:EE:03").unwrap(),
        custom: CString::new("<Pauls iPhone>AA:BB:CC:DD:EE:02>0>5>cb>1").unwrap(),
        empty: CString::new("").unwrap(),
        lock_dir: CString::new(lock_dir).unwrap(),
        inputs: RustHttpdClientlistInputs {
            shm_key: key,
            productid: ptr::null(),
            lan_ipaddr: ptr::null(),
            login_ip_str: ptr::null(),
            rog_clientlist: ptr::null(),
            custom_clientlist: ptr::null(),
            qos_rulelist: ptr::null(),
            wtf_rulelist: ptr::null(),
            multifilter_all: 0,
            multifilter_mac: ptr::null(),
            multifilter_enable: ptr::null(),
            multifilter_daytime: ptr::null(),
            amas_support: 1,
            amas_client_list_path: ptr::null(),
            lock_dir: ptr::null(),
            is_re_node: Some(re_node_f1),
        },
    });
    owned.inputs.productid = owned.productid.as_ptr();
    owned.inputs.lan_ipaddr = owned.lan.as_ptr();
    owned.inputs.login_ip_str = owned.login.as_ptr();
    owned.inputs.rog_clientlist = owned.rog.as_ptr();
    owned.inputs.custom_clientlist = owned.custom.as_ptr();
    owned.inputs.qos_rulelist = owned.empty.as_ptr();
    owned.inputs.lock_dir = owned.lock_dir.as_ptr();
    owned
}

fn segment_bytes() -> Vec<u8> {
    let mut builder = SegmentBuilder::new(Layout::Legacy);
    builder
        .count(3)
        .ip(0, [192, 168, 50, 20])
        .mac(0, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02])
        .device_name(0, b"Phone")
        .online(0, 1)
        .wireless(0, 2)
        .ip(1, [192, 168, 50, 30])
        .mac(1, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03])
        .device_name(1, b"Console")
        .online(1, 0)
        .ip(2, [192, 168, 50, 39])
        .mac(2, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf1])
        .device_name(2, b"RE")
        .online(2, 1);
    builder.build()
}

#[test]
fn render_from_a_real_segment_and_fail_closed_paths() {
    let directory = scratch();
    let lock_dir = directory.to_str().unwrap();
    let key = private_key(1);
    let _segment = Segment::create(key, &segment_bytes());
    let owned = inputs(key, "GT-AX11000", lock_dir);
    let mut buffer = vec![0_u8; 64 * 1024];

    // SAFETY: valid inputs and a buffer of the stated capacity.
    let length = unsafe {
        rust_httpd_clientlist_render(&owned.inputs, buffer.as_mut_ptr().cast(), buffer.len())
    };
    assert!(length > 0, "render failed: {length}");
    let text = std::str::from_utf8(&buffer[..length as usize]).unwrap();
    assert_eq!(buffer[length as usize], 0);
    let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(parsed["maclist"], serde_json::json!(["AA:BB:CC:DD:EE:02"]));
    assert_eq!(parsed["ClientAPILevel"], "7");
    assert_eq!(parsed["AA:BB:CC:DD:EE:02"]["nickName"], "Pauls iPhone");
    assert_eq!(parsed["AA:BB:CC:DD:EE:02"]["type"], "5");
    assert_eq!(parsed["AA:BB:CC:DD:EE:02"]["isLogin"], "1");
    assert_eq!(parsed["AA:BB:CC:DD:EE:03"]["ROG"], "1");
    assert_eq!(parsed["AA:BB:CC:DD:EE:03"]["type"], "36");
    assert!(parsed.get("AA:BB:CC:DD:EE:F1").is_none());
    assert_eq!(
        std::fs::metadata(directory.join("networkmap.lock"))
            .unwrap()
            .len(),
        0
    );

    // The same segment is not decoded for another model.
    let other = inputs(key, "RT-AX88U", lock_dir);
    // SAFETY: as above.
    assert_eq!(
        unsafe {
            rust_httpd_clientlist_render(&other.inputs, buffer.as_mut_ptr().cast(), buffer.len())
        },
        CLIENTLIST_UNSUPPORTED_LAYOUT
    );
    // NULL buffer, NULL inputs, small buffer.
    // SAFETY: NULL arguments are part of the contract.
    unsafe {
        assert_eq!(
            rust_httpd_clientlist_render(&owned.inputs, ptr::null_mut(), 16),
            CLIENTLIST_INVALID
        );
        assert_eq!(
            rust_httpd_clientlist_render(ptr::null(), buffer.as_mut_ptr().cast(), buffer.len()),
            CLIENTLIST_INVALID
        );
        assert_eq!(
            rust_httpd_clientlist_render(&owned.inputs, buffer.as_mut_ptr().cast(), 64),
            CLIENTLIST_OVERFLOW
        );
    }

    // Cache round trip and the name lookup over the rendered document.
    let cache = CString::new(directory.join("nmp_cache.js").to_str().unwrap()).unwrap();
    let ip = CString::new("192.168.50.20").unwrap();
    let mut name = [0 as c_char; 8];
    // SAFETY: valid strings and buffers.
    unsafe {
        assert_eq!(
            rust_httpd_clientlist_cache_write(
                cache.as_ptr(),
                buffer.as_ptr().cast(),
                length as usize
            ),
            0
        );
        let mut copy = vec![0_u8; buffer.len()];
        let copied =
            rust_httpd_clientlist_cache_read(cache.as_ptr(), copy.as_mut_ptr().cast(), copy.len());
        assert_eq!(copied, length);
        assert_eq!(&copy[..length as usize], &buffer[..length as usize]);
        assert_eq!(
            rust_httpd_clientlist_name_for_ip(
                buffer.as_ptr().cast(),
                length as usize,
                ip.as_ptr(),
                name.as_mut_ptr(),
                name.len()
            ),
            1
        );
        // strlcpy-style truncation keeps the terminator.
        assert_eq!(
            std::ffi::CStr::from_ptr(name.as_ptr()).to_str().unwrap(),
            "Pauls i"
        );
        let empty = b"{\"maclist\":[],\"ClientAPILevel\":\"7\"}";
        assert_eq!(
            rust_httpd_clientlist_cache_write(cache.as_ptr(), empty.as_ptr().cast(), empty.len()),
            CLIENTLIST_CACHE_REJECTED
        );
        std::fs::write(directory.join("nmp_cache.js"), empty).unwrap();
        assert_eq!(
            rust_httpd_clientlist_cache_read(cache.as_ptr(), copy.as_mut_ptr().cast(), copy.len()),
            CLIENTLIST_CACHE_REJECTED
        );
        assert_eq!(
            rust_httpd_clientlist_basic_render(
                &owned.inputs,
                1,
                ptr::null(),
                2,
                buffer.as_mut_ptr().cast(),
                buffer.len()
            ),
            28
        );
        assert_eq!(&buffer[..28], br#"{"wireless":"1", "wire":"1"}"#);
        assert_eq!(
            rust_httpd_clientlist_basic_render(
                &owned.inputs,
                0,
                ptr::null(),
                1,
                buffer.as_mut_ptr().cast(),
                buffer.len()
            ),
            2
        );
        assert_eq!(&buffer[..2], b"[]");
    }
}

#[test]
fn wrong_segment_size_and_missing_segment() {
    let directory = scratch();
    let lock_dir = directory.to_str().unwrap();
    let mut buffer = vec![0_u8; 4096];

    let missing = inputs(private_key(2), "GT-AX11000", lock_dir);
    // SAFETY: valid inputs and buffer.
    assert_eq!(
        unsafe {
            rust_httpd_clientlist_render(&missing.inputs, buffer.as_mut_ptr().cast(), buffer.len())
        },
        CLIENTLIST_NO_SEGMENT
    );

    let key = private_key(3);
    let _segment = Segment::create(key, &vec![0; 1000]);
    let small = inputs(key, "GT-AX11000", lock_dir);
    // SAFETY: valid inputs and buffer.
    assert_eq!(
        unsafe {
            rust_httpd_clientlist_render(&small.inputs, buffer.as_mut_ptr().cast(), buffer.len())
        },
        CLIENTLIST_UNSUPPORTED_LAYOUT
    );
}
