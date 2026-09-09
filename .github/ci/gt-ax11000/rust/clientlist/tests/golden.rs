//! Golden documents derived by hand from `httpd/web.c` at `6be5bc84b50`
//! (vendor line numbers) as compiled for the GT-AX11000 overlay
//! (`RTCONFIG_AMAS=y`, `RTCONFIG_IPV6=y`, no PERMISSION_MANAGEMENT,
//! MULTILAN_CFG, MLO, STA_AP_BAND_BIND or PC_SCHED_V3).

use clientlist::amas::parse_re_client_details;
use clientlist::layout::{Layout, FLAG_ASUS, FLAG_EXIST, FLAG_HTTP};
use clientlist::model::{BuildInputs, ClientList};
use clientlist::nvram::{KeyedList, LocalTime, MultifilterInputs};
use clientlist::render::{self, DatabaseInputs, MAX_OUTPUT};
use clientlist::snapshot::builder::SegmentBuilder;
use clientlist::snapshot::Snapshot;

const WEDNESDAY_NOON: LocalTime = LocalTime {
    weekday: 3,
    hour: 12,
};

fn never_re(_: &str) -> bool {
    false
}

fn inputs<'a>(
    amas_support: bool,
    re_details: &'a KeyedList<clientlist::amas::ReDetail>,
    is_re_node: &'a dyn Fn(&str) -> bool,
) -> BuildInputs<'a> {
    BuildInputs {
        lan_ipaddr: "192.168.50.1",
        login_ip_str: "192.168.50.20",
        rog_clientlist: "<AA:BB:CC:DD:EE:03",
        custom_clientlist: "<Pauls iPhone>AA:BB:CC:DD:EE:02>0>5>cb>1",
        qos_rulelist: "<>AA:BB:CC:DD:EE:02>>>>2",
        wtf_rulelist: "<1>AA:BB:CC:DD:EE:02>>>",
        multifilter: MultifilterInputs {
            all: 1,
            mac: "AA:BB:CC:DD:EE:02>AA:BB:CC:DD:EE:03",
            enable: "1>2",
            daytime: "T<330024>T<x",
        },
        amas_support,
        now: WEDNESDAY_NOON,
        re_details,
        is_re_node,
    }
}

/// Three-client legacy segment: gateway, logged-in phone with every NVRAM
/// override, offline ROG console with an unterminated `ipMethod`.
fn legacy_segment() -> Vec<u8> {
    let mut builder = SegmentBuilder::new(Layout::Legacy);
    builder
        .count(3)
        .ip(0, [192, 168, 50, 1])
        .mac(0, [0x04, 0xd4, 0xc4, 0xaa, 0xbb, 0x01])
        .device_name(0, b"GT-AX11000")
        .vendor_name(0, b"ASUSTek COMPUTER INC.")
        .online(0, 1)
        .client_type(0, 9)
        .ip_method(0, b"Manual")
        .device_flag(0, (1 << FLAG_ASUS) | (1 << FLAG_HTTP))
        .ip(1, [192, 168, 50, 20])
        .mac(1, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02])
        .user_define(1, b"Paul's Phone!")
        .device_name(1, b"ignored")
        .vendor_name(1, b"Apple, Inc.")
        .apple_model(1, b"iPhone")
        .online(1, 1)
        .client_type(1, 2)
        .ip_method(1, b"DHCP")
        .wireless(1, 2)
        .ssid(1, b"Home5G")
        .txrate(1, b"866.7")
        .rxrate(1, b"1200.9")
        .rssi(1, -47)
        .conn_time(1, b"01:02:03")
        .ip(2, [192, 168, 50, 30])
        .mac(2, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03])
        .device_name(2, b"Xbox")
        .vendor_name(2, b"Microsoft")
        .online(2, 0)
        .client_type(2, 1)
        .ip_method(2, b"OffLine")
        .device_flag(2, 1 << FLAG_EXIST)
        .wireless(2, 1);
    builder.build()
}

const GATEWAY: &str = r#"{"type":"9","defaultType":"9","name":"GT-AX11000","nickName":"","ip":"192.168.50.1","ip6":"","ip6_prefix":"","mac":"04:D4:C4:AA:BB:01","from":"networkmapd","macRepeat":"0","isGateway":"1","isASUS":"1","isWebServer":"1","isPrinter":"0","isITunes":"0","isAiBoard":"0","dpiType":"","dpiDevice":"","vendor":"ASUSTek COMPUTER INC.","isWL":"0","isGN":"","isOnline":"1","ssid":"","isLogin":"0","opMode":"0","rssi":"0","curTx":"","curRx":"","totalTx":"","totalRx":"","wlConnectTime":"","wlAuth":"","ipMethod":"Manual","ROG":"0","group":"","callback":"","keeparp":"","qosLevel":"","wtfast":"0","internetMode":"allow","internetState":"1","amesh_bind_mac":"","amesh_bind_band":"0"}"#;

// web.c:10469-10485 sanitises "Paul's Phone!" to "Paul s Phone ";
// 10742-10760 custom type 5 replaces type but not defaultType; 10762-10786
// qosLevel/wtfast; 10788-10800 MULTIFILTER "time" with schedule 330024 on
// Wednesday noon gives the JSON integer 1.
const PHONE: &str = r#"{"type":"5","defaultType":"2","name":"Paul s Phone ","nickName":"Pauls iPhone","ip":"192.168.50.20","ip6":"","ip6_prefix":"","mac":"AA:BB:CC:DD:EE:02","from":"networkmapd","macRepeat":"0","isGateway":"0","isASUS":"0","isWebServer":"0","isPrinter":"0","isITunes":"0","isAiBoard":"0","dpiType":"","dpiDevice":"iPhone","vendor":"Apple, Inc.","isWL":"2","isGN":"","isOnline":"1","ssid":"Home5G","isLogin":"1","opMode":"0","rssi":"-47","curTx":"866.7","curRx":"1200.9","totalTx":"","totalRx":"","wlConnectTime":"01:02:03","wlAuth":"","ipMethod":"DHCP","ROG":"0","group":"","callback":"cb","keeparp":"1","qosLevel":"2","wtfast":"1","internetMode":"time","internetState":1,"amesh_bind_mac":"","amesh_bind_band":"0"}"#;

// web.c:10728-10736 ROG forces type/defaultType "36"; FLAG_EXIST is not a
// reported flag; "OffLine" fills all seven ipMethod bytes; MULTIFILTER enable
// 2 is "block"/0; offline clients are not appended to maclist (10743-10758).
const CONSOLE: &str = r#"{"type":"36","defaultType":"36","name":"Xbox","nickName":"","ip":"192.168.50.30","ip6":"","ip6_prefix":"","mac":"AA:BB:CC:DD:EE:03","from":"networkmapd","macRepeat":"0","isGateway":"0","isASUS":"0","isWebServer":"0","isPrinter":"0","isITunes":"0","isAiBoard":"0","dpiType":"","dpiDevice":"","vendor":"Microsoft","isWL":"1","isGN":"","isOnline":"0","ssid":"","isLogin":"0","opMode":"0","rssi":"0","curTx":"","curRx":"","totalTx":"","totalRx":"","wlConnectTime":"","wlAuth":"","ipMethod":"OffLine","ROG":"1","group":"","callback":"","keeparp":"","qosLevel":"","wtfast":"0","internetMode":"block","internetState":0,"amesh_bind_mac":"","amesh_bind_band":"0"}"#;

fn legacy_list() -> ClientList {
    let snapshot = Snapshot::parse("GT-AX11000", &legacy_segment()).unwrap();
    let details = KeyedList::new();
    ClientList::build(&snapshot, &inputs(true, &details, &never_re))
}

#[test]
fn ej_get_clientlist_legacy_layout_web_c_10793_10879() {
    let expected = format!(
        r#"{{"04:D4:C4:AA:BB:01":{GATEWAY},"AA:BB:CC:DD:EE:02":{PHONE},"AA:BB:CC:DD:EE:03":{CONSOLE},"maclist":["04:D4:C4:AA:BB:01","AA:BB:CC:DD:EE:02"],"ClientAPILevel":"7"}}"#
    );
    assert_eq!(
        render::render_live(&legacy_list(), MAX_OUTPUT).unwrap(),
        expected
    );
}

#[test]
fn duplicate_mac_without_amas_support_web_c_10743_10758_and_9291_9302() {
    // Without is_amas_support() every client is reported online and appended
    // to maclist; the second row with the same MAC replaces the first entry
    // in place and reports macRepeat "1".
    let mut builder = SegmentBuilder::new(Layout::Legacy);
    builder
        .count(2)
        .ip(0, [192, 168, 50, 10])
        .mac(0, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x10])
        .device_name(0, b"One")
        .online(0, 0)
        .ip(1, [192, 168, 50, 11])
        .mac(1, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x10])
        .device_name(1, b"Two")
        .online(1, 1)
        .wireless(1, 1);
    let snapshot = Snapshot::parse("GT-AX11000", &builder.build()).unwrap();
    let details = KeyedList::new();
    let mut plain = inputs(false, &details, &never_re);
    plain.rog_clientlist = "";
    plain.custom_clientlist = "";
    plain.qos_rulelist = "";
    plain.wtf_rulelist = "";
    plain.multifilter = MultifilterInputs::default();
    let list = ClientList::build(&snapshot, &plain);
    let expected = r#"{"AA:BB:CC:DD:EE:10":{"type":"0","defaultType":"0","name":"Two","nickName":"","ip":"192.168.50.11","ip6":"","ip6_prefix":"","mac":"AA:BB:CC:DD:EE:10","from":"networkmapd","macRepeat":"1","isGateway":"0","isASUS":"0","isWebServer":"0","isPrinter":"0","isITunes":"0","isAiBoard":"0","dpiType":"","dpiDevice":"","vendor":"","isWL":"1","isGN":"","isOnline":"1","ssid":"","isLogin":"0","opMode":"0","rssi":"0","curTx":"","curRx":"","totalTx":"","totalRx":"","wlConnectTime":"","wlAuth":"","ipMethod":"","ROG":"0","group":"","callback":"","keeparp":"","qosLevel":"","wtfast":"0","internetMode":"allow","internetState":"1"},"maclist":["AA:BB:CC:DD:EE:10","AA:BB:CC:DD:EE:10"],"ClientAPILevel":"7"}"#;
    assert_eq!(render::render_live(&list, MAX_OUTPUT).unwrap(), expected);
}

#[test]
fn public_layout_amas_fields_and_re_rssi_override_web_c_10700_10731() {
    let mut builder = SegmentBuilder::new(Layout::Public);
    builder
        .count(3)
        .ip(0, [192, 168, 50, 39])
        .mac(0, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf1])
        .device_name(0, b"RE node")
        .online(0, 1)
        .ip(1, [192, 168, 50, 40])
        .mac(1, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x21])
        .device_name(1, b"Tablet")
        .online(1, 1)
        .wireless(1, 2)
        .rssi(1, -60)
        .pap_mac(1, b"AA:BB:CC:DD:EE:F1")
        .is_re(1, b"0")
        .guest_network(1, b"1")
        .ip6_addr(1, b"fe80::1")
        .ip6_prefix(1, b"2001:db8::/64")
        .wireless_auth(1, b"WPA2")
        .ip(2, [192, 168, 50, 41])
        .mac(2, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x22])
        .device_name(2, b"Node")
        .online(2, 1)
        .is_re(2, b"1");
    let snapshot = Snapshot::parse("RT-AX88U", &builder.build()).unwrap();
    assert_eq!(snapshot.layout, Layout::Public);
    let details = parse_re_client_details(
        br#"{"AA:BB:CC:DD:EE:F1":{"5G":{"AA:BB:CC:DD:EE:21":{"rssi":-52}}}}"#,
    );
    let is_re_node = |mac: &str| mac == "AA:BB:CC:DD:EE:F1";
    let mut plain = inputs(true, &details, &is_re_node);
    plain.rog_clientlist = "";
    plain.custom_clientlist = "";
    plain.qos_rulelist = "";
    plain.wtf_rulelist = "";
    plain.multifilter = MultifilterInputs::default();
    let list = ClientList::build(&snapshot, &plain);
    let tablet = r#"{"type":"0","defaultType":"0","name":"Tablet","nickName":"","ip":"192.168.50.40","ip6":"fe80::1","ip6_prefix":"2001:db8::/64","mac":"AA:BB:CC:DD:EE:21","from":"networkmapd","macRepeat":"0","isGateway":"0","isASUS":"0","isWebServer":"0","isPrinter":"0","isITunes":"0","isAiBoard":"0","dpiType":"","dpiDevice":"","vendor":"","isWL":"2","isGN":"1","isOnline":"1","ssid":"","isLogin":"0","opMode":"0","rssi":"-52","curTx":"","curRx":"","totalTx":"","totalRx":"","wlConnectTime":"","wlAuth":"WPA2","ipMethod":"","ROG":"0","group":"","callback":"","keeparp":"","qosLevel":"","wtfast":"0","internetMode":"allow","internetState":"1","amesh_isReClient":"1","amesh_papMac":"AA:BB:CC:DD:EE:F1","amesh_bind_mac":"","amesh_bind_band":"0"}"#;
    let node = r#"{"type":"0","defaultType":"0","name":"Node","nickName":"","ip":"192.168.50.41","ip6":"","ip6_prefix":"","mac":"AA:BB:CC:DD:EE:22","from":"networkmapd","macRepeat":"0","isGateway":"0","isASUS":"0","isWebServer":"0","isPrinter":"0","isITunes":"0","isAiBoard":"0","dpiType":"","dpiDevice":"","vendor":"","isWL":"0","isGN":"","isOnline":"1","ssid":"","isLogin":"0","opMode":"0","rssi":"0","curTx":"","curRx":"","totalTx":"","totalRx":"","wlConnectTime":"","wlAuth":"","ipMethod":"","ROG":"0","group":"","callback":"","keeparp":"","qosLevel":"","wtfast":"0","internetMode":"allow","internetState":"1","amesh_isRe":"1","amesh_bind_mac":"","amesh_bind_band":"0"}"#;
    let expected = format!(
        r#"{{"AA:BB:CC:DD:EE:21":{tablet},"AA:BB:CC:DD:EE:22":{node},"maclist":["AA:BB:CC:DD:EE:21","AA:BB:CC:DD:EE:22"],"ClientAPILevel":"7"}}"#
    );
    assert_eq!(render::render_live(&list, MAX_OUTPUT).unwrap(), expected);
}

#[test]
fn full_table_of_255_clients_with_maximal_fields_fits_the_bound() {
    let mut builder = SegmentBuilder::new(Layout::Legacy);
    builder.count(300);
    for index in 0..255 {
        builder
            .ip(index, [10, 0, (index / 256) as u8, index as u8])
            .mac(index, [0x02, 0, 0, 0, (index >> 8) as u8, index as u8])
            .device_name(index, &[b'"'; 32])
            .vendor_name(index, &[0x01; 128])
            .apple_model(index, &[b'\\'; 16])
            .ssid(index, &[0x1f; 32])
            .txrate(index, &[b'9'; 7])
            .rxrate(index, &[b'9'; 10])
            .conn_time(index, &[b'1'; 12])
            .ip_method(index, &[0x7f; 7])
            .online(index, 1)
            .wireless(index, 3);
    }
    let snapshot = Snapshot::parse("GT-AX11000", &builder.build()).unwrap();
    assert_eq!(snapshot.clients.len(), 255);
    let details = KeyedList::new();
    let list = ClientList::build(&snapshot, &inputs(true, &details, &never_re));
    let text = render::render_live(&list, MAX_OUTPUT).unwrap();
    assert!(text.len() < MAX_OUTPUT);
    assert_eq!(list.maclist.len(), 255);
    assert!(render::render_live(&list, 1024).is_err());
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["maclist"].as_array().unwrap().len(), 255);
    assert_eq!(
        parsed["02:00:00:00:00:FE"]["name"],
        "                               "
    );
    assert_eq!(
        parsed["02:00:00:00:00:FE"]["vendor"]
            .as_str()
            .unwrap()
            .len(),
        128
    );
}

const DATABASE: &[u8] = br#"{"AA:BB:CC:DD:EE:01":{"mac":"AA:BB:CC:DD:EE:01","ip":"192.168.50.20","name":"Phone","vendor":"Apple","type":2,"online":1,"is_wireless":1,"os_type":0,"sdn_idx":0,"conn_time":"","from":""},"AA:BB:CC:DD:EE:F1":{"name":"RE","type":9},"AA:BB:CC:DD:EE:03":{"name":"Xbox","type":1,"online":0}}"#;
const DATABASE_CUSTOM: &str =
    "<Pauls iPhone>AA:BB:CC:DD:EE:01>0>5>0>0<Printer>AA:BB:CC:DD:EE:09>0>0>0>0";

#[test]
fn ej_get_clientlist_from_json_database_web_c_1954_2119() {
    let database = render::parse_database(DATABASE).unwrap();
    let is_re_node = |mac: &str| mac == "AA:BB:CC:DD:EE:F1";
    let text = render::render_database(
        Some(database),
        &DatabaseInputs {
            rog_clientlist: "<AA:BB:CC:DD:EE:03",
            custom_clientlist: DATABASE_CUSTOM,
            amas_node_types: "04:D4:C4:AA:BB:01>CAP<AA:BB:CC:DD:EE:01>RE",
            is_re_node: &is_re_node,
        },
        MAX_OUTPUT,
    )
    .unwrap();
    // Existing keys keep their position when replaced (json-c 0.12.1
    // json_object_object_add), new keys are appended in C call order; the RE
    // node entry is skipped and left untouched; the never-online custom entry
    // is appended last (web.c:2078-2101).
    let expected = r#"{"AA:BB:CC:DD:EE:01":{"mac":"AA:BB:CC:DD:EE:01","ip":"192.168.50.20","name":"Phone","vendor":"Apple","type":"5","online":"1","is_wireless":1,"os_type":0,"sdn_idx":0,"conn_time":"","from":"nmpClient","nickName":"Pauls iPhone","defaultType":"2","ROG":"0","amesh_isRe":"1","amesh_bind_mac":"","amesh_bind_band":"0"},"AA:BB:CC:DD:EE:F1":{"name":"RE","type":9},"AA:BB:CC:DD:EE:03":{"name":"Xbox","type":"36","online":"0","nickName":"","defaultType":"36","from":"nmpClient","ROG":"1","amesh_bind_mac":"","amesh_bind_band":"0"},"AA:BB:CC:DD:EE:09":{"type":"0","mac":"AA:BB:CC:DD:EE:09","name":"AA:BB:CC:DD:EE:09","vendor":"","nickName":"Printer","defaultType":"0","from":"customList"},"maclist":["AA:BB:CC:DD:EE:01","AA:BB:CC:DD:EE:03","AA:BB:CC:DD:EE:09"],"ClientAPILevel":"7"}"#;
    assert_eq!(text, expected);

    // web.c:1985-1993: no database yields the fake document.
    let empty = render::render_database(
        None,
        &DatabaseInputs {
            rog_clientlist: "",
            custom_clientlist: DATABASE_CUSTOM,
            amas_node_types: "",
            is_re_node: &never_re,
        },
        MAX_OUTPUT,
    )
    .unwrap();
    assert_eq!(empty, r#"{"maclist":[],"ClientAPILevel":"7"}"#);
    assert!(render::parse_database(b"[1,2]").is_none());
    assert!(render::parse_database(b"").is_none());
}

#[test]
fn ej_get_all_basic_clientlist_web_c_2121_2161() {
    let database = render::parse_database(DATABASE).unwrap();
    assert_eq!(
        render::render_all_basic(&database, DATABASE_CUSTOM, MAX_OUTPUT).unwrap(),
        r#"[["AA:BB:CC:DD:EE:01","Pauls iPhone"],["AA:BB:CC:DD:EE:F1","RE"],["AA:BB:CC:DD:EE:03","Xbox"]]"#
    );
    let nameless =
        render::parse_database(br#"{"AA:BB:CC:DD:EE:05":{"ip":"1.2.3.4"},"AA:BB:CC:DD:EE:06":7}"#)
            .unwrap();
    assert_eq!(
        render::render_all_basic(&nameless, "", MAX_OUTPUT).unwrap(),
        r#"[["AA:BB:CC:DD:EE:05",null],["AA:BB:CC:DD:EE:06",null]]"#
    );
}

#[test]
fn get_basic_clientlist_info_web_c_2265_2360() {
    let list = legacy_list();
    let database = render::parse_database(DATABASE).unwrap();
    assert_eq!(
        render::render_basic(Some(&list), None, 0, MAX_OUTPUT).unwrap(),
        r#"[["04:D4:C4:AA:BB:01","GT-AX11000"]]"#
    );
    assert_eq!(
        render::render_basic(Some(&list), None, 1, MAX_OUTPUT).unwrap(),
        r#"[["AA:BB:CC:DD:EE:02","Paul s Phone "],["AA:BB:CC:DD:EE:03","Xbox"]]"#
    );
    assert_eq!(
        render::render_basic(Some(&list), None, 2, MAX_OUTPUT).unwrap(),
        r#"{"wireless":"2", "wire":"1"}"#
    );
    // opt 3: DB records not currently seen as wireless clients.
    assert_eq!(
        render::render_basic(Some(&list), Some(&database), 3, MAX_OUTPUT).unwrap(),
        r#"[["AA:BB:CC:DD:EE:01","Phone"],["AA:BB:CC:DD:EE:F1","RE"]]"#
    );
    // networkmap not running: empty views.
    assert_eq!(
        render::render_basic(None, None, 0, MAX_OUTPUT).unwrap(),
        "[]"
    );
    assert_eq!(
        render::render_basic(None, None, 2, MAX_OUTPUT).unwrap(),
        r#"{"wireless":"0", "wire":"0"}"#
    );
    assert_eq!(
        render::render_basic(None, Some(&database), 3, MAX_OUTPUT).unwrap(),
        "[]"
    );
    assert_eq!(
        render::render_basic(Some(&list), None, 3, MAX_OUTPUT).unwrap(),
        "[]"
    );
}

#[test]
fn get_client_name_over_the_rendered_document_web_c_43306_43339() {
    let text = render::render_live(&legacy_list(), MAX_OUTPUT).unwrap();
    assert_eq!(
        render::name_for_ip(text.as_bytes(), "192.168.50.20").as_deref(),
        Some("Pauls iPhone")
    );
    assert_eq!(
        render::name_for_ip(text.as_bytes(), "192.168.50.30").as_deref(),
        Some("Xbox")
    );
    assert_eq!(render::name_for_ip(text.as_bytes(), "192.168.50.99"), None);
}
