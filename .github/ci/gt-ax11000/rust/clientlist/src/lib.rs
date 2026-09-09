//! GT-AX11000 Web UI client list.
//!
//! Replaces the json-c based client-list readers of `httpd/web.c`
//! (`get_client_detail_info()`, `ej_get_clientlist()`,
//! `get_clientlist_ex()`, `get_client_name()`, `get_sdn_client_num()`,
//! `ej_get_clientlist_from_json_database()`, `ej_get_all_basic_clientlist()`,
//! `get_basic_clientlist_info()` and `search_device_name_in_clientlist()`)
//! with a size- and layout-checked shared-memory snapshot, a typed data model
//! and bounded JSON rendering. `unsafe` is confined to [`shm`] (SysV shared
//! memory and the vendor advisory lock) and [`ffi`] (the C boundary).

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod amas;
pub mod cache;
pub mod ffi;
pub mod json;
pub mod layout;
pub mod model;
pub mod nvram;
pub mod render;
pub mod shm;
pub mod snapshot;

/// `CLIENTAPILEVEL` (web.c:646).
pub const CLIENT_API_LEVEL: &str = "7";
