//! Module registration and lifecycle: `get_module`, MINIT/MSHUTDOWN, the three
//! ini entries, and `phpinfo()`/`php --ri` surfacing. All process-global state
//! lives here. Workers are NTS (single-threaded per process), so the
//! `static mut` globals are never touched concurrently.

use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::mem::size_of;
use std::ptr;

use howdah_core::ffi as core;
use howdah_sys as sys;

use crate::response;
use crate::rfc1867;

/// The prior `php_rfc1867_callback` (e.g. ext/session's upload-progress hook).
pub(crate) type Prior =
    Option<unsafe extern "C" fn(c_uint, *mut c_void, *mut *mut c_void) -> c_int>;

// ---- process-global state (NTS: no concurrent access) -----------------------
pub(crate) static mut CTX: *mut core::howdah_ctx = ptr::null_mut();
pub(crate) static mut PRIOR: Prior = None;
/// Log destination file; `None` => stderr fallback.
pub(crate) static mut LOG_PATH: Option<CString> = None;
static mut MODULE_NUMBER: c_int = 0;
/// For the info table: (mode, config path, log path) as displayed.
static mut DISP_MODE: Option<CString> = None;
static mut DISP_CONFIG: Option<CString> = None;
static mut DISP_LOG: Option<CString> = None;

const SUCCESS: c_int = 0;

// ---- the zend_module_entry --------------------------------------------------

/// A fully-zeroed module entry (all fields are POD: null ptrs / `None` / 0),
/// used as the base before `get_module` fills in the live fields. The layout is
/// identical across the PHP 5/7/8 headers measured, so one literal serves all.
const EMPTY_MODULE: sys::zend_module_entry = sys::zend_module_entry {
    size: 0,
    zend_api: 0,
    zend_debug: 0,
    zts: 0,
    ini_entry: ptr::null(),
    deps: ptr::null(),
    name: ptr::null(),
    functions: ptr::null(),
    module_startup_func: None,
    module_shutdown_func: None,
    request_startup_func: None,
    request_shutdown_func: None,
    info_func: None,
    version: ptr::null(),
    globals_size: 0,
    globals_ptr: ptr::null_mut(),
    globals_ctor: None,
    globals_dtor: None,
    post_deactivate_func: None,
    module_started: 0,
    type_: 0,
    handle: ptr::null_mut(),
    module_number: 0,
    build_id: ptr::null(),
};

static mut MODULE: sys::zend_module_entry = EMPTY_MODULE;

const NAME: &[u8] = b"howdah\0";
const VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();

/// PHP's dynamic loader calls this to obtain the module entry. Called once,
/// before MINIT. We fill the entry (including the per-generation `build_id`,
/// taken from the C header via the howdah-sys shim so the ABI check passes) and
/// return a stable pointer to it.
///
/// # Safety
/// Called by the PHP loader exactly once per process.
#[no_mangle]
pub unsafe extern "C" fn get_module() -> *mut sys::zend_module_entry {
    let m = sys::zend_module_entry {
        size: size_of::<sys::zend_module_entry>() as u16,
        zend_api: sys::ZEND_MODULE_API_NO,
        zend_debug: sys::ZEND_DEBUG as u8,
        zts: sys::USING_ZTS as u8,
        name: NAME.as_ptr() as *const c_char,
        module_startup_func: Some(minit),
        module_shutdown_func: Some(mshutdown),
        info_func: Some(minfo),
        version: VERSION.as_ptr() as *const c_char,
        type_: 1, // MODULE_PERSISTENT
        build_id: sys::howdah_sys_build_id(),
        ..EMPTY_MODULE
    };
    let slot = ptr::addr_of_mut!(MODULE);
    slot.write(m);
    slot
}

// ---- ini entries ------------------------------------------------------------

/// Wrapper so an array of ini defs (which contains raw pointers) can be a
/// `static`. Safe: read-only, single-threaded registration. php5 registers the
/// older runtime `zend_ini_entry`; php7/php8 the `zend_ini_entry_def`.
#[cfg(not(feature = "php5"))]
struct IniDefs([sys::zend_ini_entry_def; 4]);
#[cfg(feature = "php5")]
struct IniDefs([sys::zend_ini_entry; 4]);
unsafe impl Sync for IniDefs {}

#[cfg(not(feature = "php5"))]
const fn def(name: &'static [u8], value: &'static [u8]) -> sys::zend_ini_entry_def {
    sys::zend_ini_entry_def {
        name: name.as_ptr() as *const c_char,
        on_modify: None,
        mh_arg1: ptr::null_mut(),
        mh_arg2: ptr::null_mut(),
        mh_arg3: ptr::null_mut(),
        value: value.as_ptr() as *const c_char,
        displayer: None,
        value_length: (value.len() - 1) as u32, // strlen (drop trailing NUL)
        name_length: (name.len() - 1) as u16,
        modifiable: 7, // ZEND_INI_ALL (SYSTEM|PERDIR|USER)
    }
}

#[cfg(not(feature = "php5"))]
static INI: IniDefs = IniDefs([
    def(b"howdah.mode\0", b"block\0"),
    def(b"howdah.config\0", b"\0"),
    def(b"howdah.log\0", b"\0"),
    // terminating sentinel (name == NULL)
    sys::zend_ini_entry_def {
        name: ptr::null(),
        on_modify: None,
        mh_arg1: ptr::null_mut(),
        mh_arg2: ptr::null_mut(),
        mh_arg3: ptr::null_mut(),
        value: ptr::null(),
        displayer: None,
        value_length: 0,
        name_length: 0,
        modifiable: 0,
    },
]);

// --- php5 uses the older runtime `zend_ini_entry` for registration ----------
#[cfg(feature = "php5")]
const fn def(name: &'static [u8], value: &'static [u8]) -> sys::zend_ini_entry {
    sys::zend_ini_entry {
        module_number: 0,
        modifiable: 7, // ZEND_INI_ALL
        name: name.as_ptr() as *mut c_char,
        name_length: name.len() as _, // php5 hash keys include the NUL
        on_modify: None,
        mh_arg1: ptr::null_mut(),
        mh_arg2: ptr::null_mut(),
        mh_arg3: ptr::null_mut(),
        value: value.as_ptr() as *mut c_char,
        value_length: (value.len() - 1) as _,
        orig_value: ptr::null_mut(),
        orig_value_length: 0,
        orig_modifiable: 0,
        modified: 0,
        displayer: None,
    }
}

#[cfg(feature = "php5")]
static INI: IniDefs = IniDefs([
    def(b"howdah.mode\0", b"block\0"),
    def(b"howdah.config\0", b"\0"),
    def(b"howdah.log\0", b"\0"),
    sys::zend_ini_entry {
        module_number: 0,
        modifiable: 0,
        name: ptr::null_mut(),
        name_length: 0,
        on_modify: None,
        mh_arg1: ptr::null_mut(),
        mh_arg2: ptr::null_mut(),
        mh_arg3: ptr::null_mut(),
        value: ptr::null_mut(),
        value_length: 0,
        orig_value: ptr::null_mut(),
        orig_value_length: 0,
        orig_modifiable: 0,
        modified: 0,
        displayer: None,
    },
]);

#[cfg(feature = "php5")]
unsafe fn register_ini(module_number: c_int) {
    sys::zend_register_ini_entries(INI.0.as_ptr(), module_number);
}

/// Read a registered ini string by name (name includes a trailing NUL).
/// Returns `None` when unset or empty.
unsafe fn ini_string(name: &[u8]) -> Option<String> {
    #[cfg(not(feature = "php5"))]
    let nlen = name.len() - 1; // php7/php8: strlen, no NUL
    #[cfg(feature = "php5")]
    let nlen = name.len(); // php5 hash keys include the NUL
    let p = sys::zend_ini_string(name.as_ptr() as _, nlen as _, 0);
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    (!s.is_empty()).then_some(s)
}

// ---- MINIT / MSHUTDOWN / MINFO ---------------------------------------------

/// Module startup (once per process). Registers ini entries, loads the core
/// config from the ini-configured TOML path, sets the log destination, and
/// chains the multipart callback. Never fails open-endedly: a bad/missing
/// config yields the core's safe defaults; nothing here may take PHP down.
///
/// # Safety
/// Called by PHP once at module startup.
unsafe extern "C" fn minit(_type: c_int, module_number: c_int) -> c_int {
    MODULE_NUMBER = module_number;
    register_ini(module_number);

    // Load core config from howdah.config (a TOML path). Missing/unreadable =>
    // the core falls back to safe defaults (block mode, critical limits on).
    let cfg_path = ini_string(b"howdah.config\0");
    let ctx = match cfg_path.as_deref().and_then(read_file) {
        Some(bytes) => core::howdah_init(bytes.as_ptr() as *const c_char, bytes.len()),
        None => core::howdah_init(ptr::null(), 0),
    };
    CTX = ctx;

    // Log destination.
    LOG_PATH = ini_string(b"howdah.log\0").map(|p| CString::new(p).unwrap_or_default());

    // Display strings for `php --ri howdah` / phpinfo().
    DISP_MODE = Some(cstring(ini_string(b"howdah.mode\0").as_deref().unwrap_or("block")));
    DISP_CONFIG = Some(cstring(cfg_path.as_deref().unwrap_or("(none; safe defaults)")));
    DISP_LOG = Some(cstring(
        ini_string(b"howdah.log\0").as_deref().unwrap_or("(stderr)"),
    ));

    // Chain the multipart callback: save whatever is installed (e.g. session
    // upload-progress) and install ours above it.
    PRIOR = ptr::addr_of!(sys::php_rfc1867_callback).read();
    let slot = ptr::addr_of_mut!(sys::php_rfc1867_callback);
    slot.write(Some(rfc1867::callback));

    SUCCESS
}

#[cfg(not(feature = "php5"))]
unsafe fn register_ini(module_number: c_int) {
    sys::zend_register_ini_entries(INI.0.as_ptr(), module_number);
}

/// Module shutdown: restore the prior callback, release the core context, and
/// unregister ini entries.
///
/// # Safety
/// Called by PHP once at module shutdown.
unsafe extern "C" fn mshutdown(_type: c_int, _module_number: c_int) -> c_int {
    let slot = ptr::addr_of_mut!(sys::php_rfc1867_callback);
    slot.write(PRIOR);
    PRIOR = None;
    core::howdah_free(CTX);
    CTX = ptr::null_mut();
    sys::zend_unregister_ini_entries(MODULE_NUMBER);
    SUCCESS
}

/// phpinfo() / `php --ri howdah` table.
///
/// # Safety
/// Called by PHP with the module entry.
unsafe extern "C" fn minfo(_module: *mut sys::zend_module_entry) {
    sys::php_info_print_table_start();
    row(b"Howdah\0", b"enabled\0");
    row(b"Version\0", VERSION);
    if let Some(m) = (*ptr::addr_of!(DISP_MODE)).as_ref() {
        row(b"Mode\0", m.as_bytes_with_nul());
    }
    if let Some(c) = (*ptr::addr_of!(DISP_CONFIG)).as_ref() {
        row(b"Rules file (howdah.config)\0", c.as_bytes_with_nul());
    }
    if let Some(l) = (*ptr::addr_of!(DISP_LOG)).as_ref() {
        row(b"Log (howdah.log)\0", l.as_bytes_with_nul());
    }
    row(
        b"Panic guard (catch_unwind active)\0",
        if crate::panic_unwinds() { b"yes\0" } else { b"NO - UNSAFE BUILD\0" },
    );
    sys::php_info_print_table_end();
}

unsafe fn row(k: &[u8], v: &[u8]) {
    sys::php_info_print_table_row(2, k.as_ptr() as *const c_char, v.as_ptr() as *const c_char);
}

// ---- helpers ----------------------------------------------------------------

fn cstring(s: &str) -> CString {
    CString::new(s).unwrap_or_default()
}

/// Read a whole file; `None` (with a loud stderr note) on any error, so a
/// missing/unreadable config never takes PHP down.
fn read_file(path: &str) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(b) => Some(b),
        Err(e) => {
            response::loud_error(&format!("cannot read howdah.config '{path}': {e}"));
            None
        }
    }
}
