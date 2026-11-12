//! UIKit NSH view owned by the containing app, never linked into Packet Tunnel.
#![cfg(target_os = "ios")]
use nsh_platform_ios::{AppView, SurfaceOptions};
use objc2::MainThreadMarker;
use objc2_core_foundation::{CGPoint, CGRect, CGSize};
use std::{
    ffi::{CStr, c_char, c_void},
    path::PathBuf,
};

/// # Safety
/// Called on the UIKit main thread. `directory` is a live NUL-terminated UTF-8 path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn helios_ui_create(
    directory: *const c_char,
    width: f64,
    height: f64,
) -> *mut c_void {
    if directory.is_null() {
        return std::ptr::null_mut();
    }
    let Some(main) = MainThreadMarker::new() else {
        return std::ptr::null_mut();
    };
    // SAFETY: Swift keeps the directory string alive during this call.
    let Ok(directory) = unsafe { CStr::from_ptr(directory) }.to_str() else {
        return std::ptr::null_mut();
    };
    nsh_platform_ios::set_ui_sets(vec![nsh_base::registry(), helios::registry()]);
    let mut options = SurfaceOptions::default();
    options.data_dir = Some(PathBuf::from(directory));
    let app = AppView::new(
        main,
        CGRect::new(CGPoint::new(0.0, 0.0), CGSize::new(width, height)),
        options,
    );
    app.run(
        nsh_core::element::Root::of::<helios::App>()
            .app_id("com.helios.mobile")
            .appearance(nsh_core::element::Appearance::Dark),
    );
    Box::into_raw(Box::new(app)).cast()
}

/// # Safety
/// `app` comes from create, is still alive, and is used only on the main thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn helios_ui_view(app: *mut c_void) -> *mut c_void {
    if app.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the host owns this live AppView.
    std::ptr::from_ref(unsafe { &*app.cast::<AppView>() }.view())
        .cast_mut()
        .cast()
}

/// # Safety
/// Called once on the main thread with a live pointer returned by create.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn helios_ui_destroy(app: *mut c_void) {
    if !app.is_null() {
        // SAFETY: this call transfers the one Box allocation back to Rust.
        let app = unsafe { Box::from_raw(app.cast::<AppView>()) };
        app.view().removeFromSuperview();
    }
}
