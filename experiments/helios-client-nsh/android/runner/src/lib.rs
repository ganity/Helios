nsh::ui_sets!(vec![nsh_base::registry(), helios::registry()]);
nsh::main!(nsh_core::element::Root::of::<helios::App>()
    .app_id("com.helios.mobile")
    .appearance(nsh_core::element::Appearance::Dark));
