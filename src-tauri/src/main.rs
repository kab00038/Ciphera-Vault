// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let arguments: Vec<_> = std::env::args().collect();
    if arguments
        .iter()
        .any(|argument| argument == "--install-browser")
    {
        if let Err(error) = app_lib::install_browser_host_from_cli() {
            eprintln!("{error}");
            std::process::exit(1);
        }
    } else if arguments
        .iter()
        .any(|argument| argument == "--native-host" || argument.starts_with("chrome-extension://"))
    {
        app_lib::run_native_host();
    } else {
        app_lib::run();
    }
}
