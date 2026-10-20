fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    #[cfg(windows)]
    tauri_winres::WindowsResource::new()
        .set_icon("assets/icon.ico")
        .set("ProductName", "URA")
        .set("FileDescription", "Ultimate Reverse Engineer")
        .set("OriginalFilename", "ura-native.exe")
        .compile()
        .expect("compile URA Windows icon and version resources");
}
