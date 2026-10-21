fn main() {
    let icon =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../ura-native/assets/icon.ico");
    println!("cargo:rerun-if-changed={}", icon.display());
    #[cfg(windows)]
    tauri_winres::WindowsResource::new()
        .set_icon(icon.to_str().expect("icon path is valid UTF-8"))
        .set("ProductName", "URA")
        .set("FileDescription", "Ultimate Reverse Engineer MCP server")
        .set("OriginalFilename", "ura-mcp.exe")
        .compile()
        .expect("compile URA Windows icon and version resources");
}
