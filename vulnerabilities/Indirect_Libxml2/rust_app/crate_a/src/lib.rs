pub fn entry(xml_buf: *const i8, base_url: *const i8, out_buf: *mut i8, out_len: i32) -> i32 {
    crate_b::call_c(xml_buf, base_url, out_buf, out_len)
}
