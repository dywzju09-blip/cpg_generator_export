extern "C" {
    fn component_a_entry(xml_buf: *const i8, base_url: *const i8, out_buf: *mut i8, out_len: i32) -> i32;
}

pub fn call_c(xml_buf: *const i8, base_url: *const i8, out_buf: *mut i8, out_len: i32) -> i32 {
    unsafe { component_a_entry(xml_buf, base_url, out_buf, out_len) }
}
