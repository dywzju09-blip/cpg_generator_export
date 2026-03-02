#include <string.h>

int component_b_process(const char *xml_buf,
                        const char *base_url,
                        char *out_buf,
                        int out_len);

/*
 * Component A: thin wrapper around component B.
 */
int component_a_entry(const char *xml_buf,
                      const char *base_url,
                      char *out_buf,
                      int out_len) {
    return component_b_process(xml_buf, base_url, out_buf, out_len);
}
