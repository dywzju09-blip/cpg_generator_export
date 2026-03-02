#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>

/*
 * Component B: parses XML using libxml2 (vulnerable before 2.9.4 to XXE).
 * Returns 0 on success, -1 on error.
 */
int component_b_process(const char *xml_buf,
                        const char *base_url,
                        char *out_buf,
                        int out_len) {
    if (!xml_buf || !out_buf || out_len <= 0) {
        return -1;
    }

    int options = XML_PARSE_NOENT | XML_PARSE_DTDLOAD;
    xmlDocPtr doc = xmlReadMemory(xml_buf, (int)strlen(xml_buf), base_url, NULL, options);
    if (!doc) {
        return -1;
    }

    xmlNode *root = xmlDocGetRootElement(doc);
    if (!root) {
        xmlFreeDoc(doc);
        return -1;
    }

    xmlChar *content = xmlNodeGetContent(root);
    if (!content) {
        xmlFreeDoc(doc);
        return -1;
    }

    // Copy content to out_buf (truncate if necessary)
    int to_copy = (int)strlen((const char *)content);
    if (to_copy >= out_len) {
        to_copy = out_len - 1;
    }
    memcpy(out_buf, content, to_copy);
    out_buf[to_copy] = '\0';

    xmlFree(content);
    xmlFreeDoc(doc);
    return 0;
}
