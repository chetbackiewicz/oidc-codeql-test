package com.cback.sharedutils;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

/**
 * XmlHelper — INTENTIONALLY VULNERABLE for CodeQL testing.
 *
 * Parses XML with external entity processing enabled, creating an
 * XML External Entity (XXE) injection vulnerability.
 *
 * CWE-611: Improper Restriction of XML External Entity Reference
 */
public class XmlHelper {

    /**
     * Parses the given XML string into a DOM Document.
     *
     * VULNERABLE: The DocumentBuilderFactory is not configured to disable
     * external entities or DTDs, allowing XXE attacks.
     *
     * @param xml the XML content to parse (may come from untrusted input)
     * @return the parsed Document
     * @throws Exception if parsing fails
     */
    public static Document parse(String xml) throws Exception {
        // VULNERABLE: no protection against XXE
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Intentionally NOT setting:
        // factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",
        // true);
        // factory.setFeature("http://xml.org/sax/features/external-general-entities",
        // false);
        // factory.setFeature("http://xml.org/sax/features/external-parameter-entities",
        // false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }
}
