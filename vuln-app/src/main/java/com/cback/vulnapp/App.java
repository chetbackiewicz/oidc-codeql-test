package com.cback.vulnapp;

import com.cback.sharedutils.XmlHelper;
import org.w3c.dom.Document;

/**
 * App — Entry point for the vulnerable application.
 *
 * INTENTIONALLY VULNERABLE for CodeQL testing.
 * Passes user-supplied XML directly to XmlHelper.parse(), which is
 * vulnerable to XML External Entity (XXE) injection (CWE-611).
 */
public class App {

    /**
     * Processes user-supplied XML content using the shared-utils XmlHelper.
     *
     * VULNERABLE: User input flows directly into an XXE-vulnerable parser.
     *
     * @param userXml XML string from an untrusted source
     * @return the root element tag name, or an error message
     */
    public String processXml(String userXml) {
        try {
            // VULNERABLE: passes untrusted XML to XXE-prone parser
            Document doc = XmlHelper.parse(userXml);
            return "Parsed root element: " + doc.getDocumentElement().getTagName();
        } catch (Exception e) {
            return "Error parsing XML: " + e.getMessage();
        }
    }

    public static void main(String[] args) {
        App app = new App();

        if (args.length > 0) {
            // VULNERABLE: command-line argument treated as trusted XML
            String result = app.processXml(args[0]);
            System.out.println(result);
        } else {
            System.out.println("Usage: java App <xml-string>");
        }
    }
}
