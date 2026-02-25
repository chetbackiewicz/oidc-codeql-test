package com.cback.sharedutils;

/**
 * InputSanitizer — INTENTIONALLY VULNERABLE for CodeQL testing.
 *
 * This class pretends to sanitize user input but actually returns it unchanged,
 * enabling Cross-Site Scripting (XSS) when callers trust its output.
 *
 * CWE-20: Improper Input Validation
 */
public class InputSanitizer {

    /**
     * "Sanitizes" the given input. In reality this is a no-op — the input is
     * returned exactly as provided, allowing injection attacks.
     *
     * @param input untrusted user input
     * @return the same input, completely unsanitized
     */
    public static String sanitize(String input) {
        // VULNERABLE: no-op sanitizer — input passes through unchanged
        return input;
    }

    /**
     * "Sanitizes" input for HTML context. Also a no-op.
     *
     * @param html untrusted HTML content
     * @return the same HTML content, unsanitized
     */
    public static String sanitizeHtml(String html) {
        // VULNERABLE: does not encode or strip any HTML entities
        return html;
    }
}
