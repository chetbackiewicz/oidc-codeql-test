package com.cback.vulnapp;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * FileService — INTENTIONALLY VULNERABLE for CodeQL testing.
 *
 * Allows arbitrary file reads via path traversal (CWE-22).
 * A user-controlled filename is passed directly to File() without
 * validation or canonicalization.
 */
public class FileService {

    private static final String BASE_DIR = "/var/app/uploads";

    /**
     * Reads a file from the uploads directory.
     *
     * VULNERABLE: The filename parameter is user-controlled and is not
     * validated or canonicalized. An attacker can use "../" sequences
     * to escape the base directory and read arbitrary files.
     *
     * @param filename user-supplied filename (e.g., "../../etc/passwd")
     * @return the file contents as a string
     * @throws IOException if the file cannot be read
     */
    public String readFile(String filename) throws IOException {
        // VULNERABLE: no path validation — allows traversal via "../"
        File file = new File(BASE_DIR, filename);
        return new String(Files.readAllBytes(file.toPath()));
    }

    /**
     * Checks whether a file exists in the uploads directory.
     *
     * VULNERABLE: Same path traversal issue.
     *
     * @param filename user-supplied filename
     * @return true if the file exists
     */
    public boolean fileExists(String filename) {
        // VULNERABLE: no path canonicalization
        File file = new File(BASE_DIR, filename);
        return file.exists();
    }
}
