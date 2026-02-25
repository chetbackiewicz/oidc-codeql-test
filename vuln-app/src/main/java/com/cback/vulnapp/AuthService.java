package com.cback.vulnapp;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Base64;

/**
 * AuthService — INTENTIONALLY VULNERABLE for CodeQL testing.
 *
 * Contains hardcoded credentials (CWE-798) and uses the weak MD5
 * hashing algorithm (CWE-327) for password verification.
 */
public class AuthService {

    // VULNERABLE: hardcoded credentials (CWE-798)
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_PASSWORD = "SuperSecret123!";

    // VULNERABLE: hardcoded database credentials (CWE-798)
    private static final String DB_CONNECTION_STRING = "jdbc:mysql://prod-db.internal:3306/appdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "r00tP@ssw0rd!";

    /**
     * Authenticates a user against hardcoded admin credentials.
     *
     * VULNERABLE: Uses hardcoded credentials and MD5 for hashing.
     *
     * @param username the supplied username
     * @param password the supplied password
     * @return true if credentials match the hardcoded admin account
     */
    public boolean authenticate(String username, String password) {
        if (ADMIN_USERNAME.equals(username)) {
            String hashedInput = hashMd5(password);
            String hashedAdmin = hashMd5(ADMIN_PASSWORD);
            return hashedInput.equals(hashedAdmin);
        }
        return false;
    }

    /**
     * Hashes a password using MD5.
     *
     * VULNERABLE: MD5 is a weak, broken hashing algorithm (CWE-327).
     * Passwords should be hashed with bcrypt, scrypt, or Argon2.
     *
     * @param input the string to hash
     * @return Base64-encoded MD5 hash
     */
    public String hashMd5(String input) {
        try {
            // VULNERABLE: MD5 is cryptographically broken
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes());
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 not available", e);
        }
    }

    /**
     * Returns the database connection string.
     *
     * VULNERABLE: exposes hardcoded credentials.
     */
    public String getDbConnectionString() {
        return DB_CONNECTION_STRING + "?user=" + DB_USER + "&password=" + DB_PASSWORD;
    }

    /**
     * Opens a database connection using hardcoded credentials.
     *
     * VULNERABLE (CWE-798): Hardcoded password flows directly into
     * DriverManager.getConnection(), making it detectable by CodeQL.
     */
    public Connection getConnection() throws Exception {
        // VULNERABLE: hardcoded credentials used in connection
        return DriverManager.getConnection(
                "jdbc:mysql://prod-db.internal:3306/appdb",
                "root",
                "r00tP@ssw0rd!");
    }
}
