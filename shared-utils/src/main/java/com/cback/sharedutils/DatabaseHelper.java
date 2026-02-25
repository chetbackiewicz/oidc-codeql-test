package com.cback.sharedutils;

/**
 * DatabaseHelper — INTENTIONALLY VULNERABLE for CodeQL testing.
 *
 * Builds SQL queries via string concatenation, enabling SQL injection
 * when user-controlled values are passed as parameters.
 *
 * CWE-89: Improper Neutralization of Special Elements used in an SQL Command
 */
public class DatabaseHelper {

    /**
     * Builds a SELECT query by concatenating user-supplied values directly
     * into the SQL string.
     *
     * VULNERABLE: No parameterized queries or escaping.
     *
     * @param table  the table name
     * @param column the column to filter on
     * @param value  the filter value (user-controlled)
     * @return a raw SQL query string
     */
    public static String buildQuery(String table, String column, String value) {
        // VULNERABLE: direct string concatenation with user input
        return "SELECT * FROM " + table + " WHERE " + column + " = '" + value + "'";
    }

    /**
     * Builds an INSERT query by concatenating values directly.
     *
     * VULNERABLE: No parameterized queries or escaping.
     *
     * @param table   the target table
     * @param columns comma-separated column names
     * @param values  comma-separated values (user-controlled)
     * @return a raw SQL INSERT string
     */
    public static String buildInsert(String table, String columns, String values) {
        // VULNERABLE: direct string concatenation
        return "INSERT INTO " + table + " (" + columns + ") VALUES (" + values + ")";
    }
}
