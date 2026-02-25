package com.cback.vulnapp;

import com.cback.sharedutils.DatabaseHelper;
import com.cback.sharedutils.InputSanitizer;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * UserController — INTENTIONALLY VULNERABLE for CodeQL testing.
 *
 * This servlet exposes endpoints with SQL Injection (CWE-89) and
 * Cross-Site Scripting (CWE-79) vulnerabilities by using the
 * intentionally broken shared-utils helpers.
 */
public class UserController extends HttpServlet {

    private static final String DB_URL = "jdbc:h2:mem:testdb";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String action = request.getParameter("action");

        if ("search".equals(action)) {
            handleSearch(request, response);
        } else if ("greet".equals(action)) {
            handleGreet(request, response);
        } else {
            response.getWriter().println("Unknown action");
        }
    }

    /**
     * Handles user search — VULNERABLE to SQL Injection (CWE-89).
     *
     * User input flows through DatabaseHelper.buildQuery() which performs
     * unsafe string concatenation, then is executed as SQL.
     */
    private void handleSearch(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String username = request.getParameter("username");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        // VULNERABLE: user input → DatabaseHelper.buildQuery() → SQL execution
        // DatabaseHelper uses string concatenation (no parameterized queries)
        String query = DatabaseHelper.buildQuery("users", "username", username);

        try {
            Connection conn = DriverManager.getConnection(DB_URL);
            Statement stmt = conn.createStatement();
            // VULNERABLE: executing a query built from unsanitized user input
            ResultSet rs = stmt.executeQuery(query);

            out.println("<html><body><h2>Search Results</h2>");
            while (rs.next()) {
                out.println("<p>" + rs.getString("username") + " — " + rs.getString("email") + "</p>");
            }
            out.println("</body></html>");

            rs.close();
            stmt.close();
            conn.close();
        } catch (Exception e) {
            out.println("Error: " + e.getMessage());
        }
    }

    /**
     * Handles greeting — VULNERABLE to Cross-Site Scripting / XSS (CWE-79).
     *
     * User input passes through InputSanitizer.sanitize() which is a no-op,
     * then is reflected directly into the HTML response.
     */
    private void handleGreet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String name = request.getParameter("name");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        // VULNERABLE: InputSanitizer.sanitize() is a no-op — returns input unchanged
        String safeName = InputSanitizer.sanitize(name);

        // VULNERABLE: unsanitized user input reflected in HTML output
        out.println("<html><body>");
        out.println("<h1>Hello, " + safeName + "!</h1>");
        out.println("</body></html>");
    }
}
