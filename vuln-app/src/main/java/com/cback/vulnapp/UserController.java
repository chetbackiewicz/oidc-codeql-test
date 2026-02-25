package com.cback.vulnapp;

import com.cback.sharedutils.DatabaseHelper;
import com.cback.sharedutils.InputSanitizer;
import com.cback.sharedutils.XmlHelper;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import org.w3c.dom.Document;

/**
 * UserController — INTENTIONALLY VULNERABLE for CodeQL testing.
 *
 * This servlet exposes endpoints with multiple vulnerability types.
 * Vulnerabilities are written with DIRECT taint flows so CodeQL
 * can trace from HTTP source → vulnerable sink without crossing
 * JAR boundaries.
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
        } else if ("readfile".equals(action)) {
            handleReadFile(request, response);
        } else if ("parsexml".equals(action)) {
            handleParseXml(request, response);
        } else {
            response.getWriter().println("Unknown action");
        }
    }

    /**
     * Handles user search — VULNERABLE to SQL Injection (CWE-89).
     *
     * User input is concatenated directly into a SQL query string
     * and then executed. Also calls DatabaseHelper to keep the
     * shared-utils dependency exercised.
     */
    private void handleSearch(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String username = request.getParameter("username");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        // Also call shared-utils so the dependency is exercised during build
        String helperQuery = DatabaseHelper.buildQuery("users", "username", username);

        // VULNERABLE (CWE-89): direct string concatenation of user input into SQL
        String query = "SELECT * FROM users WHERE username = '" + username + "'";

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
            // VULNERABLE (CWE-209): error message exposed to user
            out.println("Error: " + e.getMessage());
        }
    }

    /**
     * Handles greeting — VULNERABLE to Cross-Site Scripting / XSS (CWE-79).
     *
     * User input is reflected directly into the HTML response without
     * any encoding or escaping.
     */
    private void handleGreet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String name = request.getParameter("name");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        // Call shared-utils to exercise the dependency (still a no-op)
        InputSanitizer.sanitize(name);

        // VULNERABLE (CWE-79): user input reflected directly in HTML output
        out.println("<html><body>");
        out.println("<h1>Hello, " + name + "!</h1>");
        out.println("</body></html>");
    }

    /**
     * Handles file read — VULNERABLE to Path Traversal (CWE-22).
     *
     * User-controlled filename is used directly in a File path
     * without validation, allowing directory traversal.
     */
    private void handleReadFile(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String filename = request.getParameter("filename");
        response.setContentType("text/plain");
        PrintWriter out = response.getWriter();

        // VULNERABLE (CWE-22): path traversal — user controls the filename
        File file = new File("/var/app/uploads", filename);

        try {
            String content = new String(Files.readAllBytes(file.toPath()));
            out.println(content);
        } catch (Exception e) {
            out.println("Error: " + e.getMessage());
        }
    }

    /**
     * Handles XML parsing — VULNERABLE to XXE (CWE-611).
     *
     * User-supplied XML is parsed with external entities enabled.
     * Also calls XmlHelper from shared-utils to exercise that dependency.
     */
    private void handleParseXml(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String xmlInput = request.getParameter("xml");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        // Call shared-utils to exercise the dependency
        try {
            XmlHelper.parse(xmlInput);
        } catch (Exception ignored) {
        }

        try {
            // VULNERABLE (CWE-611): XXE — no external entity restrictions
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(
                    new ByteArrayInputStream(xmlInput.getBytes(StandardCharsets.UTF_8)));
            out.println("<html><body>");
            out.println("<p>Root element: " + doc.getDocumentElement().getTagName() + "</p>");
            out.println("</body></html>");
        } catch (Exception e) {
            out.println("Error: " + e.getMessage());
        }
    }
}
