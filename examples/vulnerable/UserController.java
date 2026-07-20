package com.example.vuln;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Random;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserController extends HttpServlet {

    private static final String DB_PASSWORD = "SuperS3cretPass!";
    private String apiKey = "AKIAIOSFODNN7EXAMPLE0";

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String userId = request.getParameter("id");
        String name = request.getParameter("name");

        // SQL injection: tainted concat into executeQuery
        try {
            Connection conn = DriverManager.getConnection(
                    "jdbc:mysql://db.internal/prod", "root", "hunter2secret");
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE id = '" + userId + "'";
            stmt.executeQuery(query);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Command injection
        try {
            Runtime.getRuntime().exec("ping " + request.getParameter("host"));
        } catch (IOException e) {
        }

        // XSS: tainted data to response writer
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + name + "</h1>");

        // Open redirect
        response.sendRedirect(request.getParameter("next"));

        // Path traversal
        File f = new File("/var/data/" + request.getParameter("file"));

        // SSRF
        URL url = new URL(request.getParameter("callback"));
        url.openConnection();

        // Weak randomness in a security context
        Random random = new Random();
        String sessionToken = String.valueOf(random.nextInt());

        // Insecure cookie
        Cookie session = new Cookie("JSESSIONID", sessionToken);
        response.addCookie(session);

        // Permissive CORS
        response.setHeader("Access-Control-Allow-Origin", "*");

        // Cleartext HTTP
        String endpoint = "http://payments.internal.example.net/api";
    }

    // Suppressed finding: should NOT appear
    public void suppressed(HttpServletRequest request) throws IOException {
        Runtime.getRuntime().exec("ls " + request.getParameter("d")); // nosec
    }
}
