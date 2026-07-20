package com.example.safe;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import org.owasp.encoder.Encode;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SafeService {

    /** Parameterized query: no injection. */
    @GetMapping("/user")
    public String findUser(Connection conn, @RequestParam String id) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT name FROM users WHERE id = ?");
        ps.setString(1, id);
        ResultSet rs = ps.executeQuery();
        return rs.next() ? rs.getString(1) : "";
    }

    /** Output encoding kills the taint before rendering. */
    @GetMapping("/greet")
    public String greet(@RequestParam String name) {
        return "<h1>Hello " + Encode.forHtml(name) + "</h1>";
    }

    /** Numeric parsing sanitizes the input. */
    @GetMapping("/page")
    public int page(@RequestParam String page) {
        int p = Integer.parseInt(page);
        return Math.max(0, p);
    }

    public byte[] strongHash(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] token() {
        SecureRandom rng = new SecureRandom();
        byte[] token = new byte[32];
        rng.nextBytes(token);
        return token;
    }
}
