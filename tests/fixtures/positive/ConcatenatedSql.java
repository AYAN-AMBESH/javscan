package fixtures;

import java.sql.Connection;
import java.sql.Statement;

/** JS101 must still fire when values, not just column names, are concatenated. */
public class ConcatenatedSql {

    public void deleteUser(Connection conn, String name) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeUpdate("DELETE FROM users WHERE name = '" + name + "'");
    }

    public void viaLocal(Connection conn, String name) throws Exception {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        stmt.executeQuery(sql);
    }
}
