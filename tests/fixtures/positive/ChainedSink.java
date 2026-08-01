package fixtures;

import jakarta.servlet.http.HttpServletRequest;

/**
 * The sink sits at the end of a multi-line call chain. The finding must be
 * anchored at `executeQuery`, not at the first line of the chain — otherwise
 * the reported line and snippet point at an unrelated statement.
 */
public class ChainedSink {

    public void run(HttpServletRequest request) throws Exception {
        String query = request.getParameter("queryString");
        DatabaseInfo info = DatabaseService.get("mysql")
                .executeQuery(query);
        info.toString();
    }

    static class DatabaseService {
        static DatabaseService get(String type) {
            return new DatabaseService();
        }

        DatabaseInfo executeQuery(String sql) {
            return new DatabaseInfo();
        }
    }

    static class DatabaseInfo {
    }
}
