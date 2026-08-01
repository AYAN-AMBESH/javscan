package fixtures;

import java.util.ArrayList;
import java.util.List;

/**
 * JS101 must not fire when a query skeleton is concatenated from constants but
 * every value is bound through a `?` placeholder and passed alongside the SQL.
 * This is the dominant shape in real DAOs and was the single largest source of
 * false positives when scanning Apache SkyWalking.
 */
public class ParameterizedDao {

    private JdbcClient jdbcClient;

    public List<String> queryEvents(String table, List<String> ids) throws Exception {
        StringBuilder whereQuery = new StringBuilder()
                .append(" where ")
                .append("table_name").append(" = ?")
                .append(" and service_id = ?");
        String sql = "select * from " + table + whereQuery;
        return jdbcClient.executeQuery(sql, r -> new ArrayList<String>(), ids.toArray());
    }

    public List<String> inlineSkeleton(String table, String id) throws Exception {
        return jdbcClient.executeQuery("SELECT * FROM " + table + " WHERE id = ?", r -> new ArrayList<String>(), id);
    }

    interface JdbcClient {
        <T> T executeQuery(String sql, ResultHandler<T> handler, Object... params) throws Exception;
    }

    interface ResultHandler<T> {
        T handle(Object rs);
    }
}
