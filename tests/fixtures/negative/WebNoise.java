package fixtures;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.regex.Pattern;

/**
 * Assorted precision fixes, all reproduced from real scans:
 *
 * JS204 — a `Cookie` built to send upstream is never a Set-Cookie header.
 * JS207 — `"http://"` used in a scheme comparison is not a cleartext endpoint.
 * JS203 — Commons FileUpload's `openStream()` is not `URL.openStream()`.
 * JS303 — the word `private` contains `iv`, which must not imply a
 *         security-sensitive context.
 * JS701 — `(/x+)*` is anchored by a separator and backtracks linearly.
 */
public class WebNoise {

    private static final Pattern VALID_NAME = Pattern.compile("^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$");

    public List<Cookie> upstreamCookies(HttpServletRequest request) {
        List<Cookie> out = new ArrayList<>();
        for (Cookie c : request.getCookies()) {
            out.add(new Cookie(c.getName(), c.getValue()));
        }
        return out;
    }

    public boolean isCleartext(String url) {
        return url.startsWith("http://");
    }

    public void readUpload(FileItemStream item) throws Exception {
        InputStream stream = item.openStream();
        stream.close();
    }

    private long randomSleep(int min, int max) {
        Random rand = new Random();
        return rand.nextInt((max - min) + 1) + min;
    }

    interface FileItemStream {
        InputStream openStream() throws Exception;
    }
}
