package fixtures;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.regex.Pattern;

/**
 * JS201 — a reflected value checked against a whole-string regex is validated.
 * `matches()` anchors at both ends, so the developer has declared the accepted
 * alphabet; this is the JSONP-callback shape from OpenRefine's Command.java.
 */
public class RegexValidated {

    public void jsonp(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String cb = request.getParameter("callback");
        Pattern validIdentifier = Pattern.compile("[a-zA-Z0-9_]+");
        if (validIdentifier.matcher(cb).matches()) {
            PrintWriter pw = response.getWriter();
            pw.write(cb + "(");
            pw.write(")");
        }
    }
}
