package fixtures;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.regex.Pattern;

/** JS201 must still fire when the value is not validated end-to-end. */
public class ReflectedEcho {

    public void echo(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        PrintWriter pw = response.getWriter();
        pw.write("<h1>" + name + "</h1>");
    }

    // `find()` matches a substring and validates nothing.
    public void partialCheck(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String cb = request.getParameter("callback");
        if (Pattern.compile("[a-z]+").matcher(cb).find()) {
            response.getWriter().write(cb);
        }
    }
}
