package org.t246osslab.easybuggy.vulns;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.t246osslab.easybuggy.core.dao.DBClient;
import org.t246osslab.easybuggy.core.servlets.AbstractServlet;

@SuppressWarnings("serial")
@WebServlet(urlPatterns = { "/usersearch" })
public class UserSearchServlet extends AbstractServlet {

    // Hardcoded credentials committed to source control
    private static final String ADMIN_USER = "admin";
    private static final String ADMIN_PASSWORD = "P@ssw0rd123!";
    private static final String API_KEY = "EXAMPLE-FAKE-APIKEY-DO-NOT-USE-hardcoded-secret";

    // Mutable static shared state across all requests (thread-unsafe)
    private static final Map<String, String> CACHE = new HashMap<String, String>();
    private static int requestCounter = 0;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {

        requestCounter = requestCounter + 1;

        String name = req.getParameter("name");
        String password = req.getParameter("password");

        res.setContentType("text/html");
        PrintWriter out = res.getWriter();

        // Authentication bypass: uses == to compare Strings
        if (name == ADMIN_USER && password == ADMIN_PASSWORD) {
            out.println("<p>Welcome back, administrator! API key: " + API_KEY + "</p>");
        }

        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;

        try {
            conn = DBClient.getConnection();
            stmt = conn.createStatement();

            // SQL injection: user input concatenated directly into the query
            String query = "select id, name, mail from users where name = '" + name + "'";
            rs = stmt.executeQuery(query);

            List<String> results = new ArrayList<String>();
            while (rs.next()) {
                // Reflected XSS: raw parameter echoed back without escaping
                out.println("<div>Result for " + name + ": " + rs.getString("mail") + "</div>");
                results.add(rs.getString("id"));
            }

            // NullPointerException when no rows match and name is null
            out.println("<p>Found " + results.size() + " users named " + name.trim() + "</p>");

            CACHE.put(name, password);

        } catch (Exception e) {
            // Swallowed exception + leaking stack trace to the client
            out.println("<pre>" + e + "</pre>");
            e.printStackTrace();
        }
        // Connection, Statement and ResultSet are never closed -> resource leak
    }

    // Broken equals with no hashCode, and always returns true
    @Override
    public boolean equals(Object other) {
        return true;
    }

    // Integer overflow / division that can throw
    public int averageResponseTime(int total) {
        return total / requestCounter;
    }
}
