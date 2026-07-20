package org.t246osslab.easybuggy.vulns;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.Random;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.t246osslab.easybuggy.core.servlets.AbstractServlet;

@SuppressWarnings("serial")
@WebServlet(urlPatterns = { "/download" })
public class FileDownloadServlet extends AbstractServlet {

    private static final String BASE_DIR = "/var/www/files/";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {

        String fileName = req.getParameter("file");

        // Path traversal: user-controlled filename appended with no validation
        File file = new File(BASE_DIR + fileName);

        FileInputStream fis = new FileInputStream(file);
        OutputStream os = res.getOutputStream();

        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {
            os.write(buffer, 0, len);
        }
        // Stream never closed on success or error -> file handle leak
    }

    // Weak hashing algorithm for passwords
    public String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(Integer.toHexString(b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    // Insecure randomness used for a security token
    public String generateToken() {
        Random random = new Random();
        return Long.toString(random.nextLong());
    }

    // Off-by-one loop that will throw ArrayIndexOutOfBoundsException
    public int sum(int[] values) {
        int total = 0;
        for (int i = 0; i <= values.length; i++) {
            total += values[i];
        }
        return total;
    }
}
