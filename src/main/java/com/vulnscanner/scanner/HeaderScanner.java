package com.vulnscanner.scanner;

import com.vulnscanner.model.Vulnerability;

import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * HeaderScanner — Checks for missing or misconfigured HTTP security headers.
 */
public class HeaderScanner extends BaseScanner {

    // Header name → { description, severity, fix }
    private static final Map<String, String[]> SECURITY_HEADERS = new LinkedHashMap<>();

    static {
        SECURITY_HEADERS.put("Strict-Transport-Security", new String[]{
                "HSTS header is missing. The application does not enforce HTTPS connections, "
                        + "making it vulnerable to protocol downgrade and man-in-the-middle attacks.",
                "HIGH",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        });

        SECURITY_HEADERS.put("Content-Security-Policy", new String[]{
                "CSP header is missing. Without CSP, the browser cannot restrict which resources "
                        + "can be loaded, increasing risk of XSS and data injection attacks.",
                "HIGH",
                "Add: Content-Security-Policy: default-src 'self'; script-src 'self'"
        });

        SECURITY_HEADERS.put("X-Frame-Options", new String[]{
                "X-Frame-Options header is missing. The application may be vulnerable to "
                        + "Clickjacking attacks where the page is embedded in a malicious iframe.",
                "MEDIUM",
                "Add: X-Frame-Options: DENY  or  X-Frame-Options: SAMEORIGIN"
        });

        SECURITY_HEADERS.put("X-Content-Type-Options", new String[]{
                "X-Content-Type-Options header is missing. Browsers may perform MIME-type sniffing "
                        + "and execute files as a different content type than declared.",
                "MEDIUM",
                "Add: X-Content-Type-Options: nosniff"
        });

        SECURITY_HEADERS.put("X-XSS-Protection", new String[]{
                "X-XSS-Protection header is missing. The browser's built-in XSS filter is not "
                        + "explicitly enabled, reducing client-side XSS protection.",
                "MEDIUM",
                "Add: X-XSS-Protection: 1; mode=block"
        });

        SECURITY_HEADERS.put("Referrer-Policy", new String[]{
                "Referrer-Policy header is missing. Sensitive URL parameters may be leaked "
                        + "to third-party sites through the Referer header.",
                "LOW",
                "Add: Referrer-Policy: strict-origin-when-cross-origin"
        });

        SECURITY_HEADERS.put("Permissions-Policy", new String[]{
                "Permissions-Policy header is missing. Browser features like camera, microphone, "
                        + "and geolocation are not restricted.",
                "LOW",
                "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
        });
    }

    public HeaderScanner(String targetUrl) {
        super(targetUrl);
    }

    @Override
    public List<Vulnerability> scan() throws Exception {
        System.out.println("[*] Security header scan starting...");
        System.out.println("[*] Target: " + targetUrl);

        if (!isReachable(targetUrl)) {
            System.out.println("[-] Target not reachable: " + targetUrl);
            return findings;
        }

        HttpResponse<String> response = sendGet(targetUrl);
        System.out.println("[~] Response status: " + response.statusCode());

        for (Map.Entry<String, String[]> entry : SECURITY_HEADERS.entrySet()) {
            String   headerName = entry.getKey();
            String[] info       = entry.getValue();
            String   description = info[0];
            String   severityStr = info[1];
            String   fix         = info[2];

            boolean missing = response.headers()
                    .firstValue(headerName.toLowerCase())
                    .isEmpty();

            if (missing) {
                System.out.println("[+] Missing header: " + headerName);

                Vulnerability.Severity severity =
                        Vulnerability.Severity.valueOf(severityStr);

                findings.add(new Vulnerability.Builder()
                        .name("Missing Security Header: " + headerName)
                        .type(Vulnerability.Type.MISSING_HEADER)
                        .severity(severity)
                        .url(targetUrl)
                        .payload("N/A")
                        .evidence("HTTP response does not contain the '"
                                + headerName + "' header.")
                        .description(description)
                        .fix(fix)
                        .build());
            } else {
                System.out.println("[✓] Present: " + headerName);
            }
        }

        System.out.println("[+] Header scan complete. Missing: "
                + findings.size() + " headers");
        return findings;
    }
}
