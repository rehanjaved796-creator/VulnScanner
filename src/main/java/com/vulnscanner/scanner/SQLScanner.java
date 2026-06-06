package com.vulnscanner.scanner;

import com.vulnscanner.model.Vulnerability;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

public class SQLScanner extends BaseScanner {

    // DVWA SQL Injection vulnerable endpoints
    private static final List<String> VULN_PATHS = List.of(
            "/vulnerabilities/sqli/?id=",
            "/vulnerabilities/sqli_blind/?id=",
            "?id=",
            "?user=",
            "?search="
    );

    private static final List<String> PAYLOADS = List.of(
            "'",
            "''",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR 1=1--",
            "1' AND 1=1--",
            "1 AND 1=2",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "admin'--"
    );

    private static final List<String> ERROR_PATTERNS = List.of(
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "mysql_fetch",
            "mysql_num_rows",
            "mysql_query",
            "ora-01756",
            "sqlite3::",
            "microsoft ole db",
            "jdbc exception",
            "sql command not properly ended",
            "unexpected end of sql command",
            "syntax error",
            "invalid query",
            "pg_query",
            "supplied argument is not a valid mysql"
    );

    private final HttpClient client;

    public SQLScanner(String targetUrl) {
        super(targetUrl);
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.ALWAYS)
                .build();
    }

    @Override
    public List<Vulnerability> scan() throws Exception {
        System.out.println("[*] SQL Injection scan starting...");
        System.out.println("[*] Target: " + targetUrl);

        // Try each vulnerable path
        for (String path : VULN_PATHS) {
            String baseTestUrl = targetUrl + path;

            for (String payload : PAYLOADS) {
                String encoded  = URLEncoder.encode(payload, StandardCharsets.UTF_8);
                String testUrl  = baseTestUrl + encoded;

                try {
                    HttpRequest request = HttpRequest.newBuilder()
                            .uri(URI.create(testUrl))
                            .timeout(Duration.ofSeconds(5))
                            .header("User-Agent", "Mozilla/5.0")
                            .header("Cookie", "PHPSESSID=dvwa; security=low")
                            .GET()
                            .build();

                    HttpResponse<String> response = client.send(
                            request, HttpResponse.BodyHandlers.ofString());

                    String body = response.body().toLowerCase();

                    for (String pattern : ERROR_PATTERNS) {
                        if (body.contains(pattern)) {
                            System.out.println("[+] SQL Injection found! URL: "
                                    + testUrl + " | Pattern: " + pattern);

                            // Avoid duplicate findings for same path
                            boolean alreadyFound = findings.stream()
                                    .anyMatch(v -> v.getUrl().contains(path));
                            if (!alreadyFound) {
                                findings.add(new Vulnerability.Builder()
                                        .name("SQL Injection")
                                        .type(Vulnerability.Type.SQL_INJECTION)
                                        .severity(Vulnerability.Severity.CRITICAL)
                                        .url(testUrl)
                                        .payload(payload)
                                        .evidence("SQL error pattern detected: '"
                                                + pattern + "' in response body.")
                                        .description("The application is vulnerable to SQL Injection. "
                                                + "An attacker can read, modify, or delete database contents.")
                                        .fix("Use PreparedStatements and parameterized queries. "
                                                + "Never concatenate user input directly into SQL queries. "
                                                + "Apply input validation and use a WAF.")
                                        .build());
                            }
                            break;
                        }
                    }

                } catch (Exception e) {
                    System.out.println("[-] Could not test: " + testUrl
                            + " | " + e.getMessage());
                }
            }
        }

        System.out.println("[+] SQL Scan complete. Found: "
                + findings.size() + " vulnerabilities");
        return findings;
    }
}
