package com.vulnscanner.scanner;

import com.vulnscanner.model.Vulnerability;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

public class XSSScanner extends BaseScanner {

    // DVWA XSS vulnerable endpoints
    private static final List<String> VULN_PATHS = List.of(
            "/vulnerabilities/xss_r/?name=",
            "/vulnerabilities/xss_s/",
            "?name=",
            "?q=",
            "?search=",
            "?input=",
            "?message="
    );

    private static final List<String> XSS_PAYLOADS = List.of(
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(1)>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<ScRiPt>alert('XSS')</ScRiPt>"
    );

    private final HttpClient client;

    public XSSScanner(String targetUrl) {
        super(targetUrl);
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.ALWAYS)
                .build();
    }

    @Override
    public List<Vulnerability> scan() throws Exception {
        System.out.println("[*] XSS scan starting...");
        System.out.println("[*] Target: " + targetUrl);

        for (String path : VULN_PATHS) {
            String baseTestUrl = targetUrl + path;

            for (String payload : XSS_PAYLOADS) {
                String encoded = URLEncoder.encode(payload, StandardCharsets.UTF_8);
                String testUrl = baseTestUrl + encoded;

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

                    String body = response.body();

                    // Check if payload is reflected in response (case-insensitive)
                    if (body.toLowerCase().contains(
                            payload.toLowerCase().substring(0, Math.min(payload.length(), 15)))) {

                        System.out.println("[+] XSS Found! URL: " + testUrl);

                        // Avoid duplicate findings for same path
                        boolean alreadyFound = findings.stream()
                                .anyMatch(v -> v.getUrl().contains(path));

                        if (!alreadyFound) {
                            findings.add(new Vulnerability.Builder()
                                    .name("Reflected Cross-Site Scripting (XSS)")
                                    .type(Vulnerability.Type.XSS)
                                    .severity(Vulnerability.Severity.HIGH)
                                    .url(testUrl)
                                    .payload(payload)
                                    .evidence("XSS payload was reflected in the HTTP response body. "
                                            + "Payload: " + payload)
                                    .description("The application does not sanitize user input before "
                                            + "rendering it in the browser. An attacker can inject "
                                            + "malicious scripts to steal cookies, redirect users, "
                                            + "or perform actions on their behalf.")
                                    .fix("Encode all user-supplied output using HTML entity encoding. "
                                            + "Implement a Content Security Policy (CSP) header. "
                                            + "Use frameworks that auto-escape output.")
                                    .build());
                        }
                    }

                } catch (Exception e) {
                    System.out.println("[-] Could not test: " + testUrl
                            + " | " + e.getMessage());
                }
            }
        }

        System.out.println("[+] XSS Scan complete. Found: "
                + findings.size() + " vulnerabilities");
        return findings;
    }
}
