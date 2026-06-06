package com.vulnscanner.scanner;

import com.vulnscanner.model.Vulnerability;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * BaseScanner — Abstract base class for all scanner modules.
 * Handles HTTP client, session cookies, and common request logic.
 */
public abstract class BaseScanner {

    protected final String          targetUrl;
    protected final List<Vulnerability> findings;
    protected final HttpClient      client;

    // DVWA session cookie — shared across all scanners
    protected static String SESSION_COOKIE = "PHPSESSID=dvwa; security=low";

    public BaseScanner(String targetUrl) {
        this.targetUrl = targetUrl.endsWith("/")
                ? targetUrl.substring(0, targetUrl.length() - 1)
                : targetUrl;
        this.findings  = new ArrayList<>();
        this.client    = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(8))
                .followRedirects(HttpClient.Redirect.ALWAYS)
                .build();
    }

    // ── Abstract method — each scanner implements this ──
    public abstract List<Vulnerability> scan() throws Exception;

    // ── Send GET request with session ──
    protected HttpResponse<String> sendGet(String url) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(8))
                .header("User-Agent",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                + "AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
                .header("Cookie", SESSION_COOKIE)
                .header("Accept", "text/html,application/xhtml+xml,*/*")
                .GET()
                .build();

        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    // ── Send POST request with session ──
    protected HttpResponse<String> sendPost(String url, String body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(8))
                .header("User-Agent",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                + "AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
                .header("Cookie", SESSION_COOKIE)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    // ── Check if URL is reachable ──
    protected boolean isReachable(String url) {
        try {
            HttpResponse<String> response = sendGet(url);
            return response.statusCode() < 500;
        } catch (Exception e) {
            return false;
        }
    }

    // ── Set custom session cookie ──
    public static void setSessionCookie(String cookie) {
        SESSION_COOKIE = cookie;
    }

    // ── Get findings ──
    public List<Vulnerability> getFindings() { return findings; }

    // ── Avoid duplicate findings ──
    protected boolean alreadyFound(String path) {
        return findings.stream().anyMatch(v -> v.getUrl().contains(path));
    }

    // ── Legacy sendRequest — kept for compatibility ──
    protected HttpResponse<String> sendRequest(String url) throws Exception {
        return sendGet(url);
    }
}
