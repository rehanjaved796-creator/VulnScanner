package com.vulnscanner.scanner;

import com.vulnscanner.model.Vulnerability;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * PortScanner — Multi-threaded port scanner.
 * Detects open ports and flags dangerous ones.
 */
public class PortScanner extends BaseScanner {

    private static final Map<Integer, String[]> PORT_INFO = new LinkedHashMap<>();

    static {
        //  port → { service name, severity, description, fix }
        PORT_INFO.put(21,   new String[]{ "FTP",
                "HIGH",
                "FTP transmits data in plaintext, including credentials. "
                        + "An attacker can intercept login details via a MITM attack.",
                "Disable FTP and use SFTP (port 22) instead. "
                        + "If FTP is required, use FTPS with TLS encryption." });

        PORT_INFO.put(22,   new String[]{ "SSH",
                "INFO",
                "SSH port is open. This is normal for remote administration "
                        + "but should be restricted to trusted IPs only.",
                "Restrict SSH access to specific IP addresses using firewall rules. "
                        + "Disable root login and use key-based authentication." });

        PORT_INFO.put(23,   new String[]{ "Telnet",
                "CRITICAL",
                "Telnet is open. Telnet transmits everything in plaintext including "
                        + "usernames and passwords. This is a critical security risk.",
                "Immediately disable Telnet. Replace with SSH for remote access." });

        PORT_INFO.put(25,   new String[]{ "SMTP",
                "MEDIUM",
                "SMTP port is publicly accessible. Open SMTP relays can be abused "
                        + "for sending spam or phishing emails.",
                "Restrict SMTP to authenticated users only. "
                        + "Disable open relay configuration." });

        PORT_INFO.put(80,   new String[]{ "HTTP",
                "INFO",
                "HTTP port is open. Traffic is not encrypted.",
                "Redirect all HTTP traffic to HTTPS (port 443)." });

        PORT_INFO.put(443,  new String[]{ "HTTPS",
                "INFO",
                "HTTPS port is open. Encrypted web traffic.",
                "Ensure SSL/TLS certificates are valid and up to date." });

        PORT_INFO.put(3306, new String[]{ "MySQL",
                "HIGH",
                "MySQL database port is publicly accessible. "
                        + "An attacker may attempt brute-force or exploit known MySQL vulnerabilities.",
                "Block port 3306 in your firewall. "
                        + "MySQL should only be accessible from localhost or trusted IPs." });

        PORT_INFO.put(3389, new String[]{ "RDP",
                "HIGH",
                "Remote Desktop Protocol (RDP) is publicly accessible. "
                        + "RDP is a common target for brute-force and ransomware attacks.",
                "Restrict RDP access using a VPN or firewall rules. "
                        + "Enable Network Level Authentication (NLA)." });

        PORT_INFO.put(8080, new String[]{ "HTTP-Alt",
                "MEDIUM",
                "Alternate HTTP port 8080 is open. "
                        + "Development servers are often misconfigured and expose sensitive data.",
                "Ensure this port is not exposing debug or development interfaces. "
                        + "Block externally if not required." });

        PORT_INFO.put(8443, new String[]{ "HTTPS-Alt",
                "INFO",
                "Alternate HTTPS port 8443 is open.",
                "Verify this port is intentional and properly secured." });

        PORT_INFO.put(27017, new String[]{ "MongoDB",
                "CRITICAL",
                "MongoDB port is publicly accessible without authentication. "
                        + "Unauthenticated MongoDB instances have led to massive data breaches.",
                "Enable MongoDB authentication immediately. "
                        + "Block port 27017 externally using a firewall." });

        PORT_INFO.put(6379, new String[]{ "Redis",
                "CRITICAL",
                "Redis port is publicly accessible. "
                        + "Unauthenticated Redis allows reading all cached data and remote code execution.",
                "Enable Redis authentication (requirepass). "
                        + "Block port 6379 from external access." });
    }

    private final String host;

    public PortScanner(String targetUrl) {
        super(targetUrl);
        // Extract hostname from URL
        this.host = targetUrl
                .replace("https://", "")
                .replace("http://", "")
                .split("/")[0]
                .split(":")[0];
    }

    @Override
    public List<Vulnerability> scan() throws Exception {
        System.out.println("[*] Port scan starting on: " + host);

        // Multi-threaded scanning — faster!
        ExecutorService executor = Executors.newFixedThreadPool(8);
        List<Future<?>> futures  = new ArrayList<>();

        for (Map.Entry<Integer, String[]> entry : PORT_INFO.entrySet()) {
            int      port    = entry.getKey();
            String[] info    = entry.getValue();

            Future<?> future = executor.submit(() -> {
                if (isPortOpen(host, port)) {
                    String service  = info[0];
                    String sevStr   = info[1];
                    String desc     = info[2];
                    String fix      = info[3];

                    System.out.println("[+] Open port: "
                            + port + " (" + service + ") [" + sevStr + "]");

                    // Only report if not INFO level
                    if (!sevStr.equals("INFO")) {
                        synchronized (findings) {
                            findings.add(new Vulnerability.Builder()
                                    .name("Open Port: " + port + " " + service)
                                    .type(Vulnerability.Type.OPEN_PORT)
                                    .severity(Vulnerability.Severity.valueOf(sevStr))
                                    .url(host + ":" + port)
                                    .payload("TCP Connect to port " + port)
                                    .evidence(service + " service is reachable "
                                            + "on port " + port + ".")
                                    .description(desc)
                                    .fix(fix)
                                    .build());
                        }
                    } else {
                        System.out.println("[~] Info port open: "
                                + port + " (" + service + ") — not flagged");
                    }
                }
            });
            futures.add(future);
        }

        // Wait for all threads
        executor.shutdown();
        executor.awaitTermination(30, TimeUnit.SECONDS);

        System.out.println("[+] Port scan complete. Issues found: "
                + findings.size());
        return findings;
    }

    private boolean isPortOpen(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 2000);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
