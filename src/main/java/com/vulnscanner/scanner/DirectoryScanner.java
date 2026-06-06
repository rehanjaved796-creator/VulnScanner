package com.vulnscanner.scanner;

import com.vulnscanner.model.Vulnerability;

import java.net.http.HttpResponse;
import java.util.List;

/**
 * DirectoryScanner — Discovers exposed sensitive directories and files.
 */
public class DirectoryScanner extends BaseScanner {

    private static final List<String[]> TARGETS = List.of(
            // { path, description, severity }
            new String[]{ "/admin",           "Admin panel",              "HIGH"   },
            new String[]{ "/admin/login",      "Admin login page",         "HIGH"   },
            new String[]{ "/administrator",    "Administrator panel",      "HIGH"   },
            new String[]{ "/phpmyadmin",       "phpMyAdmin database UI",   "CRITICAL"},
            new String[]{ "/phpmyadmin/",      "phpMyAdmin database UI",   "CRITICAL"},
            new String[]{ "/wp-admin",         "WordPress admin panel",    "HIGH"   },
            new String[]{ "/wp-login.php",     "WordPress login page",     "HIGH"   },
            new String[]{ "/backup",           "Backup directory",         "HIGH"   },
            new String[]{ "/backup.zip",       "Backup archive file",      "CRITICAL"},
            new String[]{ "/backup.sql",       "Database backup file",     "CRITICAL"},
            new String[]{ "/db",               "Database directory",       "HIGH"   },
            new String[]{ "/database",         "Database directory",       "HIGH"   },
            new String[]{ "/config",           "Configuration directory",  "HIGH"   },
            new String[]{ "/config.php",       "PHP config file",          "CRITICAL"},
            new String[]{ "/.env",             "Environment config file",  "CRITICAL"},
            new String[]{ "/.git",             "Git repository exposed",   "CRITICAL"},
            new String[]{ "/.git/config",      "Git config file",          "CRITICAL"},
            new String[]{ "/logs",             "Log files directory",      "MEDIUM" },
            new String[]{ "/error.log",        "Error log file",           "MEDIUM" },
            new String[]{ "/debug",            "Debug interface",          "HIGH"   },
            new String[]{ "/test",             "Test directory",           "MEDIUM" },
            new String[]{ "/tmp",              "Temp files directory",     "MEDIUM" },
            new String[]{ "/uploads",          "Uploads directory",        "MEDIUM" },
            new String[]{ "/files",            "Files directory",          "MEDIUM" },
            new String[]{ "/install",          "Installation directory",   "HIGH"   },
            new String[]{ "/setup",            "Setup directory",          "HIGH"   },
            new String[]{ "/private",          "Private directory",        "HIGH"   },
            new String[]{ "/secret",           "Secret directory",         "HIGH"   },
            new String[]{ "/server-status",    "Apache server status",     "MEDIUM" },
            new String[]{ "/server-info",      "Apache server info",       "MEDIUM" },
            new String[]{ "/info.php",         "PHP info page exposed",    "HIGH"   },
            new String[]{ "/phpinfo.php",      "PHP info page exposed",    "HIGH"   },
            new String[]{ "/shell.php",        "Web shell detected",       "CRITICAL"},
            new String[]{ "/cmd.php",          "Command shell detected",   "CRITICAL"},
            // DVWA specific paths
            new String[]{ "/vulnerabilities",  "DVWA vulnerabilities page","HIGH"   },
            new String[]{ "/dvwa/setup.php",   "DVWA setup page",          "HIGH"   }
    );

    public DirectoryScanner(String targetUrl) {
        super(targetUrl);
    }

    @Override
    public List<Vulnerability> scan() throws Exception {
        System.out.println("[*] Directory scan starting...");
        System.out.println("[*] Target: " + targetUrl);
        System.out.println("[*] Checking " + TARGETS.size() + " paths...");

        for (String[] target : TARGETS) {
            String path        = target[0];
            String description = target[1];
            String severityStr = target[2];
            String testUrl     = targetUrl + path;

            try {
                HttpResponse<String> response = sendGet(testUrl);
                int statusCode = response.statusCode();

                // 200 = accessible, 403 = exists but restricted, 401 = auth required
                if (statusCode == 200 || statusCode == 403 || statusCode == 401) {

                    Vulnerability.Severity severity;
                    String evidence;

                    if (statusCode == 200) {
                        // Override severity to CRITICAL if accessible
                        severity = Vulnerability.Severity.valueOf(severityStr);
                        evidence = description + " is publicly accessible. "
                                + "Status: 200 OK — content is readable by anyone.";
                        System.out.println("[+] ACCESSIBLE: " + testUrl
                                + " [200] — " + description);
                    } else {
                        // Exists but restricted — downgrade severity
                        severity = Vulnerability.Severity.LOW;
                        evidence = description + " exists but access is restricted. "
                                + "Status: " + statusCode;
                        System.out.println("[~] EXISTS (restricted): " + testUrl
                                + " [" + statusCode + "]");
                    }

                    findings.add(new Vulnerability.Builder()
                            .name("Exposed Path: " + path)
                            .type(Vulnerability.Type.DIRECTORY_LISTING)
                            .severity(severity)
                            .url(testUrl)
                            .payload("GET " + path)
                            .evidence(evidence)
                            .description("Sensitive path '" + path + "' ("
                                    + description + ") was discovered on the server. "
                                    + "HTTP Status Code: " + statusCode)
                            .fix("Remove or restrict access to '" + path + "'. "
                                    + "Use server configuration (.htaccess / nginx rules) "
                                    + "to block external access to sensitive directories.")
                            .build());
                }

            } catch (Exception e) {
                // Connection error — path likely doesn't exist, skip
            }
        }

        System.out.println("[+] Directory scan complete. Found: "
                + findings.size() + " exposed paths");
        return findings;
    }
}
