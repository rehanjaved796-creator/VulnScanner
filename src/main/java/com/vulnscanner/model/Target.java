package com.vulnscanner.model;

public class Target {

    private String url;
    private String domain;
    private String ipAddress;
    private int    port;
    private String protocol;  // http or https
    private String notes;

    public Target(String url) {
        this.url = url;

        // Auto extract protocol
        if (url.startsWith("https")) {
            this.protocol = "HTTPS";
            this.port = 443;
        } else {
            this.protocol = "HTTP";
            this.port = 80;
        }

        // Extract domain
        this.domain = url.replace("https://","")
                .replace("http://","")
                .split("/")[0];
    }

    // Getters & Setters
    public String getUrl()           { return url; }
    public String getDomain()        { return domain; }
    public String getIpAddress()     { return ipAddress; }
    public int    getPort()          { return port; }
    public String getProtocol()      { return protocol; }
    public String getNotes()         { return notes; }

    public void setIpAddress(String ip)  { this.ipAddress = ip; }
    public void setNotes(String notes)   { this.notes = notes; }
    public void setPort(int port)        { this.port = port; }

    @Override
    public String toString() {
        return String.format("Target{url='%s', domain='%s'," +
                " protocol='%s', port=%d}", url, domain, protocol, port);
    }
}