package com.threatdetect.rules;

import com.threatdetect.model.InvalidInputException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class UrlRules {

    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$");

    private static final List<String> BRANDS = List.of(
            "paypal", "google", "apple", "microsoft", "amazon", "facebook",
            "instagram", "netflix", "whatsapp", "binance", "baridimob");

    private static final List<String> SUSPICIOUS_TLDS = List.of(
            ".zip", ".xyz", ".top", ".tk", ".click", ".gq", ".ml", ".cf", ".work", ".support");

    private static final Set<String> SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy");

    private static final List<String> PATH_KEYWORDS = List.of(
            "login", "signin", "verify", "secure", "update", "account", "password", "confirm");

    private UrlRules() {}

    /** Parses and evaluates a URL. Throws InvalidInputException if it is empty or malformed. */
    public static List<RuleHit> evaluate(String raw) throws InvalidInputException {
        if (raw == null || raw.isBlank()) {
            throw new InvalidInputException("Empty URL");
        }

        String input = raw.trim();
        boolean schemeMissing = !input.contains("://");
        String candidate = schemeMissing ? "http://" + input : input;

        URI uri;
        try {
            uri = new URI(candidate);
        } catch (URISyntaxException e) {
            throw new InvalidInputException("Malformed URL: " + e.getReason());
        }

        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
            throw new InvalidInputException("Unsupported URL scheme: " + scheme);
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new InvalidInputException("Malformed URL: no host found");
        }
        host = host.toLowerCase(Locale.ROOT);

        boolean isIp = IPV4.matcher(host).matches() || host.startsWith("[");
        if (!isIp && !host.contains(".")) {
            throw new InvalidInputException("Malformed URL: host has no domain");
        }

        List<RuleHit> hits = new ArrayList<>();

        // 1. Transport security
        if (schemeMissing) {
            hits.add(new RuleHit(20, "No scheme given, assuming insecure HTTP"));
        } else if (scheme.equalsIgnoreCase("http")) {
            hits.add(new RuleHit(20, "Uses HTTP instead of HTTPS"));
        }

        // 2. IP address instead of a domain name
        if (isIp) {
            hits.add(new RuleHit(30, "Host is an IP address"));
        }

        // 3. Credentials trick: http://google.com@evil.com
        if (uri.getUserInfo() != null) {
            hits.add(new RuleHit(25, "Contains '@' user-info (hides the real destination)"));
        }

        // 4. Too many subdomains
        if (!isIp && host.split("\\.").length > 4) {
            hits.add(new RuleHit(15, "Excessive number of subdomains"));
        }

        // 5. Misleading brand in the host
        if (!isIp) {
            for (String brand : BRANDS) {
                if (host.contains(brand) && !isOfficial(host, brand)) {
                    hits.add(new RuleHit(30, "Misleading subdomain/domain imitating '" + brand + "'"));
                    break;
                }
            }
        }

        // 6. Suspicious TLD
        for (String tld : SUSPICIOUS_TLDS) {
            if (host.endsWith(tld)) {
                hits.add(new RuleHit(15, "Suspicious top-level domain '" + tld + "'"));
                break;
            }
        }

        // 7. URL shorteners hide the destination
        if (SHORTENERS.contains(host)) {
            hits.add(new RuleHit(15, "URL shortener hides the real destination"));
        }

        // 8. Punycode (lookalike characters)
        if (host.contains("xn--")) {
            hits.add(new RuleHit(20, "Punycode host (possible lookalike characters)"));
        }

        // 9. Many hyphens in the host
        if (host.chars().filter(c -> c == '-').count() >= 3) {
            hits.add(new RuleHit(10, "Many hyphens in the domain name"));
        }

        // 10. Non-standard port
        int port = uri.getPort();
        if (port != -1 && port != 80 && port != 443) {
            hits.add(new RuleHit(10, "Non-standard port " + port));
        }

        // 11. Very long URL
        if (input.length() > 100) {
            hits.add(new RuleHit(10, "Very long URL"));
        }

        // 12. Sensitive keywords in path/query
        String pathAndQuery = ((uri.getRawPath() == null ? "" : uri.getRawPath())
                + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery())).toLowerCase(Locale.ROOT);
        for (String kw : PATH_KEYWORDS) {
            if (pathAndQuery.contains(kw)) {
                hits.add(new RuleHit(10, "Sensitive keyword in path: '" + kw + "'"));
                break;
            }
        }

        return hits;
    }

    private static boolean isOfficial(String host, String brand) {
        String official = brand + ".com";
        return host.equals(official) || host.endsWith("." + official);
    }
}