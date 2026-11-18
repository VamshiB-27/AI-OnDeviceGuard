package com.vcs.ondeviceguard.security;

import android.net.Uri;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class UrlThreatScanner {

    private static final Pattern URL_PATTERN =
            Pattern.compile(
                    "(?i)(?<![@\\w])((?:https?://|www\\.)[^\\s<>']+"
                            + "|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}"
                            + "(?::\\d{1,5})?(?:/[^\\s<>']*)?)");

    private static final Set<String> SHORTENERS =
            new HashSet<>(Arrays.asList(
                    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
                    "is.gd", "cutt.ly", "ow.ly", "rb.gy",
                    "shorturl.at"
            ));

    private static final Set<String> REVIEW_TLDS =
            new HashSet<>(Arrays.asList(
                    "zip", "mov", "top", "click", "work",
                    "support", "country", "kim"
            ));

    private static final String[] ACCOUNT_WORDS = {
            "login", "verify", "verification", "secure",
            "account", "password", "wallet", "banking",
            "update", "signin", "payment", "confirm",
            "credential"
    };

    public List<UrlScanResult> scanText(String text) {
        List<UrlScanResult> results = new ArrayList<>();

        if (text == null || text.trim().isEmpty()) {
            return results;
        }

        Matcher matcher = URL_PATTERN.matcher(text);
        while (matcher.find()) {
            String url = matcher.group(1);

            while (!url.isEmpty()
                    && ".,;:!?)]}".indexOf(
                    url.charAt(url.length() - 1)) >= 0) {
                url = url.substring(0, url.length() - 1);
            }

            if (!url.isEmpty()) {
                results.add(scanUrl(url));
            }
        }

        return results;
    }

    public UrlScanResult scanUrl(String input) {
        String url = input == null ? "" : input.trim();
        List<String> indicators = new ArrayList<>();

        if (url.isEmpty()) {
            indicators.add("No URL was supplied.");
            return new UrlScanResult(url, false, indicators);
        }

        String normalized = url;
        if (!normalized.contains("://")
                && !normalized.regionMatches(true, 0, "javascript:", 0, 11)) {
            normalized = "https://" + normalized;
        }

        Uri uri = Uri.parse(normalized);
        String scheme = uri.getScheme();
        String host = uri.getHost();

        if (host == null || host.trim().isEmpty()) {
            indicators.add("The URL host could not be parsed.");
            return new UrlScanResult(url, true, indicators);
        }

        host = host.toLowerCase(Locale.ROOT);
        boolean highRisk = false;

        if (!"http".equalsIgnoreCase(scheme)
                && !"https".equalsIgnoreCase(scheme)) {
            indicators.add("Unexpected URL scheme.");
            highRisk = true;
        }

        if (uri.getUserInfo() != null) {
            indicators.add("The URL contains user information before the host.");
            highRisk = true;
        }

        if (host.startsWith("xn--") || host.contains(".xn--")) {
            indicators.add("The domain uses punycode; verify its spelling carefully.");
            highRisk = true;
        }

        if (isIpAddress(host)) {
            indicators.add("The URL uses an IP address instead of a domain name.");
            highRisk = true;
        }

        if ("http".equalsIgnoreCase(scheme)) {
            indicators.add("The connection uses HTTP rather than HTTPS.");
        }

        String normalizedHost = host.startsWith("www.")
                ? host.substring(4) : host;

        if (SHORTENERS.contains(normalizedHost)) {
            indicators.add("The URL uses a shortening service; its destination is hidden.");
        }

        String[] labels = host.split("\\.");
        if (labels.length >= 5) {
            indicators.add("The domain has several subdomain levels; inspect its registered domain.");
        }

        if (labels.length > 1) {
            String tld = labels[labels.length - 1];
            if (REVIEW_TLDS.contains(tld)) {
                indicators.add("The top-level domain may deserve additional review.");
            }
        }

        String lowerUrl = normalized.toLowerCase(Locale.ROOT);
        for (String word : ACCOUNT_WORDS) {
            if (lowerUrl.contains(word)) {
                indicators.add("Contains account-related wording: " + word
                        + ". This wording alone does not prove phishing.");
                break;
            }
        }

        try {
            String decoded = URLDecoder.decode(
                    lowerUrl, StandardCharsets.UTF_8.name());

            if (decoded.indexOf('\0') >= 0
                    || decoded.contains("javascript:")) {
                indicators.add("Contains suspicious encoded URL content.");
                highRisk = true;
            }
        } catch (Exception error) {
            indicators.add("URL encoding could not be decoded.");
            highRisk = true;
        }

        if (indicators.isEmpty()) {
            indicators.add("No high-risk URL pattern was identified by the local heuristic scanner.");
        }

        return new UrlScanResult(url, highRisk, indicators);
    }

    private boolean isIpAddress(String host) {
        if (host.indexOf(':') >= 0) {
            return true;
        }

        if (!host.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            return false;
        }

        String[] parts = host.split("\\.");
        for (String part : parts) {
            try {
                int value = Integer.parseInt(part);
                if (value < 0 || value > 255) {
                    return false;
                }
            } catch (NumberFormatException error) {
                return false;
            }
        }
        return true;
    }
}
