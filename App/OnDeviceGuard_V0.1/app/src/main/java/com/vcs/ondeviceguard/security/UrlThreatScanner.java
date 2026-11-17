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
                    "(?i)\\b((?:https?://|www\\.)[^\\s<>\"']+)"
            );

    private static final Set<String> SHORTENERS =
            new HashSet<>(Arrays.asList(
                    "bit.ly",
                    "tinyurl.com",
                    "t.co",
                    "goo.gl",
                    "is.gd",
                    "cutt.ly",
                    "ow.ly",
                    "rb.gy",
                    "shorturl.at"
            ));

    private static final Set<String> SUSPICIOUS_TLDS =
            new HashSet<>(Arrays.asList(
                    "zip",
                    "mov",
                    "top",
                    "click",
                    "work",
                    "support",
                    "country",
                    "kim"
            ));

    private static final String[] SUSPICIOUS_WORDS = {
            "login",
            "verify",
            "verification",
            "secure",
            "account",
            "password",
            "wallet",
            "banking",
            "update",
            "signin",
            "payment",
            "confirm",
            "credential"
    };

    public List<UrlScanResult> scanText(String text) {

        List<UrlScanResult> results =
                new ArrayList<>();

        if (text == null || text.trim().isEmpty()) {
            return results;
        }

        Matcher matcher =
                URL_PATTERN.matcher(text);

        while (matcher.find()) {

            String url = matcher.group(1);

            while (!url.isEmpty()
                    && ".,;:!?)]}".indexOf(
                    url.charAt(url.length() - 1)) >= 0) {

                url = url.substring(
                        0,
                        url.length() - 1);
            }

            if (!url.isEmpty()) {
                results.add(scanUrl(url));
            }
        }

        return results;
    }

    public UrlScanResult scanUrl(String input) {

        String url =
                input == null ? "" : input.trim();

        List<String> indicators =
                new ArrayList<>();

        if (url.isEmpty()) {

            indicators.add("Empty URL");

            return new UrlScanResult(
                    url,
                    true,
                    indicators);
        }

        String normalized = url;

        if (normalized.regionMatches(
                true, 0, "www.", 0, 4)) {

            normalized = "https://" + normalized;
        }

        Uri uri = Uri.parse(normalized);

        String scheme = uri.getScheme();
        String host = uri.getHost();

        if (host == null || host.trim().isEmpty()) {

            indicators.add(
                    "Invalid or unrecognized URL host");

            return new UrlScanResult(
                    url,
                    true,
                    indicators);
        }

        host = host.toLowerCase(Locale.ROOT);

        if (!"http".equalsIgnoreCase(scheme)
                && !"https".equalsIgnoreCase(scheme)) {

            indicators.add(
                    "Unexpected URL scheme");
        }

        if ("http".equalsIgnoreCase(scheme)) {

            indicators.add(
                    "Uses unencrypted HTTP");
        }

        if (uri.getUserInfo() != null) {

            indicators.add(
                    "Contains user information before the host");
        }

        if (host.startsWith("xn--")
                || host.contains(".xn--")) {

            indicators.add(
                    "Contains an internationalized punycode domain");
        }

        if (isIpAddress(host)) {

            indicators.add(
                    "Uses an IP address instead of a normal domain");
        }

        String normalizedHost = host;

        if (normalizedHost.startsWith("www.")) {
            normalizedHost =
                    normalizedHost.substring(4);
        }

        if (SHORTENERS.contains(normalizedHost)) {

            indicators.add(
                    "Uses a URL shortening service");
        }

        String[] labels = host.split("\\.");

        if (labels.length >= 5) {

            indicators.add(
                    "Contains an unusually deep subdomain structure");
        }

        if (labels.length > 1) {

            String tld =
                    labels[labels.length - 1];

            if (SUSPICIOUS_TLDS.contains(tld)) {

                indicators.add(
                        "Uses a TLD that warrants additional checking");
            }
        }

        String fullUrl =
                normalized.toLowerCase(Locale.ROOT);

        for (String word : SUSPICIOUS_WORDS) {

            if (fullUrl.contains(word)) {

                indicators.add(
                        "Contains a sensitive-account keyword: "
                                + word);

                break;
            }
        }

        try {

            String decoded =
                    URLDecoder.decode(
                            fullUrl,
                            StandardCharsets.UTF_8.name());

            if (decoded.indexOf('\0') >= 0
                    || decoded.contains("javascript:")) {

                indicators.add(
                        "Contains suspicious encoded URL content");
            }

        } catch (Exception error) {

            indicators.add(
                    "URL encoding could not be decoded");
        }

        return new UrlScanResult(
                url,
                !indicators.isEmpty(),
                indicators);
    }

    private boolean isIpAddress(String host) {

        if (!host.matches(
                "\\d{1,3}(\\.\\d{1,3}){3}")) {

            return host.contains(":");
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