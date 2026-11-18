package com.vcs.ondeviceguard.security;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Set;
import java.util.HashSet;

public final class UrlFeatureExtractor {

    private static final String[] SUSPICIOUS_TOKENS = {
            "login", "verify", "verification", "secure", "account",
            "password", "wallet", "banking", "update",
            "signin", "payment", "confirm", "credential", "free",
            "gift", "bonus", "urgent", "suspend", "unlock", "support",
            "auth", "webscr"
    };

    private static final String[] HOST_LOGIN_WORDS = {
            "login", "verify", "verification", "secure", "account",
            "signin", "password", "banking", "wallet",
            "payment", "credential", "auth"
    };

    private UrlFeatureExtractor() {
    }

    public static double[] extract(String input) {
        if (input == null || input.trim().isEmpty()) {
            throw new IllegalArgumentException("URL must not be empty.");
        }

        String original = input.trim();
        String normalized = original;
        if (!normalized.matches("(?i)^[a-z][a-z0-9+.-]*://.*$")
                && !normalized.regionMatches(true, 0, "javascript:", 0, 11)) {
            normalized = "https://" + normalized;
        }

        URI uri;
        try {
            uri = new URI(normalized);
        } catch (URISyntaxException error) {
            throw new IllegalArgumentException("URL could not be parsed.", error);
        }

        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            String authority = uri.getRawAuthority();
            if (authority != null) {
                int at = authority.lastIndexOf('@');
                if (at >= 0) {
                    authority = authority.substring(at + 1);
                }
                if (authority.startsWith("[") && authority.contains("]")) {
                    host = authority.substring(1, authority.indexOf(']'));
                } else {
                    int colon = authority.lastIndexOf(':');
                    host = colon > 0 && authority.substring(colon + 1).matches("\\d+")
                            ? authority.substring(0, colon) : authority;
                }
            }
        }

        if (host == null) {
            throw new IllegalArgumentException("URL host could not be parsed.");
        }

        host = host.toLowerCase(Locale.ROOT);
        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) {
            path = "";
        }
        String query = uri.getRawQuery();
        if (query == null) {
            query = "";
        }

        String lowerUrl = normalized.toLowerCase(Locale.ROOT);
        int digits = 0;
        for (int i = 0; i < original.length(); i++) {
            if (Character.isDigit(original.charAt(i))) {
                digits++;
            }
        }

        int suspiciousTokenCount = 0;
        for (String token : SUSPICIOUS_TOKENS) {
            if (lowerUrl.contains(token)) {
                suspiciousTokenCount++;
            }
        }

        boolean hostHasLoginWords = false;
        for (String token : HOST_LOGIN_WORDS) {
            if (host.contains(token)) {
                hostHasLoginWords = true;
                break;
            }
        }

        int labels = host.indexOf(':') >= 0 ? 1 : host.split("\\.", -1).length;
        int subdomainCount = Math.max(0, labels - 2);
        int pathDepth = 0;
        for (String segment : path.split("/")) {
            if (!segment.isEmpty()) {
                pathDepth++;
            }
        }

        double[] features = new double[18];
        features[0] = original.length();
        features[1] = host.length();
        features[2] = path.length();
        features[3] = query.length();
        features[4] = count(original, '.');
        features[5] = count(original, '-');
        features[6] = count(original, '@');
        features[7] = original.isEmpty() ? 0.0 : (double) digits / original.length();
        features[8] = subdomainCount;
        features[9] = "https".equalsIgnoreCase(uri.getScheme()) ? 1.0 : 0.0;
        features[10] = isIpAddress(host) ? 1.0 : 0.0;
        features[11] = uri.getPort() >= 0 || hasExplicitPort(uri) ? 1.0 : 0.0;
        features[12] = count(original, '%');
        features[13] = path.contains("//") ? 1.0 : 0.0;
        features[14] = suspiciousTokenCount;
        features[15] = hostHasLoginWords ? 1.0 : 0.0;
        features[16] = entropy(host);
        features[17] = pathDepth;
        return features;
    }

    private static int count(String value, char character) {
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == character) {
                count++;
            }
        }
        return count;
    }

    private static boolean hasExplicitPort(URI uri) {
        String authority = uri.getRawAuthority();
        if (authority == null) {
            return false;
        }
        int colon = authority.lastIndexOf(':');
        if (colon < 0 || colon == authority.length() - 1) {
            return false;
        }
        return authority.substring(colon + 1).matches("\\d+");
    }

    private static boolean isIpAddress(String host) {
        if (host.indexOf(':') >= 0) {
            return true;
        }
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (!part.matches("\\d{1,3}")) {
                return false;
            }
            int value;
            try {
                value = Integer.parseInt(part);
            } catch (NumberFormatException error) {
                return false;
            }
            if (value > 255) {
                return false;
            }
        }
        return true;
    }

    private static double entropy(String value) {
        if (value.isEmpty()) {
            return 0.0;
        }
        int[] counts = new int[Character.MAX_VALUE + 1];
        for (int i = 0; i < value.length(); i++) {
            counts[value.charAt(i)]++;
        }
        double result = 0.0;
        for (int count : counts) {
            if (count == 0) {
                continue;
            }
            double probability = (double) count / value.length();
            result -= probability * (Math.log(probability) / Math.log(2.0));
        }
        return result;
    }
}
