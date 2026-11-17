package com.vcs.ondeviceguard.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class UrlScanResult {

    private final String url;
    private final boolean suspicious;
    private final List<String> indicators;

    public UrlScanResult(
            String url,
            boolean suspicious,
            List<String> indicators) {

        this.url = url;
        this.suspicious = suspicious;

        this.indicators = Collections.unmodifiableList(
                new ArrayList<>(indicators));
    }

    public String getUrl() {
        return url;
    }

    public boolean isSuspicious() {
        return suspicious;
    }

    public List<String> getIndicators() {
        return indicators;
    }
}