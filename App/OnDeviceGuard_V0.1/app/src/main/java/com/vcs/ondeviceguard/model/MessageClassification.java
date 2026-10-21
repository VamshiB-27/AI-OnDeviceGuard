
package com.vcs.ondeviceguard.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MessageClassification {

    private final String label;
    private final float confidence;
    private final double decisionScore;
    private final List<String> indicators;

    public MessageClassification(
            String label,
            float confidence,
            List<String> indicators) {

        this(label, confidence, indicators, Double.NaN);
    }

    public MessageClassification(
            String label,
            float confidence,
            List<String> indicators,
            double decisionScore) {

        this.label = label == null ? "unknown" : label;
        this.confidence = Math.max(
                0.0f,
                Math.min(1.0f, confidence));

        this.decisionScore = decisionScore;

        this.indicators = indicators == null
                ? Collections.emptyList()
                : Collections.unmodifiableList(
                new ArrayList<>(indicators));
    }

    public String getLabel() {
        return label;
    }

    public float getConfidence() {
        return confidence;
    }

    public double getDecisionScore() {
        return decisionScore;
    }

    public List<String> getIndicators() {
        return indicators;
    }

    public boolean isSuspicious() {
        return "scam".equalsIgnoreCase(label)
                || "suspicious".equalsIgnoreCase(label)
                || "spam".equalsIgnoreCase(label)
                || "phishing".equalsIgnoreCase(label);
    }
}
