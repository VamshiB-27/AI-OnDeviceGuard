package com.vcs.ondeviceguard.security;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class UrlPhishingClassifier {

    private static final String MODEL_FILE = "url_model.json";
    private static final int FEATURE_COUNT = 18;

    private final double[] means = new double[FEATURE_COUNT];
    private final double[] scales = new double[FEATURE_COUNT];
    private final double[] coefficients = new double[FEATURE_COUNT];

    private double intercept;
    private double threshold;
    private boolean closed;

    public static final class Result {
        private final String label;
        private final double score;
        private final double probability;
        private final double[] features;

        Result(String label, double score, double probability, double[] features) {
            this.label = label;
            this.score = score;
            this.probability = probability;
            this.features = features.clone();
        }

        public String getLabel() {
            return label;
        }

        public double getScore() {
            return score;
        }

        public double getProbability() {
            return probability;
        }

        public double[] getFeatures() {
            return features.clone();
        }

        public boolean isPhishing() {
            return "phishing".equals(label);
        }
    }

    public UrlPhishingClassifier(Context context) throws Exception {
        loadModel(context);
    }

    private void loadModel(Context context) throws Exception {
        byte[] bytes;
        try (InputStream input = context.getAssets().open(MODEL_FILE);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
            }
            bytes = output.toByteArray();
        }

        JSONObject root = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
        if (!"standard_scaler_logistic_regression".equals(root.getString("model_type"))) {
            throw new IllegalArgumentException("Unsupported URL model type.");
        }

        JSONArray names = root.getJSONArray("feature_names");
        JSONArray meanArray = root.getJSONArray("scaler_mean");
        JSONArray scaleArray = root.getJSONArray("scaler_scale");
        JSONArray coefficientArray = root.getJSONArray("coefficients");

        if (names.length() != FEATURE_COUNT
                || meanArray.length() != FEATURE_COUNT
                || scaleArray.length() != FEATURE_COUNT
                || coefficientArray.length() != FEATURE_COUNT) {
            throw new IllegalArgumentException("URL model must contain exactly 18 features.");
        }

        String[] expectedNames = {
                "url_length", "host_length", "path_length", "query_length",
                "dot_count", "hyphen_count", "at_count", "digit_ratio",
                "subdomain_count", "uses_https", "has_ip_host", "has_port",
                "percent_count", "double_slash_path", "suspicious_token_count",
                "host_has_brand_login_words", "host_entropy", "path_depth"
        };

        for (int i = 0; i < FEATURE_COUNT; i++) {
            if (!expectedNames[i].equals(names.getString(i))) {
                throw new IllegalArgumentException(
                        "URL model feature order mismatch at index " + i);
            }
            means[i] = meanArray.getDouble(i);
            scales[i] = scaleArray.getDouble(i);
            coefficients[i] = coefficientArray.getDouble(i);
            if (!Double.isFinite(means[i])
                    || !Double.isFinite(scales[i])
                    || scales[i] <= 0.0
                    || !Double.isFinite(coefficients[i])) {
                throw new IllegalArgumentException("Invalid URL model parameter at index " + i);
            }
        }

        intercept = root.getDouble("intercept");
        threshold = root.getDouble("threshold");
        if (!Double.isFinite(intercept) || !Double.isFinite(threshold)) {
            throw new IllegalArgumentException("Invalid URL model intercept or threshold.");
        }
    }

    public Result classify(String url) {
        if (closed) {
            throw new IllegalStateException("URL classifier is closed.");
        }

        double[] features = UrlFeatureExtractor.extract(url);
        double score = intercept;

        for (int i = 0; i < FEATURE_COUNT; i++) {
            score += coefficients[i] * ((features[i] - means[i]) / scales[i]);
        }

        if (!Double.isFinite(score)) {
            throw new IllegalStateException("URL model produced a non-finite score.");
        }

        double probability;
        if (score >= 0.0) {
            probability = 1.0 / (1.0 + Math.exp(-score));
        } else {
            double exponential = Math.exp(score);
            probability = exponential / (1.0 + exponential);
        }

        return new Result(
                score >= threshold ? "phishing" : "not phishing",
                score,
                probability,
                features);
    }

    public void close() {
        if (closed) {
            return;
        }
        Arrays.fill(means, 0.0);
        Arrays.fill(scales, 0.0);
        Arrays.fill(coefficients, 0.0);
        intercept = 0.0;
        threshold = 0.0;
        closed = true;
    }
}
