package com.vcs.ondeviceguard.model;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public final class NetworkFlowClassifier {

    private static final String MODEL_FILE = "network_model.json";
    private static final int FEATURE_COUNT = 20;

    private final double[] medians = new double[FEATURE_COUNT];
    private final double[] means = new double[FEATURE_COUNT];
    private final double[] scales = new double[FEATURE_COUNT];
    private final double[] coefficients = new double[FEATURE_COUNT];

    private double intercept;
    private double threshold;
    private boolean closed;

    public NetworkFlowClassifier(Context context) throws Exception {
        loadModel(context);
    }

    private void loadModel(Context context) throws Exception {

        byte[] bytes;

        try (
                InputStream input =
                        context.getAssets().open(MODEL_FILE);

                ByteArrayOutputStream output =
                        new ByteArrayOutputStream()
        ) {
            byte[] buffer = new byte[8192];
            int count;

            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
            }

            bytes = output.toByteArray();
        }

        JSONObject root = new JSONObject(
                new String(bytes, StandardCharsets.UTF_8));

        if (!"standard_scaler_logistic_regression".equals(
                root.getString("model_type"))) {
            throw new IllegalArgumentException(
                    "Unsupported network model type");
        }

        JSONArray medianArray =
                root.getJSONArray("imputation_medians");

        JSONArray meanArray =
                root.getJSONArray("scaler_mean");

        JSONArray scaleArray =
                root.getJSONArray("scaler_scale");

        JSONArray coefficientArray =
                root.getJSONArray("coefficients");

        if (medianArray.length() != FEATURE_COUNT
                || meanArray.length() != FEATURE_COUNT
                || scaleArray.length() != FEATURE_COUNT
                || coefficientArray.length() != FEATURE_COUNT
                || root.getJSONArray("feature_names").length()
                != FEATURE_COUNT) {

            throw new IllegalArgumentException(
                    "Network model must contain exactly 20 features");
        }

        readArray(medianArray, medians);
        readArray(meanArray, means);
        readArray(scaleArray, scales);
        readArray(coefficientArray, coefficients);

        intercept = root.getDouble("intercept");
        threshold = root.getDouble("threshold");

        if (!Double.isFinite(intercept)
                || !Double.isFinite(threshold)) {
            throw new IllegalArgumentException(
                    "Invalid model parameters");
        }

        for (double scale : scales) {
            if (!Double.isFinite(scale) || scale <= 0) {
                throw new IllegalArgumentException(
                        "Invalid scaler value");
            }
        }
    }

    private void readArray(
            JSONArray source,
            double[] destination) throws Exception {

        for (int i = 0; i < destination.length; i++) {
            destination[i] = source.getDouble(i);

            if (!Double.isFinite(destination[i])) {
                throw new IllegalArgumentException(
                        "Invalid model parameter at index " + i);
            }
        }
    }

    public NetworkFlowResult classify(double[] features) {

        if (closed) {
            throw new IllegalStateException("Network classifier is closed.");
        }

        if (features == null
                || features.length != FEATURE_COUNT) {
            throw new IllegalArgumentException(
                    "Exactly 20 network features are required");
        }

        double score = intercept;

        for (int i = 0; i < FEATURE_COUNT; i++) {

            double value = features[i];

            if (!Double.isFinite(value)) {
                value = medians[i];
            }

            double scaled =
                    (value - means[i]) / scales[i];

            score += coefficients[i] * scaled;
        }

        if (!Double.isFinite(score)) {
            throw new IllegalStateException(
                    "Invalid network decision score");
        }

        double probability;

        if (score >= 0) {
            probability = 1.0 / (1.0 + Math.exp(-score));
        } else {
            double exponential = Math.exp(score);
            probability = exponential / (1.0 + exponential);
        }

        String label =
                score >= threshold ? "ATTACK" : "BENIGN";

        return new NetworkFlowResult(
                label,
                score,
                probability);
    }
    public void close() {
        if (closed) {
            return;
        }
        java.util.Arrays.fill(medians, 0.0);
        java.util.Arrays.fill(means, 0.0);
        java.util.Arrays.fill(scales, 0.0);
        java.util.Arrays.fill(coefficients, 0.0);
        intercept = 0.0;
        threshold = 0.0;
        closed = true;
    }
}