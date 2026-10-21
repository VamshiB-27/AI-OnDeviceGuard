
package com.vcs.ondeviceguard.model;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class OnDeviceSvmClassifier implements MessageClassifier {

    private static final String ASSET_NAME = "sms_android_export.json";
    private static final String EXPECTED_MODEL_TYPE =
            "word_char_tfidf_linear_svm";

    private static final Pattern WORD_PATTERN =
            Pattern.compile("[\\p{L}\\p{N}_]{2,}");

    private final ExecutorService executor =
            Executors.newSingleThreadExecutor();

    private final Map<String, Integer> wordVocabulary =
            new HashMap<>();

    private final Map<String, Integer> charVocabulary =
            new HashMap<>();

    private double[] wordIdf;
    private double[] charIdf;
    private double[] weights;

    private double intercept;
    private double threshold;

    private volatile String loadError;

    public OnDeviceSvmClassifier(Context context) {
        try {
            loadModel(context.getApplicationContext());
        } catch (Exception e) {
            loadError = "Could not load SMS model: "
                    + e.getMessage();
        }
    }

    private void loadModel(Context context) throws Exception {
        byte[] modelBytes;

        try (InputStream input =
                     context.getAssets().open(ASSET_NAME);
             ByteArrayOutputStream output =
                     new ByteArrayOutputStream()) {

            byte[] buffer = new byte[16384];
            int count;

            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
            }

            modelBytes = output.toByteArray();
        }

        JSONObject root = new JSONObject(
                new String(modelBytes, StandardCharsets.UTF_8));

        if (!EXPECTED_MODEL_TYPE.equals(
                root.getString("model_type"))) {
            throw new IllegalArgumentException(
                    "Unsupported model type");
        }

        intercept = root.getDouble("intercept");
        threshold = root.getDouble("threshold");

        weights = readDoubleArray(
                root.getJSONArray("weights"));

        JSONObject vectorizers = root
                .getJSONObject("feature_union")
                .getJSONObject("vectorizers");

        JSONObject word = vectorizers.getJSONObject("word");
        JSONObject chars = vectorizers.getJSONObject("char");

        readVocabulary(
                word.getJSONObject("vocabulary"),
                wordVocabulary);

        readVocabulary(
                chars.getJSONObject("vocabulary"),
                charVocabulary);

        wordIdf = readDoubleArray(
                word.getJSONArray("idf"));

        charIdf = readDoubleArray(
                chars.getJSONArray("idf"));

        validateVocabulary(
                wordVocabulary,
                wordIdf.length,
                "word");

        validateVocabulary(
                charVocabulary,
                charIdf.length,
                "character");

        if (weights.length !=
                wordIdf.length + charIdf.length) {
            throw new IllegalArgumentException(
                    "Weight count does not match combined vocabulary size");
        }

        if (!Double.isFinite(intercept)
                || !Double.isFinite(threshold)) {
            throw new IllegalArgumentException(
                    "Invalid model intercept or threshold");
        }

        validateFiniteArray(weights, "weights");
        validateFiniteArray(wordIdf, "word IDF");
        validateFiniteArray(charIdf, "character IDF");
    }

    private static double[] readDoubleArray(JSONArray array)
            throws Exception {

        double[] values = new double[array.length()];

        for (int i = 0; i < array.length(); i++) {
            values[i] = array.getDouble(i);
        }

        return values;
    }

    private static void readVocabulary(
            JSONObject json,
            Map<String, Integer> destination) {

        java.util.Iterator<String> keys = json.keys();

        while (keys.hasNext()) {
            String token = keys.next();
            int index = json.optInt(token, -1);

            if (index < 0) {
                throw new IllegalArgumentException(
                        "Invalid vocabulary index");
            }

            destination.put(token, index);
        }
    }

    private static void validateVocabulary(
            Map<String, Integer> vocabulary,
            int idfLength,
            String name) {

        if (vocabulary.size() != idfLength) {
            throw new IllegalArgumentException(
                    name + " vocabulary and IDF sizes differ");
        }

        boolean[] seen = new boolean[idfLength];

        for (Map.Entry<String, Integer> entry :
                vocabulary.entrySet()) {

            int index = entry.getValue();

            if (index < 0 || index >= idfLength) {
                throw new IllegalArgumentException(
                        "Invalid " + name + " feature index");
            }

            if (seen[index]) {
                throw new IllegalArgumentException(
                        "Duplicate " + name + " feature index");
            }

            seen[index] = true;
        }

        for (boolean present : seen) {
            if (!present) {
                throw new IllegalArgumentException(
                        "Non-contiguous " + name + " vocabulary");
            }
        }
    }

    private static void validateFiniteArray(
            double[] values,
            String name) {

        for (double value : values) {
            if (!Double.isFinite(value)) {
                throw new IllegalArgumentException(
                        "Non-finite value in " + name);
            }
        }
    }

    @Override
    public void classify(String message, Callback callback) {
        if (callback == null) {
            return;
        }

        if (message == null || message.trim().isEmpty()) {
            callback.onError("Enter a non-empty message.");
            return;
        }

        if (loadError != null) {
            callback.onError(loadError);
            return;
        }

        try {
            executor.execute(() -> {
                try {
                    double score = decisionScore(message);
                    boolean spam = score >= threshold;

                    List<String> indicators = new ArrayList<>();

                    indicators.add(String.format(
                            Locale.US,
                            "SVM decision score: %.6f",
                            score));

                    indicators.add(String.format(
                            Locale.US,
                            "Decision threshold: %.6f",
                            threshold));

                    indicators.add(
                            spam
                                    ? "Score is at or above the spam threshold."
                                    : "Score is below the spam threshold.");

                    callback.onSuccess(
                            new MessageClassification(
                                    spam ? "spam" : "not spam",
                                    0.0f,
                                    indicators,
                                    score));

                } catch (Exception e) {
                    callback.onError(
                            "Classification failed: "
                                    + e.getMessage());
                }
            });
        } catch (RuntimeException e) {
            callback.onError(
                    "Classifier is unavailable: " + e.getMessage());
        }
    }

    public double decisionScore(String text) {
        if (loadError != null) {
            throw new IllegalStateException(loadError);
        }

        if (text == null) {
            throw new IllegalArgumentException(
                    "Message must not be null");
        }

        String wordText = stripAccents(
                text.toLowerCase(Locale.ROOT));

        String charText = text.toLowerCase(Locale.ROOT);

        Map<Integer, Integer> wordCounts =
                countWordFeatures(wordText);

        Map<Integer, Integer> charCounts =
                countCharacterFeatures(charText);

        Map<Integer, Double> wordVector =
                tfidfAndNormalize(wordCounts, wordIdf);

        Map<Integer, Double> charVector =
                tfidfAndNormalize(charCounts, charIdf);

        double score = intercept;

        for (Map.Entry<Integer, Double> entry :
                wordVector.entrySet()) {

            int index = entry.getKey();

            score += entry.getValue() * weights[index];
        }

        int charOffset = wordIdf.length;

        for (Map.Entry<Integer, Double> entry :
                charVector.entrySet()) {

            int index = entry.getKey() + charOffset;

            score += entry.getValue() * weights[index];
        }

        return score;
    }

    private Map<Integer, Integer> countWordFeatures(
            String text) {

        List<String> tokens = new ArrayList<>();
        Matcher matcher = WORD_PATTERN.matcher(text);

        while (matcher.find()) {
            tokens.add(matcher.group());
        }

        Map<Integer, Integer> counts = new HashMap<>();

        for (String token : tokens) {
            addFeatureCount(
                    token,
                    wordVocabulary,
                    counts);
        }

        for (int i = 0; i + 1 < tokens.size(); i++) {
            String bigram =
                    tokens.get(i) + " " + tokens.get(i + 1);

            addFeatureCount(
                    bigram,
                    wordVocabulary,
                    counts);
        }

        return counts;
    }

    private Map<Integer, Integer> countCharacterFeatures(
            String text) {

        Map<Integer, Integer> counts = new HashMap<>();

        int[] codePoints = text.codePoints().toArray();

        for (int n = 3; n <= 5; n++) {
            for (int i = 0; i + n <= codePoints.length; i++) {
                String gram = new String(
                        codePoints,
                        i,
                        n);

                addFeatureCount(
                        gram,
                        charVocabulary,
                        counts);
            }
        }

        return counts;
    }

    private static void addFeatureCount(
            String feature,
            Map<String, Integer> vocabulary,
            Map<Integer, Integer> counts) {

        Integer index = vocabulary.get(feature);

        if (index != null) {
            counts.put(
                    index,
                    counts.getOrDefault(index, 0) + 1);
        }
    }

    private static Map<Integer, Double> tfidfAndNormalize(
            Map<Integer, Integer> counts,
            double[] idf) {

        Map<Integer, Double> vector = new TreeMap<>();
        double squaredNorm = 0.0;

        for (Map.Entry<Integer, Integer> entry :
                counts.entrySet()) {

            int index = entry.getKey();
            int count = entry.getValue();

            double tf = 1.0 + Math.log(count);
            double value = tf * idf[index];

            vector.put(index, value);
            squaredNorm += value * value;
        }

        if (squaredNorm > 0.0) {
            double norm = Math.sqrt(squaredNorm);

            for (Map.Entry<Integer, Double> entry :
                    vector.entrySet()) {
                entry.setValue(entry.getValue() / norm);
            }
        }

        return vector;
    }

    private static String stripAccents(String input) {
        String normalized = Normalizer.normalize(
                input,
                Normalizer.Form.NFKD);

        StringBuilder result = new StringBuilder();

        for (int offset = 0; offset < normalized.length();) {
            int codePoint = normalized.codePointAt(offset);
            int type = Character.getType(codePoint);

            if (type != Character.NON_SPACING_MARK
                    && type != Character.COMBINING_SPACING_MARK
                    && type != Character.ENCLOSING_MARK) {
                result.appendCodePoint(codePoint);
            }

            offset += Character.charCount(codePoint);
        }

        return result.toString();
    }

    public double getThreshold() {
        return threshold;
    }

    public boolean isModelLoaded() {
        return loadError == null
                && weights != null
                && wordIdf != null
                && charIdf != null;
    }

    public String getLoadError() {
        return loadError;
    }

    public void shutdown() {
        executor.shutdown();
    }
}
