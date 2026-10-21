package com.vcs.ondeviceguard.model;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collections;
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

    private static final double THRESHOLD = -0.1402412876876613;
    private static final String ASSET_NAME = "sms_android_export.json";

    private static final Pattern WORD_PATTERN =
            Pattern.compile("[\\p{L}\\p{N}_]{2,}");

    private final ExecutorService executor =
            Executors.newSingleThreadExecutor();

    private final Map<String, Integer> wordVocabulary = new HashMap<>();
    private final Map<String, Integer> charVocabulary = new HashMap<>();

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
            loadError = "Could not load the exported SMS model: "
                    + e.getMessage();
        }
    }

    private void loadModel(Context context) throws Exception {
        byte[] bytes;

        try (InputStream input =
                     context.getAssets().open(ASSET_NAME);
             ByteArrayOutputStream output =
                     new ByteArrayOutputStream()) {

            byte[] buffer = new byte[16384];
            int count;

            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
            }

            bytes = output.toByteArray();
        }

        JSONObject root = new JSONObject(
                new String(bytes, StandardCharsets.UTF_8));

        if (!"word_char_tfidf_linear_svm".equals(
                root.getString("model_type"))) {
            throw new IllegalArgumentException(
                    "Unexpected model type");
        }

        intercept = root.getDouble("intercept");
        threshold = root.getDouble("threshold");
        weights = readDoubleArray(root.getJSONArray("weights"));

        JSONObject vectorizers =
                root.getJSONObject("feature_union")
                        .getJSONObject("vectorizers");

        JSONObject word = vectorizers.getJSONObject("word");
        JSONObject chars = vectorizers.getJSONObject("char");

        readVocabulary(
                word.getJSONObject("vocabulary"),
                wordVocabulary);

        readVocabulary(
                chars.getJSONObject("vocabulary"),
                charVocabulary);

        wordIdf = readDoubleArray(word.getJSONArray("idf"));
        charIdf = readDoubleArray(chars.getJSONArray("idf"));

        if (weights.length !=
                wordVocabulary.size() + charVocabulary.size()) {
            throw new IllegalArgumentException(
                    "Model weight and vocabulary sizes do not match");
        }

        if (wordIdf.length != wordVocabulary.size()
                || charIdf.length != charVocabulary.size()) {
            throw new IllegalArgumentException(
                    "Model IDF and vocabulary sizes do not match");
        }
    }

    private static double[] readDoubleArray(JSONArray array)
            throws Exception {
        double[] result = new double[array.length()];

        for (int i = 0; i < array.length(); i++) {
            result[i] = array.getDouble(i);
        }

        return result;
    }

    private static void readVocabulary(
            JSONObject json,
            Map<String, Integer> destination) {

        java.util.Iterator<String> keys = json.keys();

        while (keys.hasNext()) {
            String token = keys.next();
            destination.put(token, json.optInt(token, -1));
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
                                ? "The score is at or above the spam threshold."
                                : "The score is below the spam threshold.");

                callback.onSuccess(
                        new MessageClassification(
                                spam ? "spam" : "not spam",
                                0.0f,
                                indicators,
                                score));
            } catch (Exception e) {
                callback.onError(
                        "Classification failed: " + e.getMessage());
            }
        });
    }

    public double decisionScore(String text) {
        String wordText = stripAccents(text.toLowerCase(Locale.ROOT));
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

    private Map<Integer, Integer> countWordFeatures(String text) {
        List<String> tokens = new ArrayList<>();
        Matcher matcher = WORD_PATTERN.matcher(text);

        while (matcher.find()) {
            tokens.add(matcher.group());
        }

        Map<Integer, Integer> counts = new HashMap<>();

        for (String token : tokens) {
            addFeatureCount(token, wordVocabulary, counts);
        }

        for (int i = 0; i + 1 < tokens.size(); i++) {
            addFeatureCount(
                    tokens.get(i) + " " + tokens.get(i + 1),
                    wordVocabulary,
                    counts);
        }

        return counts;
    }

    private Map<Integer, Integer> countCharacterFeatures(
            String text) {

        Map<Integer, Integer> counts = new HashMap<>();

        for (int n = 3; n <= 5; n++) {
            for (int i = 0; i + n <= text.length(); i++) {
                String gram = text.substring(i, i + n);
                addFeatureCount(gram, charVocabulary, counts);
            }
        }

        return counts;
    }

    private static void addFeatureCount(
            String feature,
            Map<String, Integer> vocabulary,
            Map<Integer, Integer> counts) {

        Integer index = vocabulary.get(feature);

        if (index != null && index >= 0) {
            counts.put(index, counts.getOrDefault(index, 0) + 1);
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
                input, Normalizer.Form.NFKD);

        StringBuilder result = new StringBuilder();

        for (int i = 0; i < normalized.length(); i++) {
            char c = normalized.charAt(i);
            int type = Character.getType(c);

            if (type != Character.NON_SPACING_MARK
                    && type != Character.COMBINING_SPACING_MARK
                    && type != Character.ENCLOSING_MARK) {
                result.append(c);
            }
        }

        return result.toString();
    }

    public void shutdown() {
        executor.shutdown();
    }
}