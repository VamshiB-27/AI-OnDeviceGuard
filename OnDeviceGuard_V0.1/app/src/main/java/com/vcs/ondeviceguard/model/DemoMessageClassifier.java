
package com.vcs.ondeviceguard.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DemoMessageClassifier implements MessageClassifier {

    private final ExecutorService executor =
            Executors.newSingleThreadExecutor();

    @Override
    public void classify(String message, Callback callback) {

        if (message == null || message.trim().isEmpty()) {
            callback.onError("Message is empty.");
            return;
        }

        executor.execute(() -> {
            try {
                String text = message.toLowerCase(Locale.ROOT);

                int riskScore = 0;
                List<String> indicators = new ArrayList<>();

                if (containsAny(text,
                        "urgent",
                        "immediately",
                        "act now",
                        "account will be blocked",
                        "account suspended",
                        "verify your account",
                        "within 24 hours")) {

                    riskScore += 2;
                    indicators.add("Urgent or threatening wording");
                }

                if (containsAny(text,
                        "otp",
                        "one-time password",
                        "one time password",
                        "share your password",
                        "share your pin",
                        "send your pin",
                        "cvv",
                        "bank details")) {

                    riskScore += 3;
                    indicators.add(
                            "Requests sensitive information or credentials");
                }

                if (containsAny(text,
                        "claim your prize",
                        "you have won",
                        "won a lottery",
                        "claim reward",
                        "free gift",
                        "cashback reward")) {

                    riskScore += 2;
                    indicators.add(
                            "Prize or reward-related wording");
                }

                if (containsAny(text,
                        "http://",
                        "https://",
                        "bit.ly/",
                        "tinyurl.com/",
                        "t.co/")) {

                    riskScore += 2;
                    indicators.add("Contains a link");
                }

                if (containsAny(text,
                        "send money",
                        "transfer money",
                        "pay immediately",
                        "account verification fee")) {

                    riskScore += 2;
                    indicators.add(
                            "Requests payment or a money transfer");
                }

                String label;
                float confidence;

                if (riskScore >= 5) {
                    label = "scam";
                    confidence = 0.90f;
                } else if (riskScore >= 2) {
                    label = "suspicious";
                    confidence = 0.70f;
                } else {
                    label = "legitimate";
                    confidence = 0.75f;
                }

                MessageClassification result =
                        new MessageClassification(
                                label,
                                confidence,
                                indicators);

                callback.onSuccess(result);

            } catch (Exception e) {
                callback.onError(
                        "Demo classification failed.");
            }
        });
    }

    private boolean containsAny(
            String text,
            String... keywords) {

        for (String keyword : keywords) {
            if (text.contains(keyword)) {
                return true;
            }
        }

        return false;
    }

    public void shutdown() {
        executor.shutdown();
    }
}
