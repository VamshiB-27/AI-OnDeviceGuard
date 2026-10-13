
package com.vcs.ondeviceguard.llm;

import com.vcs.ondeviceguard.model.MessageClassification;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DemoExplanationProvider
        implements ExplanationProvider {

    private final ExecutorService executor =
            Executors.newSingleThreadExecutor();

    @Override
    public void explain(
            String originalMessage,
            MessageClassification classification,
            Callback callback) {

        executor.execute(() -> {
            try {
                StringBuilder result = new StringBuilder();

                if (classification.isSuspicious()) {
                    result.append(
                            "This message was flagged as potentially suspicious.\n\n");

                    result.append("Why it was flagged:\n");

                    if (classification.getIndicators().isEmpty()) {
                        result.append(
                                "No specific indicators were provided.\n");
                    } else {
                        for (String indicator :
                                classification.getIndicators()) {

                            result.append("- ")
                                    .append(indicator)
                                    .append("\n");
                        }
                    }

                    result.append(
                                    "\nRecommended actions:\n")
                            .append("- Do not open unexpected links.\n")
                            .append("- Verify the sender independently.\n")
                            .append("- Never share an OTP or password.");

                } else {
                    result.append(
                                    "The demo classifier did not flag this message.\n\n")
                            .append(
                                    "This does not guarantee that the message is safe. ")
                            .append(
                                    "Check unexpected requests and links carefully.");
                }

                callback.onSuccess(result.toString());

            } catch (Exception e) {
                callback.onError(
                        "Demo explanation failed.");
            }
        });
    }

    public void shutdown() {
        executor.shutdown();
    }
}
