
package com.vcs.ondeviceguard.llm;

import com.vcs.ondeviceguard.model.MessageClassification;

public interface ExplanationProvider {

    interface Callback {
        void onSuccess(String explanation);

        void onError(String message);
    }

    void explain(
            String originalMessage,
            MessageClassification classification,
            Callback callback);

    default void explainSecurityEvent(
            String type,
            String evidence,
            String classification,
            java.util.List<String> indicators,
            Callback callback) {
        if (callback != null) {
            callback.onError("Generic security-event explanations are not supported by this provider.");
        }
    }
}
