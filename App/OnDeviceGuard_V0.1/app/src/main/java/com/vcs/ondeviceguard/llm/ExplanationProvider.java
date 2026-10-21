
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
}
