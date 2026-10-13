
package com.vcs.ondeviceguard.model;

public interface MessageClassifier {

    interface Callback {
        void onSuccess(MessageClassification result);

        void onError(String message);
    }

    void classify(String message, Callback callback);
}
