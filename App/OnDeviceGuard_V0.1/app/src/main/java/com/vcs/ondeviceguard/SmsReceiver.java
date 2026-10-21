
package com.vcs.ondeviceguard;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Telephony;
import android.telephony.SmsMessage;
import android.util.Log;

import com.vcs.ondeviceguard.model.DemoMessageClassifier;
import com.vcs.ondeviceguard.model.MessageClassification;
import com.vcs.ondeviceguard.model.MessageClassifier;

public class SmsReceiver extends BroadcastReceiver {

    private static final String TAG = "SmsReceiver";
    private static final String CHANNEL_ID = "sms_threat_alerts";

    @Override
    public void onReceive(Context context, Intent intent) {

        if (intent == null
                || !Telephony.Sms.Intents.SMS_RECEIVED_ACTION
                .equals(intent.getAction())) {
            return;
        }

        SmsMessage[] messages =
                Telephony.Sms.Intents.getMessagesFromIntent(intent);

        if (messages == null || messages.length == 0) {
            return;
        }

        StringBuilder messageBuilder = new StringBuilder();

        for (SmsMessage sms : messages) {
            if (sms != null && sms.getMessageBody() != null) {
                messageBuilder.append(sms.getMessageBody());
            }
        }

        String messageText = messageBuilder.toString().trim();

        if (messageText.isEmpty()) {
            return;
        }

        Context appContext = context.getApplicationContext();

        Log.d(TAG, "Incoming SMS received for local analysis.");

        createNotificationChannel(appContext);

        // Keep the receiver active while background classification runs.
        PendingResult pendingResult = goAsync();

        // Temporary demo implementation; replace with the trained model later.
        DemoMessageClassifier classifier =
                new DemoMessageClassifier();

        try {
            classifier.classify(
                    messageText,
                    new MessageClassifier.Callback() {

                        @Override
                        public void onSuccess(
                                MessageClassification result) {

                            try {
                                Log.d(TAG,
                                        "Classification: "
                                                + result.getLabel());

                                if (result.isSuspicious()) {
                                    showNotification(
                                            appContext, result);
                                }

                            } catch (Exception e) {
                                Log.e(TAG,
                                        "Could not process SMS result", e);
                            } finally {
                                classifier.shutdown();
                                pendingResult.finish();
                            }
                        }

                        @Override
                        public void onError(String error) {
                            try {
                                Log.e(TAG,
                                        "Classification failed: " + error);
                            } finally {
                                classifier.shutdown();
                                pendingResult.finish();
                            }
                        }
                    });

        } catch (Exception e) {
            Log.e(TAG, "Could not start SMS classification", e);
            classifier.shutdown();
            pendingResult.finish();
        }
    }

    private void createNotificationChannel(Context context) {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

            NotificationChannel channel =
                    new NotificationChannel(
                            CHANNEL_ID,
                            "SMS Threat Alerts",
                            NotificationManager.IMPORTANCE_HIGH);

            channel.setDescription(
                    "Alerts for potentially suspicious SMS messages");

            NotificationManager manager =
                    context.getSystemService(NotificationManager.class);

            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    private void showNotification(
            Context context,
            MessageClassification result) {

        if (Build.VERSION.SDK_INT >= 33
                && context.checkSelfPermission(
                Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {

            Log.w(TAG, "Notification permission not granted");
            return;
        }

        NotificationManager manager =
                (NotificationManager) context.getSystemService(
                        Context.NOTIFICATION_SERVICE);

        if (manager == null) {
            return;
        }

        String label = result.getLabel().toUpperCase(
                java.util.Locale.ROOT);

        String notificationText =
                "A potentially suspicious SMS was detected. "
                        + "Review the message before taking action.";

        Notification.Builder builder;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(context, CHANNEL_ID);
        } else {
            builder = new Notification.Builder(context);
        }

        Notification notification = builder
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("OnDeviceGuard: " + label)
                .setContentText(notificationText)
                .setStyle(new Notification.BigTextStyle()
                        .bigText(notificationText))
                .setAutoCancel(true)
                .build();

        try {
            int notificationId =
                    (int) (System.currentTimeMillis() & 0x7fffffff);

            manager.notify(notificationId, notification);

        } catch (SecurityException e) {
            Log.e(TAG, "Unable to post notification", e);
        }
    }
}
