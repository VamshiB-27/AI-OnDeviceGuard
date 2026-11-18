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
import android.telephony.SmsMessage;
import android.provider.Telephony;
import android.util.Log;

import com.vcs.ondeviceguard.model.MessageClassification;
import com.vcs.ondeviceguard.model.MessageClassifier;
import com.vcs.ondeviceguard.model.OnDeviceSvmClassifier;
import com.vcs.ondeviceguard.security.UrlScanResult;
import com.vcs.ondeviceguard.security.UrlThreatScanner;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class SmsReceiver extends BroadcastReceiver {

    private static final String TAG = "OnDeviceGuardSMS";
    private static final String CHANNEL_ID = "threat_alerts";

    private static final ExecutorService EXECUTOR =
            Executors.newSingleThreadExecutor();

    private static final Object MODEL_LOCK = new Object();

    private static volatile OnDeviceSvmClassifier sharedClassifier;

    private static final UrlThreatScanner URL_SCANNER =
            new UrlThreatScanner();

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

        StringBuilder builder = new StringBuilder();
        String sender = "Unknown";

        for (SmsMessage message : messages) {

            if (message == null) {
                continue;
            }

            String body = message.getMessageBody();

            if (body != null) {
                builder.append(body);
            }

            String address =
                    message.getOriginatingAddress();

            if (address != null) {
                sender = address;
            }
        }

        String smsText = builder.toString().trim();

        if (smsText.isEmpty()) {
            return;
        }

        Context appContext =
                context.getApplicationContext();

        String finalSender = sender;

        PendingResult pendingResult = goAsync();

        AtomicBoolean finished = new AtomicBoolean(false);

        Runnable finish = () -> {

            if (finished.compareAndSet(false, true)) {
                pendingResult.finish();
            }
        };

        try {

            EXECUTOR.execute(() -> {

                OnDeviceSvmClassifier classifier = null;

                try {

                    createNotificationChannel(appContext);

                    classifier = getClassifier(appContext);

                    List<UrlScanResult> urlResults =
                            URL_SCANNER.scanText(smsText);

                    classifier.classify(
                            smsText,
                            new MessageClassifier.Callback() {

                                @Override
                                public void onSuccess(
                                        MessageClassification result) {

                                    try {

                                        boolean suspiciousUrl = false;

                                        StringBuilder urlDetails =
                                                new StringBuilder();

                                        for (UrlScanResult urlResult :
                                                urlResults) {

                                            if (urlResult.isSuspicious()) {

                                                suspiciousUrl = true;

                                                urlDetails.append(
                                                                "URL: ")
                                                        .append(
                                                                urlResult.getUrl())
                                                        .append("\n");

                                                for (String indicator :
                                                        urlResult.getIndicators()) {

                                                    urlDetails.append("- ")
                                                            .append(indicator)
                                                            .append("\n");
                                                }
                                            }
                                        }

                                        saveLatestSmsResult(
                                                appContext,
                                                smsText,
                                                finalSender,
                                                result,
                                                urlDetails.toString());

                                        if (result.isSuspicious()
                                                || suspiciousUrl) {
                                            createSmsNotification(
                                                    appContext,
                                                    finalSender,
                                                    result,
                                                    suspiciousUrl,
                                                    urlDetails.toString());
                                        }

                                        Log.i(
                                                TAG,
                                                "SMS result: "
                                                        + result.getLabel()
                                                        + ", URL warning: "
                                                        + suspiciousUrl);

                                    } catch (Exception error) {

                                        Log.e(
                                                TAG,
                                                "SMS result processing failed",
                                                error);

                                    } finally {

                                        finish.run();
                                    }
                                }

                                @Override
                                public void onError(String error) {

                                    Log.e(
                                            TAG,
                                            "SMS classification failed: "
                                                    + error);

                                    finish.run();
                                }
                            });

                } catch (Exception error) {

                    Log.e(
                            TAG,
                            "Unable to process incoming SMS",
                            error);

                    finish.run();
                }
            });

        } catch (RuntimeException error) {

            Log.e(TAG, "SMS executor unavailable", error);

            finish.run();
        }
    }

    private static OnDeviceSvmClassifier getClassifier(
            Context context) throws Exception {

        if (sharedClassifier != null
                && sharedClassifier.isModelLoaded()) {
            return sharedClassifier;
        }

        synchronized (MODEL_LOCK) {

            if (sharedClassifier == null
                    || !sharedClassifier.isModelLoaded()) {

                OnDeviceSvmClassifier newClassifier =
                        new OnDeviceSvmClassifier(context);

                if (!newClassifier.isModelLoaded()) {

                    String error =
                            newClassifier.getLoadError();

                    newClassifier.shutdown();

                    throw new IllegalStateException(
                            error == null
                                    ? "SMS model could not be loaded."
                                    : error);
                }

                sharedClassifier = newClassifier;
            }

            return sharedClassifier;
        }
    }

    private static void createNotificationChannel(
            Context context) {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

            NotificationChannel channel =
                    new NotificationChannel(
                            CHANNEL_ID,
                            "Security Threat Alerts",
                            NotificationManager.IMPORTANCE_HIGH);

            channel.setDescription(
                    "SMS scam and phishing notifications");

            NotificationManager manager =
                    context.getSystemService(
                            NotificationManager.class);

            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    private static void saveLatestSmsResult(
            Context context,
            String body,
            String sender,
            MessageClassification result,
            String urlDetails) {

        StringBuilder indicators = new StringBuilder();

        if (result.getIndicators() != null) {
            for (String indicator : result.getIndicators()) {
                if (indicator != null && !indicator.trim().isEmpty()) {
                    if (indicators.length() > 0) {
                        indicators.append("\n");
                    }
                    indicators.append(indicator.trim());
                }
            }
        }

        if (urlDetails != null && !urlDetails.trim().isEmpty()) {
            if (indicators.length() > 0) {
                indicators.append("\n");
            }
            indicators.append(urlDetails.trim());
        }

        context.getSharedPreferences(
                        "OnDeviceGuardSecurityEvents",
                        Context.MODE_PRIVATE)
                .edit()
                .putString("LATEST_SMS_BODY", body)
                .putString("LATEST_SMS_SENDER", sender)
                .putString("LATEST_SMS_LABEL", result.getLabel())
                .putFloat("LATEST_SMS_CONFIDENCE", result.getConfidence())
                .putString("LATEST_SMS_INDICATORS", indicators.toString())
                .putLong("LATEST_SMS_TIMESTAMP", System.currentTimeMillis())
                .apply();
    }

    private static void createSmsNotification(
            Context context,
            String sender,
            MessageClassification result,
            boolean suspiciousUrl,
            String urlDetails) {

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

        String title;

        if (suspiciousUrl && result.isSuspicious()) {

            title = "SMS Scam and Phishing Warning";

        } else if (suspiciousUrl) {

            title = "Suspicious URL Detected";

        } else {

            title = "Potential SMS Scam Detected";
        }

        StringBuilder content = new StringBuilder();

        content.append("Sender: ")
                .append(sender)
                .append("\n");

        content.append("SMS result: ")
                .append(result.getLabel())
                .append("\n");

        content.append(
                "Do not share OTPs, passwords or banking details.");

        if (!urlDetails.isEmpty()) {

            content.append("\n\nURL analysis:\n")
                    .append(urlDetails);
        }

        Notification notification =
                new Notification.Builder(context, CHANNEL_ID)
                        .setSmallIcon(
                                android.R.drawable.ic_dialog_alert)
                        .setContentTitle(title)
                        .setContentText(
                                "Review this message carefully.")
                        .setStyle(
                                new Notification.BigTextStyle()
                                        .bigText(content.toString()))
                        .setAutoCancel(true)
                        .build();

        try {

            manager.notify(
                    (int) (System.currentTimeMillis()
                            & 0x7fffffff),
                    notification);

        } catch (SecurityException error) {

            Log.e(
                    TAG,
                    "Notification permission unavailable",
                    error);
        }
    }
}