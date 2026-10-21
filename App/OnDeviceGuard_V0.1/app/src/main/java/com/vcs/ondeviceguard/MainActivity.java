
package com.vcs.ondeviceguard;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.vcs.ondeviceguard.llm.DemoExplanationProvider;
import com.vcs.ondeviceguard.llm.ExplanationProvider;
import com.vcs.ondeviceguard.model.DemoMessageClassifier;
import com.vcs.ondeviceguard.model.MessageClassification;
import com.vcs.ondeviceguard.model.MessageClassifier;

import java.util.ArrayList;
import java.util.Locale;

public class MainActivity extends AppCompatActivity {

    private static final int SMS_PERMISSION_REQUEST_CODE = 1001;

    private EditText editMessage;
    private TextView txtProtectionStatus;
    private TextView txtDetectionResult;
    private TextView txtExplanation;
    private Button btnAnalyze;
    private Button btnExplain;
    private ProgressBar progressBar;

    private MessageClassifier classifier;
    private ExplanationProvider explanationProvider;

    private MessageClassification latestResult;
    private String latestMessage;

    private boolean isClassifying = false;
    private boolean isExplaining = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initializeViews();
        initializeModelProviders();
        initializeListeners();

        requestSmsPermissions();
    }

    private void initializeViews() {
        editMessage = findViewById(R.id.editMessage);

        txtProtectionStatus =
                findViewById(R.id.txtProtectionStatus);

        txtDetectionResult =
                findViewById(R.id.txtDetectionResult);

        txtExplanation =
                findViewById(R.id.txtExplanation);

        btnAnalyze = findViewById(R.id.btnAnalyze);
        btnExplain = findViewById(R.id.btnExplain);

        progressBar = findViewById(R.id.progressBar);
    }

    private void initializeModelProviders() {
        // Temporary demo implementations.
        // Real on-device models will replace these later.
        classifier = new DemoMessageClassifier();
        explanationProvider = new DemoExplanationProvider();
    }

    private void initializeListeners() {
        btnAnalyze.setOnClickListener(v -> analyzeMessage());
        btnExplain.setOnClickListener(v -> explainMessage());
    }

    private void requestSmsPermissions() {
        ArrayList<String> permissions = new ArrayList<>();

        if (checkSelfPermission(Manifest.permission.RECEIVE_SMS)
                != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.RECEIVE_SMS);
        }

        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(
                Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            permissions.add(
                    Manifest.permission.POST_NOTIFICATIONS);
        }

        if (!permissions.isEmpty()) {
            requestPermissions(
                    permissions.toArray(new String[0]),
                    SMS_PERMISSION_REQUEST_CODE);
        } else {
            txtProtectionStatus.setText(
                    "SMS permission granted");
        }
    }

    @Override
    public void onRequestPermissionsResult(
            int requestCode,
            String[] permissions,
            int[] grantResults) {

        super.onRequestPermissionsResult(
                requestCode, permissions, grantResults);

        if (requestCode != SMS_PERMISSION_REQUEST_CODE) {
            return;
        }

        boolean smsGranted =
                checkSelfPermission(Manifest.permission.RECEIVE_SMS)
                        == PackageManager.PERMISSION_GRANTED;

        boolean notificationsGranted =
                Build.VERSION.SDK_INT < 33
                        || checkSelfPermission(
                        Manifest.permission.POST_NOTIFICATIONS)
                        == PackageManager.PERMISSION_GRANTED;

        if (smsGranted && notificationsGranted) {
            txtProtectionStatus.setText(
                    "SMS monitoring permission granted");
            Toast.makeText(
                    this,
                    "Permissions granted",
                    Toast.LENGTH_SHORT
            ).show();
        } else {
            txtProtectionStatus.setText(
                    "Some permissions are missing");
            Toast.makeText(
                    this,
                    "Allow SMS and notification permissions in Settings",
                    Toast.LENGTH_LONG
            ).show();
        }
    }

    private void analyzeMessage() {
        if (isClassifying || isExplaining) {
            return;
        }

        String message =
                editMessage.getText().toString().trim();

        if (message.isEmpty()) {
            editMessage.setError("Enter a message first");
            return;
        }

        latestMessage = message;
        latestResult = null;
        isClassifying = true;

        btnAnalyze.setEnabled(false);
        btnExplain.setEnabled(false);
        progressBar.setVisibility(View.VISIBLE);

        txtDetectionResult.setText("Analyzing message...");
        txtExplanation.setText(
                "The explanation will appear here.");
        txtProtectionStatus.setText(
                "Detection in progress");

        classifier.classify(
                message,
                new MessageClassifier.Callback() {

                    @Override
                    public void onSuccess(
                            MessageClassification result) {

                        runOnUiThread(() -> {
                            isClassifying = false;

                            btnAnalyze.setEnabled(true);
                            progressBar.setVisibility(View.GONE);

                            latestResult = result;

                            StringBuilder details =
                                    new StringBuilder();

                            details.append("Classification: ")
                                    .append(result.getLabel()
                                            .toUpperCase(Locale.ROOT))
                                    .append("\nConfidence score: ")
                                    .append(String.format(
                                            Locale.US,
                                            "%.1f%%",
                                            result.getConfidence() * 100))
                                    .append("\n\nIndicators:\n");

                            if (result.getIndicators().isEmpty()) {
                                details.append(
                                        "No indicators supplied.");
                            } else {
                                for (String indicator :
                                        result.getIndicators()) {
                                    details.append("- ")
                                            .append(indicator)
                                            .append("\n");
                                }
                            }

                            txtDetectionResult.setText(
                                    details.toString());

                            txtProtectionStatus.setText(
                                    result.isSuspicious()
                                            ? "Potential threat detected"
                                            : "No threat flagged by demo classifier");

                            btnExplain.setEnabled(true);

                            Toast.makeText(
                                    MainActivity.this,
                                    "Demo classification completed",
                                    Toast.LENGTH_SHORT
                            ).show();
                        });
                    }

                    @Override
                    public void onError(String message) {
                        runOnUiThread(() -> {
                            isClassifying = false;

                            btnAnalyze.setEnabled(true);
                            btnExplain.setEnabled(false);
                            progressBar.setVisibility(View.GONE);

                            txtDetectionResult.setText(
                                    "Classification failed: " + message);

                            txtProtectionStatus.setText(
                                    "Detection unavailable");
                        });
                    }
                });
    }

    private void explainMessage() {
        if (isClassifying || isExplaining) {
            return;
        }

        if (latestResult == null || latestMessage == null) {
            Toast.makeText(
                    this,
                    "Analyze a message first",
                    Toast.LENGTH_SHORT
            ).show();
            return;
        }

        isExplaining = true;

        btnAnalyze.setEnabled(false);
        btnExplain.setEnabled(false);
        progressBar.setVisibility(View.VISIBLE);

        txtExplanation.setText(
                "Generating explanation...");

        explanationProvider.explain(
                latestMessage,
                latestResult,
                new ExplanationProvider.Callback() {

                    @Override
                    public void onSuccess(String explanation) {
                        runOnUiThread(() -> {
                            isExplaining = false;

                            btnAnalyze.setEnabled(true);
                            btnExplain.setEnabled(true);
                            progressBar.setVisibility(View.GONE);

                            txtExplanation.setText(explanation);
                        });
                    }

                    @Override
                    public void onError(String message) {
                        runOnUiThread(() -> {
                            isExplaining = false;

                            btnAnalyze.setEnabled(true);
                            btnExplain.setEnabled(true);
                            progressBar.setVisibility(View.GONE);

                            txtExplanation.setText(
                                    "Explanation failed: " + message);
                        });
                    }
                });
    }

    @Override
    protected void onDestroy() {
        if (classifier instanceof DemoMessageClassifier) {
            ((DemoMessageClassifier) classifier).shutdown();
        }

        if (explanationProvider
                instanceof DemoExplanationProvider) {
            ((DemoExplanationProvider) explanationProvider)
                    .shutdown();
        }

        super.onDestroy();
    }
}
