
package com.vcs.ondeviceguard;

import android.os.Bundle;
import android.os.Debug;
import android.os.Process;
import android.os.SystemClock;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.vcs.ondeviceguard.llm.DemoExplanationProvider;
import com.vcs.ondeviceguard.llm.ExplanationProvider;
import com.vcs.ondeviceguard.model.MessageClassification;
import com.vcs.ondeviceguard.model.MessageClassifier;
import com.vcs.ondeviceguard.model.OnDeviceSvmClassifier;

import java.util.Locale;

public class MainActivity extends AppCompatActivity {

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

    private boolean isClassifying;
    private boolean isExplaining;

    private long classificationStartTime;
    private long cpuStartTime;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initializeViews();
        initializeModelProviders();
        initializeListeners();

        txtProtectionStatus.setText("Manual scanning ready");
        txtDetectionResult.setText(
                "Enter a message and select Analyze.");
        txtExplanation.setText(
                "Analyze a message before requesting an explanation.");

        btnExplain.setEnabled(false);
        progressBar.setVisibility(View.GONE);
    }

    private void initializeViews() {
        editMessage = findViewById(R.id.editMessage);
        txtProtectionStatus = findViewById(R.id.txtProtectionStatus);
        txtDetectionResult = findViewById(R.id.txtDetectionResult);
        txtExplanation = findViewById(R.id.txtExplanation);
        btnAnalyze = findViewById(R.id.btnAnalyze);
        btnExplain = findViewById(R.id.btnExplain);
        progressBar = findViewById(R.id.progressBar);
    }

    private void initializeModelProviders() {
        classifier = new OnDeviceSvmClassifier(
                getApplicationContext());

        explanationProvider = new DemoExplanationProvider();
    }

    private void initializeListeners() {
        btnAnalyze.setOnClickListener(v -> analyzeMessage());
        btnExplain.setOnClickListener(v -> explainMessage());
    }

    private void analyzeMessage() {
        if (isClassifying || isExplaining) {
            return;
        }

        String message = editMessage.getText().toString().trim();

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
        txtProtectionStatus.setText("Classification in progress");

        classificationStartTime = SystemClock.elapsedRealtime();
        cpuStartTime = Process.getElapsedCpuTime();

        classifier.classify(
                message,
                new MessageClassifier.Callback() {

                    @Override
                    public void onSuccess(
                            MessageClassification result) {

                        long elapsedTime =
                                SystemClock.elapsedRealtime()
                                        - classificationStartTime;

                        long cpuElapsed =
                                Process.getElapsedCpuTime()
                                        - cpuStartTime;

                        Debug.MemoryInfo memoryInfo =
                                new Debug.MemoryInfo();

                        Debug.getMemoryInfo(memoryInfo);

                        runOnUiThread(() -> {
                            isClassifying = false;

                            btnAnalyze.setEnabled(true);
                            progressBar.setVisibility(View.GONE);

                            latestResult = result;

                            double score = result.getDecisionScore();

                            double ramUsageMb =
                                    memoryInfo.getTotalPss() / 1024.0;

                            double cpuUsage = elapsedTime > 0
                                    ? cpuElapsed * 100.0 / elapsedTime
                                    : 0.0;

                            StringBuilder details =
                                    new StringBuilder();

                            details.append("CLASSIFICATION\n");
                            details.append("Result: ")
                                    .append(result.getLabel()
                                            .toUpperCase(Locale.ROOT))
                                    .append("\n");

                            if (!Double.isNaN(score)
                                    && !Double.isInfinite(score)) {
                                details.append("SVM decision score: ")
                                        .append(String.format(
                                                Locale.US,
                                                "%.6f",
                                                score))
                                        .append("\n");
                            } else {
                                details.append(
                                        "SVM decision score: unavailable\n");
                            }

                            details.append(
                                    "Spam threshold: -0.140241\n\n");

                            details.append("PERFORMANCE METRICS\n");

                            details.append("App RAM (PSS): ")
                                    .append(String.format(
                                            Locale.US,
                                            "%.2f MB",
                                            ramUsageMb))
                                    .append("\n");

                            details.append(
                                            "App CPU usage (estimated): ")
                                    .append(String.format(
                                            Locale.US,
                                            "%.1f%%",
                                            cpuUsage))
                                    .append("\n");

                            details.append("Classification time: ")
                                    .append(elapsedTime)
                                    .append(" ms\n\n");

                            details.append("INDICATORS\n");

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
                                            ? "Potential spam detected"
                                            : "Not flagged as spam");

                            btnExplain.setEnabled(true);

                            Toast.makeText(
                                    MainActivity.this,
                                    "Classification completed",
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

        txtExplanation.setText("Generating explanation...");

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
        if (classifier instanceof OnDeviceSvmClassifier) {
            ((OnDeviceSvmClassifier) classifier).shutdown();
        }

        if (explanationProvider instanceof DemoExplanationProvider) {
            ((DemoExplanationProvider) explanationProvider)
                    .shutdown();
        }

        super.onDestroy();
    }
}
