package com.vcs.ondeviceguard;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
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

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.vcs.ondeviceguard.llm.ExplanationProvider;
import com.vcs.ondeviceguard.llm.OnDeviceLlamaExplanationProvider;
import com.vcs.ondeviceguard.model.MessageClassification;
import com.vcs.ondeviceguard.model.MessageClassifier;
import com.vcs.ondeviceguard.model.OnDeviceSvmClassifier;
import com.vcs.ondeviceguard.security.UrlScanResult;
import com.vcs.ondeviceguard.security.UrlThreatScanner;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private static final String MODEL_FILE =
            "Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte";

    private static final String TOKENIZER_FILE =
            "tokenizer.model";

    private static final long MODEL_SIZE = 1135951488L;
    private static final long TOKENIZER_SIZE = 2183982L;

    private static final int PERMISSION_REQUEST_CODE = 1001;

    private EditText editMessage;
    private EditText editUrl;

    private TextView txtProtectionStatus;
    private TextView txtDetectionResult;
    private TextView txtExplanation;
    private TextView txtUrlResult;

    private Button btnAnalyze;
    private Button btnExplain;
    private Button btnImportLlama;
    private Button btnScanUrl;

    private ProgressBar progressBar;

    private OnDeviceSvmClassifier classifier;
    private ExplanationProvider explanationProvider;
    private UrlThreatScanner urlScanner;

    private MessageClassification latestResult;
    private String latestMessage;

    private boolean isModelLoading;
    private boolean isClassifying;
    private boolean isExplaining;
    private boolean isImporting;
    private boolean isScanningUrl;

    private long classificationStartTime;
    private long cpuStartTime;

    private int importStep;

    private ActivityResultLauncher<Intent> filePicker;

    private final ExecutorService modelExecutor =
            Executors.newSingleThreadExecutor();

    private final ExecutorService importExecutor =
            Executors.newSingleThreadExecutor();

    private final ExecutorService urlExecutor =
            Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        filePicker = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {

                    if (result.getResultCode() != RESULT_OK
                            || result.getData() == null
                            || result.getData().getData() == null) {

                        if (isImporting) {
                            finishImportWithError(
                                    "File selection cancelled.");
                        }

                        return;
                    }

                    importSelectedFile(
                            result.getData().getData());
                });

        initializeViews();
        initializeModelProviders();
        initializeListeners();

        btnAnalyze.setEnabled(false);
        btnExplain.setEnabled(false);

        progressBar.setVisibility(View.GONE);

        txtProtectionStatus.setText(
                "Loading on-device SMS model...");

        txtDetectionResult.setText(
                "SMS classification model is loading.");

        txtExplanation.setText(
                "Analyze a message before requesting an AI explanation.");

        txtUrlResult.setText(
                "Enter a URL and select Scan URL.");

        requestSecurityPermissions();
    }

    private void initializeViews() {

        editMessage = findViewById(R.id.editMessage);
        editUrl = findViewById(R.id.editUrl);

        txtProtectionStatus =
                findViewById(R.id.txtProtectionStatus);

        txtDetectionResult =
                findViewById(R.id.txtDetectionResult);

        txtExplanation =
                findViewById(R.id.txtExplanation);

        txtUrlResult =
                findViewById(R.id.txtUrlResult);

        btnAnalyze = findViewById(R.id.btnAnalyze);
        btnExplain = findViewById(R.id.btnExplain);
        btnImportLlama = findViewById(R.id.btnImportLlama);
        btnScanUrl = findViewById(R.id.btnScanUrl);

        progressBar = findViewById(R.id.progressBar);
    }

    private void initializeModelProviders() {

        urlScanner = new UrlThreatScanner();

        explanationProvider =
                new OnDeviceLlamaExplanationProvider(
                        getApplicationContext());

        isModelLoading = true;

        modelExecutor.execute(() -> {

            OnDeviceSvmClassifier loadedClassifier = null;

            try {

                loadedClassifier =
                        new OnDeviceSvmClassifier(
                                getApplicationContext());

                if (!loadedClassifier.isModelLoaded()) {

                    String error =
                            loadedClassifier.getLoadError();

                    loadedClassifier.shutdown();

                    runOnUiThread(() -> {

                        if (!isActivityUsable()) {
                            return;
                        }

                        isModelLoading = false;

                        btnAnalyze.setEnabled(false);

                        txtProtectionStatus.setText(
                                "SMS model loading failed");

                        txtDetectionResult.setText(
                                error == null
                                        ? "Unknown model loading error."
                                        : error);
                    });

                    return;
                }

                final OnDeviceSvmClassifier readyClassifier =
                        loadedClassifier;

                runOnUiThread(() -> {

                    if (!isActivityUsable()) {
                        readyClassifier.shutdown();
                        return;
                    }

                    classifier = readyClassifier;

                    isModelLoading = false;

                    btnAnalyze.setEnabled(true);

                    txtProtectionStatus.setText(
                            "SMS protection model ready");

                    txtDetectionResult.setText(
                            "Enter an SMS message and select Analyze.");
                });

            } catch (Exception error) {

                if (loadedClassifier != null) {
                    loadedClassifier.shutdown();
                }

                String message = error.getMessage();

                runOnUiThread(() -> {

                    if (!isActivityUsable()) {
                        return;
                    }

                    isModelLoading = false;

                    btnAnalyze.setEnabled(false);

                    txtProtectionStatus.setText(
                            "SMS model initialization failed");

                    txtDetectionResult.setText(
                            message == null
                                    ? "Unable to initialize SMS model."
                                    : message);
                });
            }
        });
    }

    private void initializeListeners() {

        btnAnalyze.setOnClickListener(
                v -> analyzeMessage());

        btnExplain.setOnClickListener(
                v -> explainMessage());

        btnImportLlama.setOnClickListener(
                v -> startLlamaImport());

        btnScanUrl.setOnClickListener(
                v -> scanUrl());
    }

    private boolean isActivityUsable() {
        return !isFinishing() && !isDestroyed();
    }

    private void requestSecurityPermissions() {

        java.util.ArrayList<String> permissions =
                new java.util.ArrayList<>();

        if (checkSelfPermission(
                Manifest.permission.RECEIVE_SMS)
                != PackageManager.PERMISSION_GRANTED) {

            permissions.add(
                    Manifest.permission.RECEIVE_SMS);
        }

        if (android.os.Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(
                Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {

            permissions.add(
                    Manifest.permission.POST_NOTIFICATIONS);
        }

        if (!permissions.isEmpty()) {

            requestPermissions(
                    permissions.toArray(new String[0]),
                    PERMISSION_REQUEST_CODE);
        }
    }

    @Override
    public void onRequestPermissionsResult(
            int requestCode,
            String[] permissions,
            int[] grantResults) {

        super.onRequestPermissionsResult(
                requestCode,
                permissions,
                grantResults);

        if (requestCode != PERMISSION_REQUEST_CODE) {
            return;
        }

        boolean smsGranted =
                checkSelfPermission(
                        Manifest.permission.RECEIVE_SMS)
                        == PackageManager.PERMISSION_GRANTED;

        boolean notificationGranted =
                android.os.Build.VERSION.SDK_INT < 33
                        || checkSelfPermission(
                        Manifest.permission.POST_NOTIFICATIONS)
                        == PackageManager.PERMISSION_GRANTED;

        if (smsGranted && notificationGranted) {

            txtProtectionStatus.setText(
                    isModelLoading
                            ? "SMS permissions granted. Loading model..."
                            : "SMS and notification permissions granted");

        } else if (!smsGranted) {

            txtProtectionStatus.setText(
                    "SMS permission required for automatic SMS protection");

        } else {

            txtProtectionStatus.setText(
                    "Notification permission not granted");
        }
    }

    private void scanUrl() {

        if (isScanningUrl) {
            return;
        }

        String url = editUrl.getText()
                .toString()
                .trim();

        if (url.isEmpty()) {

            editUrl.setError("Enter a URL");
            return;
        }

        isScanningUrl = true;

        btnScanUrl.setEnabled(false);

        txtUrlResult.setText(
                "Analyzing URL...");

        urlExecutor.execute(() -> {

            try {

                UrlScanResult result =
                        urlScanner.scanUrl(url);

                StringBuilder output =
                        new StringBuilder();

                output.append("URL ANALYSIS\n\n");

                output.append("URL: ")
                        .append(result.getUrl())
                        .append("\n\n");

                output.append("RESULT: ");

                output.append(
                        result.isSuspicious()
                                ? "SUSPICIOUS"
                                : "NO HEURISTIC WARNING");

                output.append("\n\nINDICATORS\n");

                List<String> indicators =
                        result.getIndicators();

                if (indicators.isEmpty()) {

                    output.append(
                            "No suspicious URL patterns detected.");

                } else {

                    for (String indicator : indicators) {

                        output.append("- ")
                                .append(indicator)
                                .append("\n");
                    }
                }

                output.append(
                        "\nThis is local heuristic analysis. "
                                + "It does not guarantee that a URL is safe.");

                String finalOutput = output.toString();

                runOnUiThread(() -> {

                    if (!isActivityUsable()) {
                        return;
                    }

                    isScanningUrl = false;

                    btnScanUrl.setEnabled(true);

                    txtUrlResult.setText(finalOutput);
                });

            } catch (Exception error) {

                runOnUiThread(() -> {

                    if (!isActivityUsable()) {
                        return;
                    }

                    isScanningUrl = false;

                    btnScanUrl.setEnabled(true);

                    txtUrlResult.setText(
                            "URL scanning failed: "
                                    + safeMessage(error));
                });
            }
        });
    }

    private void startLlamaImport() {

        if (isImporting
                || isClassifying
                || isExplaining
                || isModelLoading) {
            return;
        }

        importStep = 1;
        isImporting = true;

        btnImportLlama.setEnabled(false);
        btnAnalyze.setEnabled(false);
        btnExplain.setEnabled(false);

        txtExplanation.setText(
                "Select the Llama .pte model file.");

        openFilePicker();
    }

    private void openFilePicker() {

        Intent intent =
                new Intent(Intent.ACTION_OPEN_DOCUMENT);

        intent.setType("*/*");

        intent.addCategory(
                Intent.CATEGORY_OPENABLE);

        intent.addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION);

        filePicker.launch(intent);
    }

    private void importSelectedFile(Uri uri) {

        if (!isImporting) {
            return;
        }

        final int currentStep = importStep;

        final String fileName;
        final long expectedSize;

        if (currentStep == 1) {

            fileName = MODEL_FILE;
            expectedSize = MODEL_SIZE;

        } else if (currentStep == 2) {

            fileName = TOKENIZER_FILE;
            expectedSize = TOKENIZER_SIZE;

        } else {

            finishImportWithError(
                    "Invalid import step.");

            return;
        }

        txtProtectionStatus.setText(
                "Importing " + fileName + "...");

        txtExplanation.setText(
                "Please wait while the file is copied.");

        progressBar.setVisibility(View.VISIBLE);

        importExecutor.execute(() -> {

            File directory =
                    new File(getFilesDir(), "llama");

            File temporaryFile =
                    new File(directory, fileName + ".tmp");

            File destinationFile =
                    new File(directory, fileName);

            try {

                if (!directory.exists()
                        && !directory.mkdirs()) {

                    throw new IllegalStateException(
                            "Cannot create Llama model directory.");
                }

                long copiedBytes = 0;

                try (
                        InputStream input =
                                getContentResolver()
                                        .openInputStream(uri);

                        FileOutputStream output =
                                new FileOutputStream(temporaryFile)
                ) {

                    if (input == null) {
                        throw new IllegalStateException(
                                "Unable to open selected file.");
                    }

                    byte[] buffer = new byte[65536];

                    int count;

                    while ((count = input.read(buffer)) != -1) {

                        output.write(buffer, 0, count);

                        copiedBytes += count;
                    }

                    output.flush();
                    output.getFD().sync();
                }

                if (copiedBytes != expectedSize) {

                    throw new IllegalStateException(
                            "Incorrect file size.\n"
                                    + "Copied: " + copiedBytes
                                    + " bytes.\nExpected: "
                                    + expectedSize + " bytes.");
                }

                if (destinationFile.exists()
                        && !destinationFile.delete()) {

                    throw new IllegalStateException(
                            "Cannot replace existing model file.");
                }

                if (!temporaryFile.renameTo(destinationFile)) {

                    throw new IllegalStateException(
                            "Unable to finalize imported file.");
                }

                runOnUiThread(() -> {

                    if (!isActivityUsable()) {
                        return;
                    }

                    if (currentStep == 1) {

                        importStep = 2;

                        txtProtectionStatus.setText(
                                "Model imported. Select tokenizer.");

                        txtExplanation.setText(
                                "Now select tokenizer.model.");

                        openFilePicker();

                    } else {

                        importStep = 0;
                        isImporting = false;

                        progressBar.setVisibility(View.GONE);

                        btnImportLlama.setEnabled(true);
                        btnAnalyze.setEnabled(
                                classifier != null
                                        && classifier.isModelLoaded());

                        btnExplain.setEnabled(
                                latestResult != null);

                        txtProtectionStatus.setText(
                                "Llama model and tokenizer imported");

                        txtExplanation.setText(
                                "Files imported successfully. "
                                        + "Analyze a message and select Explain with AI.");

                        Toast.makeText(
                                MainActivity.this,
                                "Llama files imported successfully.",
                                Toast.LENGTH_LONG
                        ).show();
                    }
                });

            } catch (Exception error) {

                if (temporaryFile.exists()) {
                    temporaryFile.delete();
                }

                String message = safeMessage(error);

                runOnUiThread(() ->
                        finishImportWithError(message));
            }
        });
    }

    private void finishImportWithError(String message) {

        isImporting = false;
        importStep = 0;

        progressBar.setVisibility(View.GONE);

        btnImportLlama.setEnabled(true);

        btnAnalyze.setEnabled(
                classifier != null
                        && classifier.isModelLoaded()
                        && !isClassifying
                        && !isExplaining);

        btnExplain.setEnabled(
                latestResult != null
                        && !isClassifying
                        && !isExplaining);

        txtProtectionStatus.setText(
                "Llama import failed");

        txtExplanation.setText(
                "Import failed:\n" + message);

        Toast.makeText(
                this,
                "Import failed: " + message,
                Toast.LENGTH_LONG
        ).show();
    }

    private void analyzeMessage() {

        if (isModelLoading
                || isClassifying
                || isExplaining
                || isImporting) {
            return;
        }

        if (classifier == null
                || !classifier.isModelLoaded()) {

            txtDetectionResult.setText(
                    "SMS classifier is not available.");

            return;
        }

        String message = editMessage.getText()
                .toString()
                .trim();

        if (message.isEmpty()) {

            editMessage.setError(
                    "Enter a message first");

            return;
        }

        latestMessage = message;
        latestResult = null;

        isClassifying = true;

        btnAnalyze.setEnabled(false);
        btnExplain.setEnabled(false);
        btnImportLlama.setEnabled(false);

        progressBar.setVisibility(View.VISIBLE);

        txtDetectionResult.setText(
                "Analyzing message...");

        txtExplanation.setText(
                "Waiting for classification result.");

        txtProtectionStatus.setText(
                "SMS classification in progress");

        classificationStartTime =
                SystemClock.elapsedRealtime();

        cpuStartTime =
                Process.getElapsedCpuTime();

        try {

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

                                if (!isActivityUsable()) {
                                    return;
                                }

                                isClassifying = false;

                                btnAnalyze.setEnabled(true);
                                btnImportLlama.setEnabled(true);

                                progressBar.setVisibility(
                                        View.GONE);

                                if (result == null) {

                                    btnExplain.setEnabled(false);

                                    txtDetectionResult.setText(
                                            "Classifier returned an empty result.");

                                    return;
                                }

                                latestResult = result;

                                double score =
                                        result.getDecisionScore();

                                double ramUsageMb =
                                        memoryInfo.getTotalPss()
                                                / 1024.0;

                                StringBuilder details =
                                        new StringBuilder();

                                details.append(
                                        "CLASSIFICATION\n\n");

                                details.append("Result: ")
                                        .append(result.getLabel()
                                                .toUpperCase(
                                                        Locale.ROOT))
                                        .append("\n");

                                if (Double.isFinite(score)) {

                                    details.append(
                                                    "SVM decision score: ")
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
                                                "Spam threshold: ")
                                        .append(String.format(
                                                Locale.US,
                                                "%.6f",
                                                classifier.getThreshold()))
                                        .append("\n\n");

                                details.append(
                                        "PERFORMANCE METRICS\n\n");

                                details.append("App RAM (PSS): ")
                                        .append(String.format(
                                                Locale.US,
                                                "%.2f MB",
                                                ramUsageMb))
                                        .append("\n");

                                details.append(
                                                "Process CPU time: ")
                                        .append(cpuElapsed)
                                        .append(" ms\n");

                                details.append(
                                                "Classification time: ")
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

                                if (!isActivityUsable()) {
                                    return;
                                }

                                isClassifying = false;

                                btnAnalyze.setEnabled(true);
                                btnExplain.setEnabled(false);
                                btnImportLlama.setEnabled(true);

                                progressBar.setVisibility(
                                        View.GONE);

                                txtDetectionResult.setText(
                                        "Classification failed:\n"
                                                + message);

                                txtProtectionStatus.setText(
                                        "Detection unavailable");
                            });
                        }
                    });

        } catch (Exception error) {

            isClassifying = false;

            btnAnalyze.setEnabled(true);
            btnImportLlama.setEnabled(true);

            progressBar.setVisibility(View.GONE);

            txtDetectionResult.setText(
                    "Classification failed:\n"
                            + safeMessage(error));
        }
    }

    private void explainMessage() {

        if (isClassifying
                || isExplaining
                || isImporting) {
            return;
        }

        if (latestResult == null
                || latestMessage == null) {

            Toast.makeText(
                    this,
                    "Analyze a message first.",
                    Toast.LENGTH_SHORT
            ).show();

            return;
        }

        isExplaining = true;

        btnAnalyze.setEnabled(false);
        btnExplain.setEnabled(false);
        btnImportLlama.setEnabled(false);

        progressBar.setVisibility(View.VISIBLE);

        txtExplanation.setText(
                "Generating on-device AI explanation...");

        final String message = latestMessage;
        final MessageClassification result = latestResult;

        explanationProvider.explain(
                message,
                result,
                new ExplanationProvider.Callback() {

                    @Override
                    public void onSuccess(String explanation) {

                        runOnUiThread(() -> {

                            if (!isActivityUsable()) {
                                return;
                            }

                            isExplaining = false;

                            btnAnalyze.setEnabled(true);
                            btnExplain.setEnabled(true);
                            btnImportLlama.setEnabled(true);

                            progressBar.setVisibility(
                                    View.GONE);

                            txtExplanation.setText(
                                    explanation);
                        });
                    }

                    @Override
                    public void onError(String message) {

                        runOnUiThread(() -> {

                            if (!isActivityUsable()) {
                                return;
                            }

                            isExplaining = false;

                            btnAnalyze.setEnabled(true);
                            btnExplain.setEnabled(true);
                            btnImportLlama.setEnabled(true);

                            progressBar.setVisibility(
                                    View.GONE);

                            txtExplanation.setText(
                                    "Explanation failed:\n"
                                            + message);
                        });
                    }
                });
    }

    private String safeMessage(Exception error) {

        String message = error.getMessage();

        if (message == null || message.trim().isEmpty()) {
            return error.getClass().getSimpleName();
        }

        return message;
    }

    @Override
    protected void onDestroy() {

        modelExecutor.shutdownNow();
        importExecutor.shutdownNow();
        urlExecutor.shutdownNow();

        if (classifier != null) {
            classifier.shutdown();
        }

        if (explanationProvider
                instanceof OnDeviceLlamaExplanationProvider) {

            ((OnDeviceLlamaExplanationProvider)
                    explanationProvider).shutdown();
        }

        super.onDestroy();
    }
}