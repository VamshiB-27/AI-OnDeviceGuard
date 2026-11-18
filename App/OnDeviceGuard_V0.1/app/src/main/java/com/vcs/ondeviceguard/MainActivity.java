package com.vcs.ondeviceguard;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.database.Cursor;
import android.provider.Telephony;
import android.graphics.Color;
import android.content.Intent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.IntentFilter;
import android.net.VpnService;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Build;
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
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.vcs.ondeviceguard.network.NetworkProtectionService;
import com.vcs.ondeviceguard.llm.ExplanationProvider;
import com.vcs.ondeviceguard.llm.OnDeviceLlamaExplanationProvider;
import com.vcs.ondeviceguard.model.MessageClassification;
import com.vcs.ondeviceguard.model.MessageClassifier;
import com.vcs.ondeviceguard.model.OnDeviceSvmClassifier;
import com.vcs.ondeviceguard.security.UrlScanResult;
import com.vcs.ondeviceguard.security.UrlPhishingClassifier;
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
    private static final String ERROR_CHANNEL_ID = "ondeviceguard_errors";
    private static final int STATUS_SUCCESS = 0;
    private static final int STATUS_INFO = 1;
    private static final int STATUS_WARNING = 2;
    private static final int STATUS_ERROR = 3;

    private EditText editMessage;
    private EditText editUrl;

    private TextView txtProtectionStatus;
    private TextView txtDetectionResult;
    private TextView txtExplanation;
    private TextView txtUrlResult;
    private TextView txtResourceMonitor;

    private Button btnAnalyze;
    private Button btnLoadLatestSms;
    private Button btnExplain;
    private Button btnScanUrl;
    private Button btnStartNetworkProtection;
    private Button btnStopNetworkProtection;
    private TextView txtNetworkStatus;

    private ProgressBar progressBar;

    private OnDeviceSvmClassifier classifier;
    private ExplanationProvider explanationProvider;
    private UrlThreatScanner urlScanner;

    private MessageClassification latestResult;
    private String latestMessage;

    private String latestExplanationType;
    private String latestEvidence;
    private String latestClassification;
    private List<String> latestIndicators = java.util.Collections.emptyList();

    private boolean isModelLoading;
    private boolean isClassifying;
    private boolean isExplaining;
    private boolean isImporting;
    private boolean isScanningUrl;
    private boolean explainAfterImport;

    private long classificationStartTime;
    private long cpuStartTime;

    private int importStep;
    private DeviceResourceMonitor resourceMonitor;

    private ActivityResultLauncher<Intent> filePicker;
    private ActivityResultLauncher<Intent> vpnPermissionLauncher;
    private boolean networkReceiverRegistered;

    private final BroadcastReceiver networkStatusReceiver =
            new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    if (intent == null
                            || !NetworkProtectionService.ACTION_STATUS.equals(
                            intent.getAction())) {
                        return;
                    }

                    String status = intent.getStringExtra(
                            NetworkProtectionService.EXTRA_STATUS);
                    boolean blocked = intent.getBooleanExtra(
                            NetworkProtectionService.EXTRA_BLOCKED, false);

                    if (status != null) {
                        boolean warning = status.startsWith(
                                "Potentially risky domain observed");

                        int severity = blocked
                                ? STATUS_ERROR
                                : warning ? STATUS_WARNING : STATUS_SUCCESS;

                        txtNetworkStatus.setText(status);
                        setFeedbackBackground(
                                txtNetworkStatus,
                                severity);
                        setStatus(status, severity, false);
                        if (intent.hasExtra(NetworkProtectionService.EXTRA_DOMAIN)) {
                            loadLatestNetworkResult();
                        }
                    }
                }
            };

    private final ExecutorService modelExecutor =
            Executors.newSingleThreadExecutor();

    private final ExecutorService importExecutor =
            Executors.newSingleThreadExecutor();

    private final ExecutorService urlExecutor =
            Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
        getWindow().setStatusBarColor(Color.TRANSPARENT);
        getWindow().setNavigationBarColor(Color.TRANSPARENT);
        applySystemBarAppearance();
        setContentView(R.layout.activity_main);
        applySystemBarInsets();

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

        vpnPermissionLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK) {
                        startNetworkProtectionService();
                    } else {
                        setNetworkStatus(
                                "VPN permission was denied. Network protection is off.",
                                STATUS_WARNING);
                    }
                });

        initializeViews();
        createErrorNotificationChannel();
        registerNetworkStatusReceiver();
        initializeModelProviders();
        initializeListeners();

        resourceMonitor = new DeviceResourceMonitor(
                getApplicationContext(),
                metrics -> {
                    if (isActivityUsable() && txtResourceMonitor != null) {
                        txtResourceMonitor.setText(metrics);
                    }
                });

        btnAnalyze.setEnabled(false);
        btnExplain.setEnabled(false);

        progressBar.setVisibility(View.GONE);

        setStatus("Loading on-device SMS model...", STATUS_INFO, false);

        txtDetectionResult.setText(
                "SMS classification model is loading.");

        txtExplanation.setText(
                "Analyze a message before requesting an AI explanation.");

        txtUrlResult.setText(
                "Enter a URL and select Scan URL.");

        requestSecurityPermissions();
    }

    private void applySystemBarAppearance() {
        int nightMode = getResources().getConfiguration().uiMode
                & Configuration.UI_MODE_NIGHT_MASK;
        boolean isNightMode = nightMode == Configuration.UI_MODE_NIGHT_YES;

        WindowInsetsControllerCompat controller =
                new WindowInsetsControllerCompat(
                        getWindow(),
                        getWindow().getDecorView());

        controller.setAppearanceLightStatusBars(!isNightMode);
        controller.setAppearanceLightNavigationBars(!isNightMode);
    }

    private void applySystemBarInsets() {
        View root = findViewById(R.id.mainScrollView);

        int initialLeft = root.getPaddingLeft();
        int initialTop = root.getPaddingTop();
        int initialRight = root.getPaddingRight();
        int initialBottom = root.getPaddingBottom();

        ViewCompat.setOnApplyWindowInsetsListener(
                root,
                (view, windowInsets) -> {
                    Insets bars = windowInsets.getInsets(
                            WindowInsetsCompat.Type.systemBars());

                    view.setPadding(
                            initialLeft + bars.left,
                            initialTop + bars.top,
                            initialRight + bars.right,
                            initialBottom + bars.bottom);

                    return windowInsets;
                });

        ViewCompat.requestApplyInsets(root);
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
        btnLoadLatestSms = findViewById(R.id.btnLoadLatestSms);
        btnExplain = findViewById(R.id.btnExplain);
        btnScanUrl = findViewById(R.id.btnScanUrl);
        btnStartNetworkProtection =
                findViewById(R.id.btnStartNetworkProtection);
        btnStopNetworkProtection =
                findViewById(R.id.btnStopNetworkProtection);
        txtNetworkStatus = findViewById(R.id.txtNetworkStatus);

        progressBar = findViewById(R.id.progressBar);
        txtResourceMonitor = findViewById(R.id.txtResourceMonitor);
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

                        setStatus("SMS model loading failed", STATUS_ERROR, true);

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

                    setStatus("SMS protection model ready", STATUS_SUCCESS, false);

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

                    setStatus("SMS model initialization failed", STATUS_ERROR, true);

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

        btnLoadLatestSms.setOnClickListener(
                v -> loadLatestSms());

        btnExplain.setOnClickListener(
                v -> explainLatestSecurityEvent());


        btnScanUrl.setOnClickListener(
                v -> scanUrl());

        btnStartNetworkProtection.setOnClickListener(
                v -> requestNetworkProtection());

        btnStopNetworkProtection.setOnClickListener(
                v -> stopNetworkProtection());
    }

    private void registerNetworkStatusReceiver() {
        IntentFilter filter = new IntentFilter(
                NetworkProtectionService.ACTION_STATUS);

        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(
                    networkStatusReceiver,
                    filter,
                    Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(networkStatusReceiver, filter);
        }

        networkReceiverRegistered = true;
    }

    private void requestNetworkProtection() {
        Intent prepareIntent = VpnService.prepare(this);

        if (prepareIntent == null) {
            startNetworkProtectionService();
        } else {
            vpnPermissionLauncher.launch(prepareIntent);
        }
    }

    private void startNetworkProtectionService() {
        Intent intent = new Intent(
                this, NetworkProtectionService.class);
        intent.setAction(NetworkProtectionService.ACTION_START);

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent);
            } else {
                startService(intent);
            }

            setNetworkStatus(
                    "Starting DNS threat protection...",
                    STATUS_INFO);
        } catch (Exception error) {
            setNetworkStatus(
                    "Unable to start network protection: "
                            + safeMessage(error),
                    STATUS_ERROR);
        }
    }

    private void stopNetworkProtection() {
        Intent intent = new Intent(
                this, NetworkProtectionService.class);
        intent.setAction(NetworkProtectionService.ACTION_STOP);

        try {
            startService(intent);
        } catch (Exception error) {
            stopService(new Intent(
                    this, NetworkProtectionService.class));
        }

        setNetworkStatus(
                "Stopping DNS threat protection...",
                STATUS_INFO);
    }

    private void setNetworkStatus(String message, int status) {
        if (txtNetworkStatus != null) {
            txtNetworkStatus.setText(message);
            setFeedbackBackground(txtNetworkStatus, status);
        }
        setStatus(message, status, status == STATUS_ERROR);
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

        if (checkSelfPermission(
                Manifest.permission.READ_SMS)
                != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.READ_SMS);
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
        } else if (checkSelfPermission(Manifest.permission.READ_SMS)
                == PackageManager.PERMISSION_GRANTED) {
            loadLatestSms();
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

        boolean receiveSmsGranted =
                checkSelfPermission(Manifest.permission.RECEIVE_SMS)
                        == PackageManager.PERMISSION_GRANTED;

        boolean readSmsGranted =
                checkSelfPermission(Manifest.permission.READ_SMS)
                        == PackageManager.PERMISSION_GRANTED;

        boolean notificationGranted =
                Build.VERSION.SDK_INT < 33
                        || checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                        == PackageManager.PERMISSION_GRANTED;

        if (readSmsGranted) {
            loadLatestSms();
        }

        if (receiveSmsGranted && readSmsGranted && notificationGranted) {
            setStatus(
                    isModelLoading
                            ? "SMS permissions granted. Loading model..."
                            : "SMS inbox and incoming SMS access enabled",
                    STATUS_SUCCESS,
                    false);
        } else if (!readSmsGranted || !receiveSmsGranted) {
            setStatus(
                    "Allow SMS permissions to read inbox messages and detect incoming SMS. Manual paste remains available.",
                    STATUS_WARNING,
                    false);
        } else {
            setStatus("Notification permission not granted", STATUS_WARNING, false);
        }
    }

    private void loadLatestSms() {
        if (checkSelfPermission(Manifest.permission.READ_SMS)
                != PackageManager.PERMISSION_GRANTED) {
            setStatus("SMS inbox permission is required to load a message.",
                    STATUS_WARNING, false);
            requestSecurityPermissions();
            return;
        }

        String[] projection = new String[] {
                Telephony.Sms.BODY,
                Telephony.Sms.ADDRESS,
                Telephony.Sms.DATE
        };

        try (Cursor cursor = getContentResolver().query(
                Telephony.Sms.Inbox.CONTENT_URI,
                projection,
                null,
                null,
                Telephony.Sms.DATE + " DESC")) {

            if (cursor == null || !cursor.moveToFirst()) {
                setStatus("No SMS messages found in the inbox.",
                        STATUS_INFO, false);
                Toast.makeText(this, "Inbox is empty.", Toast.LENGTH_SHORT).show();
                return;
            }

            int bodyIndex = cursor.getColumnIndex(Telephony.Sms.BODY);
            int addressIndex = cursor.getColumnIndex(Telephony.Sms.ADDRESS);

            String body = bodyIndex >= 0 ? cursor.getString(bodyIndex) : null;
            String address = addressIndex >= 0 ? cursor.getString(addressIndex) : null;

            if (body == null || body.trim().isEmpty()) {
                setStatus("The latest SMS has no readable message body.",
                        STATUS_ERROR, false);
                return;
            }

            editMessage.setText(body);
            editMessage.setSelection(editMessage.getText().length());
            latestMessage = body.trim();
            latestResult = null;
            btnExplain.setEnabled(false);
            txtDetectionResult.setText("Message loaded. Select Analyze message.");
            setFeedbackBackground(txtDetectionResult, STATUS_INFO);
            txtExplanation.setText("Analyze this SMS first, then request a short AI explanation.");
            setFeedbackBackground(txtExplanation, STATUS_INFO);

            String senderText = address == null || address.trim().isEmpty()
                    ? "unknown sender"
                    : address;
            setStatus("Latest SMS loaded from " + senderText,
                    STATUS_SUCCESS, false);
            Toast.makeText(this, "Latest SMS loaded into the message box.",
                    Toast.LENGTH_SHORT).show();

        } catch (SecurityException error) {
            setStatus("SMS inbox access was denied.", STATUS_ERROR, true);
        } catch (Exception error) {
            setStatus("Unable to read SMS inbox: " + safeMessage(error),
                    STATUS_ERROR, true);
        }
    }

    private void scanUrl() {

        if (isScanningUrl) {
            return;
        }

        String url = editUrl.getText().toString().trim();
        if (url.isEmpty()) {
            editUrl.setError("Enter a URL");
            return;
        }

        isScanningUrl = true;
        btnScanUrl.setEnabled(false);
        txtUrlResult.setText("Analyzing URL with the ML model and heuristic scanner...");

        urlExecutor.execute(() -> {
            UrlPhishingClassifier mlClassifier = null;

            try {
                UrlScanResult heuristicResult = urlScanner.scanUrl(url);
                mlClassifier = new UrlPhishingClassifier(getApplicationContext());
                UrlPhishingClassifier.Result mlResult = mlClassifier.classify(url);

                StringBuilder output = new StringBuilder();
                output.append("URL SECURITY ANALYSIS\n\n");
                output.append("URL: ").append(url).append("\n\n");

                output.append("MACHINE-LEARNING RESULT\n");
                output.append("Model: StandardScaler + Logistic Regression\n");
                output.append("Prediction: ")
                        .append(mlResult.getLabel().toUpperCase(Locale.ROOT))
                        .append("\n");
                output.append(String.format(
                        Locale.US,
                        "Decision score: %.6f\nModel probability: %.2f%%\n\n",
                        mlResult.getScore(),
                        mlResult.getProbability() * 100.0));

                output.append("HEURISTIC SCANNER RESULT\n");
                output.append("Prediction: ")
                        .append(heuristicResult.isSuspicious()
                                ? "SUSPICIOUS PATTERN"
                                : "NO HIGH-RISK HEURISTIC FOUND")
                        .append("\n");

                List<String> heuristicIndicators = heuristicResult.getIndicators();
                if (heuristicIndicators == null || heuristicIndicators.isEmpty()) {
                    output.append("- No heuristic indicators were returned.\n");
                } else {
                    for (String indicator : heuristicIndicators) {
                        output.append("- ").append(indicator).append("\n");
                    }
                }

                output.append("\nThe ML prediction and heuristic result are independent. "
                        + "Neither result proves that a URL is safe or malicious.");

                String mlLabel = mlResult.getLabel();
                String storedClassification = mlLabel.toUpperCase(Locale.ROOT)
                        + " (URL ML)";
                List<String> eventIndicators = new java.util.ArrayList<>();
                if (heuristicIndicators != null) {
                    eventIndicators.addAll(heuristicIndicators);
                }
                eventIndicators.add(String.format(
                        Locale.US,
                        "URL Logistic Regression score: %.6f",
                        mlResult.getScore()));
                eventIndicators.add(String.format(
                        Locale.US,
                        "URL model probability: %.2f%%",
                        mlResult.getProbability() * 100.0));

                latestExplanationType = "URL";
                latestEvidence = url;
                latestClassification = storedClassification;
                latestIndicators = eventIndicators;

                getSharedPreferences(
                        "OnDeviceGuardSecurityEvents",
                        MODE_PRIVATE)
                        .edit()
                        .putString("LATEST_URL", url)
                        .putString("LATEST_URL_LABEL", storedClassification)
                        .putString("LATEST_URL_INDICATORS",
                                android.text.TextUtils.join("\n", eventIndicators))
                        .putLong("LATEST_URL_TIMESTAMP", System.currentTimeMillis())
                        .apply();

                boolean threatDetected = mlResult.isPhishing()
                        || heuristicResult.isSuspicious();
                String finalOutput = output.toString();

                runOnUiThread(() -> {
                    if (!isActivityUsable()) {
                        return;
                    }

                    isScanningUrl = false;
                    btnScanUrl.setEnabled(true);
                    txtUrlResult.setText(finalOutput);
                    btnExplain.setEnabled(true);
                    txtExplanation.setText(
                            "URL scan result ready. Explain with AI will explain the original ML prediction and the separate heuristic indicators.");
                    setFeedbackBackground(txtExplanation, STATUS_INFO);
                    setFeedbackBackground(
                            txtUrlResult,
                            threatDetected ? STATUS_ERROR : STATUS_SUCCESS);

                    if (threatDetected) {
                        setStatus(
                                "URL model or heuristic scanner raised a warning",
                                STATUS_ERROR,
                                false);
                    } else {
                        setStatus(
                                "URL ML and heuristic scans completed",
                                STATUS_SUCCESS,
                                false);
                    }
                });

            } catch (Exception error) {
                String message = safeMessage(error);
                runOnUiThread(() -> {
                    if (!isActivityUsable()) {
                        return;
                    }

                    isScanningUrl = false;
                    btnScanUrl.setEnabled(true);
                    txtUrlResult.setText("URL scanning failed: " + message);
                    setFeedbackBackground(txtUrlResult, STATUS_ERROR);
                    setStatus("URL scanning failed", STATUS_ERROR, true);
                });
            } finally {
                if (mlClassifier != null) {
                    mlClassifier.close();
                }
            }
        });
    }

    private void startLlamaImport() {

        if (isImporting
                || isClassifying
                || isExplaining) {
            return;
        }

        importStep = 1;
        isImporting = true;

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

        setStatus("Importing " + fileName + "...", STATUS_INFO, false);

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

                File backupFile =
                        new File(directory, fileName + ".bak");

                if (backupFile.exists() && !backupFile.delete()) {
                    throw new IllegalStateException(
                            "Cannot clear the previous import backup.");
                }

                boolean movedOldFile = false;

                if (destinationFile.exists()) {
                    if (!destinationFile.renameTo(backupFile)) {
                        throw new IllegalStateException(
                                "Cannot safely preserve the existing model file.");
                    }
                    movedOldFile = true;
                }

                if (!temporaryFile.renameTo(destinationFile)) {
                    if (movedOldFile) {
                        backupFile.renameTo(destinationFile);
                    }
                    throw new IllegalStateException(
                            "Unable to finalize imported file. "
                                    + "The previous file was restored when possible.");
                }

                if (backupFile.exists()) {
                    backupFile.delete();
                }

                runOnUiThread(() -> {

                    if (!isActivityUsable()) {
                        return;
                    }

                    if (currentStep == 1) {

                        importStep = 2;

                        setStatus("Model imported. Select tokenizer.",
                                STATUS_SUCCESS, false);

                        txtExplanation.setText(
                                "Now select tokenizer.model.");

                        openFilePicker();

                    } else {

                        importStep = 0;
                        isImporting = false;

                        progressBar.setVisibility(View.GONE);

                        btnAnalyze.setEnabled(
                                classifier != null
                                        && classifier.isModelLoaded());

                        btnExplain.setEnabled(latestResult != null);

                        setStatus("Llama model and tokenizer imported",
                                STATUS_SUCCESS, false);

                        txtExplanation.setText(
                                "Model files are ready. Loading Llama for your explanation...");

                        Toast.makeText(
                                MainActivity.this,
                                "Llama model and tokenizer imported.",
                                Toast.LENGTH_SHORT
                        ).show();

                        if (explainAfterImport && latestExplanationType != null) {
                            explainAfterImport = false;
                            explainLatestSecurityEvent();
                        }
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
        explainAfterImport = false;

        progressBar.setVisibility(View.GONE);


        btnAnalyze.setEnabled(
                classifier != null
                        && classifier.isModelLoaded()
                        && !isClassifying
                        && !isExplaining);

        btnExplain.setEnabled(
                latestResult != null
                        && !isClassifying
                        && !isExplaining);

        setStatus("Llama import failed", STATUS_ERROR, true);

        txtExplanation.setText(
                "Import failed:\n" + message);
        setFeedbackBackground(txtExplanation, STATUS_ERROR);

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

        progressBar.setVisibility(View.VISIBLE);

        txtDetectionResult.setText(
                "Analyzing message...");

        txtExplanation.setText(
                "Waiting for classification result.");

        setStatus("SMS classification in progress", STATUS_INFO, false);

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

                                progressBar.setVisibility(
                                        View.GONE);

                                if (result == null) {

                                    btnExplain.setEnabled(false);

                                    txtDetectionResult.setText(
                                            "Classifier returned an empty result.");

                                    return;
                                }

                                latestResult = result;
                                latestExplanationType = "SMS";
                                latestEvidence = latestMessage;
                                latestClassification = result.getLabel();
                                latestIndicators = result.getIndicators();

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

                                txtDetectionResult.setText(
                                        details.toString());
                                setFeedbackBackground(
                                        txtDetectionResult,
                                        result.isSuspicious()
                                                ? STATUS_ERROR
                                                : STATUS_SUCCESS);

                                setStatus(
                                        result.isSuspicious()
                                                ? "Potential spam or scam detected"
                                                : "Not flagged as spam",
                                        result.isSuspicious() ? STATUS_ERROR : STATUS_SUCCESS,
                                        false);

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

                                progressBar.setVisibility(
                                        View.GONE);

                                txtDetectionResult.setText(
                                        "Classification failed:\n"
                                                + message);
                                setFeedbackBackground(
                                        txtDetectionResult, STATUS_ERROR);

                                setStatus("Detection unavailable", STATUS_ERROR, true);
                            });
                        }
                    });

        } catch (Exception error) {

            isClassifying = false;

            btnAnalyze.setEnabled(true);

            progressBar.setVisibility(View.GONE);

            txtDetectionResult.setText(
                    "Classification failed:\n"
                            + safeMessage(error));
            setStatus("Classification failed", STATUS_ERROR, true);
        }
    }

    private void explainMessage() {
        explainLatestSecurityEvent();
    }

    private void explainLatestSecurityEvent() {

        if (isClassifying || isExplaining || isImporting) {
            return;
        }

        if (latestExplanationType == null
                || latestEvidence == null
                || latestClassification == null) {
            setStatus("Run a security scan or wait for a background detection first.",
                    STATUS_WARNING, false);
            return;
        }

        if (!areLlamaFilesReady()) {
            explainAfterImport = true;
            txtExplanation.setText(
                    "Select the Llama .pte model and tokenizer.model. "
                            + "After both files are imported, the explanation will start automatically.");
            setFeedbackBackground(txtExplanation, STATUS_INFO);
            startLlamaImport();
            return;
        }

        isExplaining = true;
        btnAnalyze.setEnabled(false);
        btnExplain.setEnabled(false);
        progressBar.setVisibility(View.VISIBLE);

        final String type = latestExplanationType;
        final String evidence = latestEvidence;
        final String classification = latestClassification;
        final List<String> indicators = new java.util.ArrayList<>(latestIndicators);

        txtExplanation.setText("AI EXPLANATION — " + type
                + "\nLoading Llama and explaining the existing classifier result...");
        setFeedbackBackground(txtExplanation, STATUS_INFO);
        setStatus("Loading local Llama model...", STATUS_INFO, false);

        explanationProvider.explainSecurityEvent(
                        type,
                        evidence,
                        classification,
                        indicators,
                        new ExplanationProvider.Callback() {

                            @Override
                            public void onSuccess(String explanation) {
                                runOnUiThread(() -> {
                                    if (!isActivityUsable()) {
                                        return;
                                    }
                                    isExplaining = false;
                                    btnAnalyze.setEnabled(
                                            classifier != null && classifier.isModelLoaded());
                                    btnExplain.setEnabled(true);
                                    progressBar.setVisibility(View.GONE);
                                    txtExplanation.setText(
                                            "AI EXPLANATION — " + type + "\n\n" + explanation);
                                    setFeedbackBackground(txtExplanation, STATUS_SUCCESS);
                                    setStatus("AI explanation completed. Llama resources released.",
                                            STATUS_SUCCESS, false);
                                });
                            }

                            @Override
                            public void onError(String message) {
                                runOnUiThread(() -> {
                                    if (!isActivityUsable()) {
                                        return;
                                    }
                                    isExplaining = false;
                                    btnAnalyze.setEnabled(
                                            classifier != null && classifier.isModelLoaded());
                                    btnExplain.setEnabled(true);
                                    progressBar.setVisibility(View.GONE);
                                    txtExplanation.setText(
                                            "AI EXPLANATION — " + type
                                                    + "\n\nExplanation failed:\n" + message);
                                    setFeedbackBackground(txtExplanation, STATUS_ERROR);
                                    setStatus("AI explanation failed", STATUS_ERROR, true);
                                });
                            }
                        });
    }

    private void loadLatestBackgroundSmsResult() {

        android.content.SharedPreferences preferences =
                getSharedPreferences(
                        "OnDeviceGuardSecurityEvents",
                        MODE_PRIVATE);

        String body = preferences.getString("LATEST_SMS_BODY", null);
        if (body == null || body.trim().isEmpty()) {
            return;
        }

        String sender = preferences.getString("LATEST_SMS_SENDER", "Unknown");
        String label = preferences.getString("LATEST_SMS_LABEL", "UNKNOWN");
        float confidence = preferences.getFloat("LATEST_SMS_CONFIDENCE", 0f);
        String indicatorText = preferences.getString("LATEST_SMS_INDICATORS", "");
        long timestamp = preferences.getLong("LATEST_SMS_TIMESTAMP", 0L);
        long urlTimestamp = preferences.getLong("LATEST_URL_TIMESTAMP", 0L);
        long networkTimestamp = preferences.getLong("LATEST_NETWORK_TIMESTAMP", 0L);
        if (urlTimestamp > timestamp || networkTimestamp > timestamp) {
            return;
        }

        List<String> indicators = new java.util.ArrayList<>();
        if (!indicatorText.trim().isEmpty()) {
            indicators.addAll(java.util.Arrays.asList(indicatorText.split("\n")));
        }

        latestExplanationType = "SMS";
        latestEvidence = body;
        latestClassification = label;
        latestIndicators = indicators;
        latestMessage = body;
        latestResult = new MessageClassification(
                label,
                confidence,
                indicators);

        editMessage.setText(body);
        editMessage.setSelection(editMessage.getText().length());

        String display = "BACKGROUND SMS DETECTION\n\n"
                + "Sender: " + sender + "\n"
                + "Result: " + label.toUpperCase(Locale.ROOT) + "\n"
                + "Confidence: " + String.format(Locale.US, "%.1f%%", confidence * 100f)
                + "\nReceived: "
                + (timestamp > 0
                ? android.text.format.DateFormat.format("dd MMM yyyy, hh:mm a", timestamp)
                : "Unknown")
                + "\n\nMessage:\n" + body
                + "\n\nIndicators:\n"
                + (indicatorText.isEmpty() ? "No indicators supplied." : indicatorText);

        txtDetectionResult.setText(display);
        setFeedbackBackground(
                txtDetectionResult,
                "SCAM".equalsIgnoreCase(label)
                        || "SUSPICIOUS".equalsIgnoreCase(label)
                        || "PHISHING".equalsIgnoreCase(label)
                        ? STATUS_ERROR : STATUS_SUCCESS);
        btnExplain.setEnabled(true);
        txtExplanation.setText("Background SMS result is ready. Select Explain with AI.");
        setFeedbackBackground(txtExplanation, STATUS_INFO);
    }

    private boolean areLlamaFilesReady() {
        File directory = new File(getFilesDir(), "llama");
        File model = new File(directory, MODEL_FILE);
        File tokenizer = new File(directory, TOKENIZER_FILE);

        return model.isFile()
                && model.length() == MODEL_SIZE
                && tokenizer.isFile()
                && tokenizer.length() == TOKENIZER_SIZE;
    }

    private void setStatus(
            String message,
            int statusType,
            boolean notify) {

        txtProtectionStatus.setText(message);

        int backgroundColor;
        int foregroundColor;

        if (statusType == STATUS_SUCCESS) {
            backgroundColor = getColor(R.color.status_success_container);
            foregroundColor = getColor(R.color.status_success_text);
        } else if (statusType == STATUS_WARNING) {
            backgroundColor = getColor(R.color.status_warning_container);
            foregroundColor = getColor(R.color.status_warning_text);
        } else if (statusType == STATUS_ERROR) {
            backgroundColor = getColor(R.color.status_error_container);
            foregroundColor = getColor(R.color.status_error_text);
        } else {
            backgroundColor = getColor(R.color.status_info_container);
            foregroundColor = getColor(R.color.status_info_text);
        }

        txtProtectionStatus.setBackgroundTintList(
                ColorStateList.valueOf(backgroundColor));
        txtProtectionStatus.setTextColor(foregroundColor);

        if (notify && statusType == STATUS_ERROR) {
            showErrorNotification(message);
        }
    }

    private void setFeedbackBackground(
            TextView view,
            int statusType) {

        int backgroundColor;
        int foregroundColor;

        if (statusType == STATUS_SUCCESS) {
            backgroundColor = getColor(R.color.status_success_container);
            foregroundColor = getColor(R.color.status_success_text);
        } else if (statusType == STATUS_WARNING) {
            backgroundColor = getColor(R.color.status_warning_container);
            foregroundColor = getColor(R.color.status_warning_text);
        } else if (statusType == STATUS_ERROR) {
            backgroundColor = getColor(R.color.status_error_container);
            foregroundColor = getColor(R.color.status_error_text);
        } else {
            backgroundColor = getColor(R.color.status_info_container);
            foregroundColor = getColor(R.color.status_info_text);
        }

        view.setBackgroundTintList(
                ColorStateList.valueOf(backgroundColor));
        view.setTextColor(foregroundColor);
    }

    private void createErrorNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    ERROR_CHANNEL_ID,
                    "OnDeviceGuard errors",
                    NotificationManager.IMPORTANCE_DEFAULT);

            channel.setDescription(
                    "Important model and protection errors");

            NotificationManager manager =
                    getSystemService(NotificationManager.class);

            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    private void showErrorNotification(String message) {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(
                Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            return;
        }

        NotificationManager manager =
                (NotificationManager) getSystemService(
                        NOTIFICATION_SERVICE);

        if (manager == null) {
            return;
        }

        Notification.Builder builder;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(this, ERROR_CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }

        Notification notification = builder
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("OnDeviceGuard needs attention")
                .setContentText(message)
                .setStyle(new Notification.BigTextStyle().bigText(message))
                .setAutoCancel(true)
                .build();

        try {
            manager.notify(
                    (int) (System.currentTimeMillis() & 0x7fffffff),
                    notification);
        } catch (SecurityException ignored) {
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (resourceMonitor != null) {
            resourceMonitor.start();
        }
        loadLatestBackgroundSmsResult();
        loadLatestUrlResult();
        loadLatestNetworkResult();
    }

    private void loadLatestUrlResult() {
        android.content.SharedPreferences preferences =
                getSharedPreferences("OnDeviceGuardSecurityEvents", MODE_PRIVATE);
        String url = preferences.getString("LATEST_URL", null);
        long urlTime = preferences.getLong("LATEST_URL_TIMESTAMP", 0L);
        long smsTime = preferences.getLong("LATEST_SMS_TIMESTAMP", 0L);
        long networkTime = preferences.getLong("LATEST_NETWORK_TIMESTAMP", 0L);
        if (url == null || urlTime < smsTime || urlTime < networkTime) {
            return;
        }
        latestExplanationType = "URL";
        latestEvidence = url;
        latestClassification = preferences.getString(
                "LATEST_URL_LABEL", "HEURISTIC RESULT");
        String indicatorsText = preferences.getString(
                "LATEST_URL_INDICATORS", "");
        latestIndicators = indicatorsText.trim().isEmpty()
                ? java.util.Collections.emptyList()
                : java.util.Arrays.asList(indicatorsText.split("\n"));
        txtUrlResult.setText(
                "URL: " + url + "\nResult: " + latestClassification
                        + "\n\nIndicators:\n"
                        + (indicatorsText.isEmpty()
                        ? "No heuristic indicators." : indicatorsText)
                        + "\n\nHeuristic-only scan. URL ML model was not included.");
        btnExplain.setEnabled(true);
        txtExplanation.setText("Latest URL event ready. Select Explain with AI.");
        setFeedbackBackground(txtExplanation, STATUS_INFO);
    }

    private void loadLatestNetworkResult() {
        android.content.SharedPreferences preferences =
                getSharedPreferences("OnDeviceGuardSecurityEvents", MODE_PRIVATE);
        String domain = preferences.getString("LATEST_NETWORK_DOMAIN", null);
        if (domain == null || domain.trim().isEmpty()) {
            return;
        }
        String label = preferences.getString("LATEST_NETWORK_LABEL", "OBSERVED");
        String indicatorsText = preferences.getString("LATEST_NETWORK_INDICATORS", "");
        long networkTime = preferences.getLong("LATEST_NETWORK_TIMESTAMP", 0L);
        long smsTime = preferences.getLong("LATEST_SMS_TIMESTAMP", 0L);
        long urlTime = preferences.getLong("LATEST_URL_TIMESTAMP", 0L);
        if (networkTime < smsTime || networkTime < urlTime) {
            return;
        }
        latestExplanationType = "NETWORK";
        latestEvidence = domain;
        latestClassification = label;
        latestIndicators = indicatorsText.trim().isEmpty()
                ? java.util.Collections.singletonList(
                        "Domain observed by DNS monitoring; no 20-feature flow prediction was run.")
                : java.util.Arrays.asList(indicatorsText.split("\n"));
        txtNetworkStatus.setText(
                "Latest DNS event: " + domain + "\n" + label
                        + "\nAI flow prediction: not run");
        setFeedbackBackground(txtNetworkStatus, STATUS_WARNING);
        btnExplain.setEnabled(true);
        txtExplanation.setText("Network event ready. Select Explain with AI.");
        setFeedbackBackground(txtExplanation, STATUS_INFO);
    }

    @Override
    protected void onPause() {
        if (resourceMonitor != null) {
            resourceMonitor.stop();
        }
        super.onPause();
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

        if (resourceMonitor != null) {
            resourceMonitor.stop();
        }

        if (networkReceiverRegistered) {
            try {
                unregisterReceiver(networkStatusReceiver);
            } catch (Exception ignored) {
            }
            networkReceiverRegistered = false;
        }

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