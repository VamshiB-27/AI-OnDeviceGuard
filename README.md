# OnDeviceAI – On-Device Security & AI

AI-based Android application for offline SMS threat detection, suspicious URL identification, network threat detection, and local AI-powered security explanations.

## Downloads

**Latest Release: [OnDeviceGuard V0.1](https://github.com/VamshiB-27/AI-OnDeviceGuard/releases/tag/v0.1.0)**

Download the required files from the Releases section:

| File | Description |
|---|---|
| `app-debug.apk` | Android application installer |
| `OnDeviceGuard_V0.1.zip` | Android Studio project source code |
| `llama model.zip` | Llama AI model and tokenizer files |

[Download all release assets](https://github.com/VamshiB-27/AI-OnDeviceGuard/releases/tag/v0.1.0)

---

# Installation & Setup Guide

Follow these steps to install and configure OnDeviceAI on your Android device.

## Step 1: Download and Install the App

1. Open the [OnDeviceGuard V0.1 Release](https://github.com/VamshiB-27/AI-OnDeviceGuard/releases/tag/v0.1.0).
2. Download `app-debug.apk`.
3. Open the downloaded APK file.
4. If Android blocks installation, enable **Install unknown apps** for the browser or file manager you used.
5. If Google Play Protect flags or blocks the APK, carefully review its warning and verify the APK's source before proceeding. Do not disable device security protections merely to bypass an unknown warning.
6. Install the application and open OnDeviceAI.
7. Grant SMS permissions if you want to use SMS threat detection.

**Important:**

- OnDeviceAI includes SMS threat detection functionality.
- SMS permissions are required to access messages for this feature.
- Google Play Protect is separate from Android SMS permissions. Disabling it is not inherently required for SMS reading.
- Only install APK files from the trusted project release.

## Step 2: Download the Llama AI Model

1. Open the [latest release](https://github.com/VamshiB-27/AI-OnDeviceGuard/releases/tag/v0.1.0).
2. Download `llama model.zip`.
3. Open your Android File Manager.
4. Locate the downloaded ZIP file.
5. Extract the ZIP file.
6. Make sure the extracted model files are accessible on your device.

**Note:** Do not select the ZIP file directly. Extract it before configuring the AI model.

## Step 3: First-Time AI Configuration

1. Open the OnDeviceAI application.
2. Open any security event that you want explained.
3. Press **Explain with AI**.
4. The app will open the folder/file picker.
5. Navigate to the extracted Llama model files.
6. Select the required **Model** file.
7. When prompted, select the corresponding **Tokenizer**.
8. Wait for the AI model to load successfully.

**Note:** This configuration may need to be repeated if you change the model or clear the app's saved configuration.

## Step 4: Start Using OnDeviceAI

Once the model and tokenizer are configured:

- Open any detected security event.
- Press **Explain with AI**.
- The local Llama model will analyze the security event.
- Read the AI-generated explanation to understand the potential threat and recommended action.

## Step 5: Important Notes

- Ensure your device has sufficient storage for the AI model.
- Ensure your device has sufficient RAM to load and run the model.
- Keep the extracted model files accessible to the application.
- Do not delete the extracted model files if the application still depends on them.
- AI explanations are designed to run locally without cloud-based AI inference.
- Detection models and AI explanations are separate functionalities.

---

## Project Files

- **APK:** Android application installer.
- **Source Code:** Android Studio project.
- **Llama Model:** Local AI model and tokenizer.
- **Technical Report:** Project documentation.

## Setup Complete!

OnDeviceAI is now installed and configured.

You can use its security detection features and **Explain with AI** functionality directly on your Android device.
