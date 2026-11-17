package com.vcs.ondeviceguard;

import android.app.ActivityManager;
import android.content.Context;
import android.os.Debug;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;

import java.util.Locale;

public final class DeviceResourceMonitor {

    public interface Listener {
        void onUpdate(String text);
    }

    private final Context context;
    private final Listener listener;
    private final Handler handler = new Handler(Looper.getMainLooper());

    private long previousCpuTime;
    private long previousWallTime;
    private boolean running;

    private final Runnable updateTask = new Runnable() {
        @Override
        public void run() {
            if (!running) {
                return;
            }

            listener.onUpdate(readMetrics());
            handler.postDelayed(this, 1000L);
        }
    };

    public DeviceResourceMonitor(
            Context context,
            Listener listener) {
        this.context = context.getApplicationContext();
        this.listener = listener;
    }

    public void start() {
        if (running) {
            return;
        }

        running = true;
        previousCpuTime = Process.getElapsedCpuTime();
        previousWallTime = SystemClock.elapsedRealtime();
        handler.removeCallbacks(updateTask);
        handler.post(updateTask);
    }

    public void stop() {
        running = false;
        handler.removeCallbacks(updateTask);
    }

    private String readMetrics() {
        long currentCpuTime = Process.getElapsedCpuTime();
        long currentWallTime = SystemClock.elapsedRealtime();

        long cpuDelta = Math.max(0L, currentCpuTime - previousCpuTime);
        long wallDelta = Math.max(1L, currentWallTime - previousWallTime);

        previousCpuTime = currentCpuTime;
        previousWallTime = currentWallTime;

        double cpuPercent = Math.min(
                100.0,
                (cpuDelta * 100.0) / wallDelta);

        Debug.MemoryInfo processMemory = new Debug.MemoryInfo();
        Debug.getMemoryInfo(processMemory);

        double appPssMb = processMemory.getTotalPss() / 1024.0;

        ActivityManager activityManager =
                (ActivityManager) context.getSystemService(
                        Context.ACTIVITY_SERVICE);

        ActivityManager.MemoryInfo deviceMemory =
                new ActivityManager.MemoryInfo();

        if (activityManager != null) {
            activityManager.getMemoryInfo(deviceMemory);
        }

        double availableRamMb =
                deviceMemory.availMem / (1024.0 * 1024.0);

        double totalRamMb =
                deviceMemory.totalMem / (1024.0 * 1024.0);

        double usedRamMb =
                Math.max(0.0, totalRamMb - availableRamMb);

        return String.format(
                Locale.US,
                "CPU (app process)   %.1f%%\n"
                        + "App RAM (PSS)       %.1f MB\n"
                        + "Device RAM used     %.0f / %.0f MB\n"
                        + "Device RAM available %.0f MB",
                cpuPercent,
                appPssMb,
                usedRamMb,
                totalRamMb,
                availableRamMb);
    }
}
