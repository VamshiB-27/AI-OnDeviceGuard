package com.vcs.ondeviceguard.network;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import com.vcs.ondeviceguard.security.UrlScanResult;
import com.vcs.ondeviceguard.security.UrlThreatScanner;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

public final class NetworkProtectionService extends VpnService {

    public static final String ACTION_START =
            "com.vcs.ondeviceguard.network.START";
    public static final String ACTION_STOP =
            "com.vcs.ondeviceguard.network.STOP";
    public static final String ACTION_STATUS =
            "com.vcs.ondeviceguard.network.STATUS";
    public static final String EXTRA_STATUS = "status";
    public static final String EXTRA_DOMAIN = "domain";
    public static final String EXTRA_BLOCKED = "blocked";
    public static final String EXTRA_DETAIL = "detail";

    private static final String CHANNEL_ID = "network_protection";
    private static final String THREAT_CHANNEL_ID = "network_threats";
    private static final int FOREGROUND_NOTIFICATION_ID = 4102;
    private static final int THREAT_NOTIFICATION_ID = 4104;

    private static final long ALERT_COOLDOWN_MS =
            30L * 60L * 1000L;

    private static final String VPN_ADDRESS = "10.77.0.1";
    private static final String DNS_ADDRESS = "10.77.0.2";
    private static final String UPSTREAM_DNS = "1.1.1.1";
    private static final String BLOCKLIST_ASSET = "network_blocklist.txt";

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final UrlThreatScanner scanner = new UrlThreatScanner();
    private final ConcurrentHashMap<String, Long> lastAlertTimes =
            new ConcurrentHashMap<>();

    private volatile Set<String> blockedDomains =
            Collections.emptySet();

    private ParcelFileDescriptor vpnInterface;
    private Thread workerThread;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopProtection();
            return START_NOT_STICKY;
        }

        if (running.get()) {
            return START_NOT_STICKY;
        }

        createNotificationChannels();
        startForeground(
                FOREGROUND_NOTIFICATION_ID,
                buildForegroundNotification("DNS monitoring is active"));

        try {
            blockedDomains = loadBlocklist();
            establishVpn();
            running.set(true);
            sendStatus("DNS monitoring is active. Local blocklist and URL heuristics are enabled; AI flow classification is not active because the 20 CICIDS2017 flow features are not collected.");

            workerThread = new Thread(
                    this::readDnsPackets,
                    "OnDeviceGuard-DNS");
            workerThread.start();
        } catch (Exception error) {
            sendStatus("Network protection failed: " + safeMessage(error));
            stopProtection();
        }

        return START_NOT_STICKY;
    }

    private Set<String> loadBlocklist() throws Exception {
        Set<String> result = new HashSet<>();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(
                        getAssets().open(BLOCKLIST_ASSET),
                        StandardCharsets.UTF_8))) {

            String line;
            while ((line = reader.readLine()) != null) {
                String domain = line.trim().toLowerCase(Locale.ROOT);

                if (domain.isEmpty() || domain.startsWith("#")) {
                    continue;
                }

                if (isValidDomain(domain)) {
                    result.add(domain);
                }
            }
        }

        return Collections.unmodifiableSet(result);
    }

    private boolean isValidDomain(String domain) {
        if (domain == null || domain.length() > 253
                || domain.isEmpty() || domain.startsWith(".")
                || domain.endsWith(".")) {
            return false;
        }

        String[] labels = domain.split("\\.");
        if (labels.length < 2) {
            return false;
        }

        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63
                    || !label.matches("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")) {
                return false;
            }
        }

        return true;
    }

    private boolean matchesBlocklist(String domain) {
        for (String blocked : blockedDomains) {
            if (domain.equals(blocked)
                    || domain.endsWith("." + blocked)) {
                return true;
            }
        }
        return false;
    }

    private void establishVpn() throws Exception {
        Builder builder = new Builder()
                .setSession("OnDeviceGuard DNS Protection")
                .setMtu(1500)
                .addAddress(VPN_ADDRESS, 30)
                .addDnsServer(DNS_ADDRESS)
                .addRoute(DNS_ADDRESS, 32);

        vpnInterface = builder.establish();

        if (vpnInterface == null) {
            throw new IllegalStateException(
                    "Android did not allow the VPN interface to start.");
        }
    }

    private void readDnsPackets() {
        byte[] packetBuffer = new byte[32767];

        try (FileInputStream input =
                     new FileInputStream(vpnInterface.getFileDescriptor());
             FileOutputStream output =
                     new FileOutputStream(vpnInterface.getFileDescriptor())) {

            while (running.get()) {
                int length = input.read(packetBuffer);

                if (length <= 0) {
                    continue;
                }

                byte[] packet = new byte[length];
                System.arraycopy(packetBuffer, 0, packet, 0, length);

                if (!isIpv4UdpDns(packet)) {
                    continue;
                }

                processDnsPacket(packet, output);
            }
        } catch (Exception error) {
            if (running.get()) {
                sendStatus("DNS monitor stopped: " + safeMessage(error));
            }
        } finally {
            stopProtection();
        }
    }

    private boolean isIpv4UdpDns(byte[] packet) {
        if (packet.length < 28) {
            return false;
        }

        int version = (packet[0] >> 4) & 0x0F;
        int headerLength = (packet[0] & 0x0F) * 4;
        int protocol = packet[9] & 0xFF;

        if (version != 4 || headerLength < 20
                || packet.length < headerLength + 8
                || protocol != 17) {
            return false;
        }

        return unsignedShort(packet, headerLength + 2) == 53;
    }

    private void processDnsPacket(
            byte[] packet,
            FileOutputStream output) {

        try {
            int ipHeaderLength = (packet[0] & 0x0F) * 4;
            int udpOffset = ipHeaderLength;
            int dnsOffset = udpOffset + 8;
            int dnsLength = packet.length - dnsOffset;

            if (dnsLength < 12) {
                return;
            }

            int sourcePort = unsignedShort(packet, udpOffset);
            byte[] dnsQuery = new byte[dnsLength];
            System.arraycopy(packet, dnsOffset, dnsQuery, 0, dnsLength);

            int flags = unsignedShort(dnsQuery, 2);
            if ((flags & 0x8000) != 0) {
                return;
            }

            String domain = extractDomain(dnsQuery);

            if (domain == null || !isValidDomain(domain)) {
                forwardAndReply(packet, dnsQuery, sourcePort, output);
                return;
            }

            if (matchesBlocklist(domain)) {
                byte[] blockedResponse = makeNxDomain(dnsQuery);
                byte[] responsePacket = buildIpv4UdpResponse(
                        packet, sourcePort, blockedResponse);
                output.write(responsePacket);
                output.flush();

                sendThreatAlert(
                        domain,
                        true,
                        "Matched an exact domain or subdomain in the local blocklist.");
                return;
            }

            forwardAndReply(packet, dnsQuery, sourcePort, output);

            UrlScanResult heuristic =
                    scanner.scanUrl("https://" + domain);

            if (heuristic.isSuspicious()) {
                sendThreatAlert(
                        domain,
                        false,
                        String.join(" ", heuristic.getIndicators()));
            }

        } catch (Exception error) {
            sendStatus("DNS request processing error: " + safeMessage(error));
        }
    }

    private void forwardAndReply(
            byte[] packet,
            byte[] dnsQuery,
            int sourcePort,
            FileOutputStream output) throws Exception {

        byte[] dnsResponse = forwardDns(dnsQuery);

        if (dnsResponse != null) {
            byte[] responsePacket = buildIpv4UdpResponse(
                    packet, sourcePort, dnsResponse);
            output.write(responsePacket);
            output.flush();
        }
    }

    private byte[] forwardDns(byte[] query) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            if (!protect(socket)) {
                throw new IllegalStateException(
                        "Unable to protect upstream DNS socket.");
            }

            socket.setSoTimeout(3500);
            InetAddress upstream = InetAddress.getByName(UPSTREAM_DNS);
            socket.send(new DatagramPacket(
                    query, query.length, upstream, 53));

            byte[] response = new byte[4096];
            DatagramPacket received =
                    new DatagramPacket(response, response.length);
            socket.receive(received);

            byte[] exact = new byte[received.getLength()];
            System.arraycopy(
                    received.getData(),
                    received.getOffset(),
                    exact,
                    0,
                    exact.length);
            return exact;
        }
    }

    private String extractDomain(byte[] dns) {
        if (dns.length < 17 || unsignedShort(dns, 4) < 1) {
            return null;
        }

        int cursor = 12;
        StringBuilder domain = new StringBuilder();

        while (cursor < dns.length) {
            int labelLength = dns[cursor++] & 0xFF;

            if (labelLength == 0) {
                break;
            }

            if ((labelLength & 0xC0) != 0
                    || labelLength > 63
                    || cursor + labelLength > dns.length) {
                return null;
            }

            if (domain.length() > 0) {
                domain.append('.');
            }

            domain.append(new String(
                    dns,
                    cursor,
                    labelLength,
                    StandardCharsets.US_ASCII));
            cursor += labelLength;
        }

        if (domain.length() == 0 || cursor + 4 > dns.length) {
            return null;
        }

        return domain.toString().toLowerCase(Locale.ROOT);
    }

    private byte[] makeNxDomain(byte[] query) {
        int questionEnd = 12;

        while (questionEnd < query.length) {
            int labelLength = query[questionEnd++] & 0xFF;

            if (labelLength == 0) {
                break;
            }

            if ((labelLength & 0xC0) != 0
                    || labelLength > 63
                    || questionEnd + labelLength > query.length) {
                return query;
            }

            questionEnd += labelLength;
        }

        questionEnd = Math.min(query.length, questionEnd + 4);
        byte[] response = new byte[questionEnd];
        System.arraycopy(query, 0, response, 0, questionEnd);

        int originalFlags = unsignedShort(response, 2);
        int responseFlags = 0x8000 | 0x0080
                | (originalFlags & 0x0100) | 0x0003;

        putShort(response, 2, responseFlags);
        putShort(response, 4, 1);
        putShort(response, 6, 0);
        putShort(response, 8, 0);
        putShort(response, 10, 0);

        return response;
    }

    private byte[] buildIpv4UdpResponse(
            byte[] request,
            int destinationPort,
            byte[] dnsResponse) {

        int ipLength = 20;
        int udpLength = 8 + dnsResponse.length;
        int totalLength = ipLength + udpLength;
        byte[] response = new byte[totalLength];

        response[0] = 0x45;
        response[1] = 0;
        putShort(response, 2, totalLength);
        putShort(response, 4, unsignedShort(request, 4));
        putShort(response, 6, 0x4000);
        response[8] = 64;
        response[9] = 17;

        byte[] dnsIp = new byte[] {10, 77, 0, 2};
        System.arraycopy(dnsIp, 0, response, 12, 4);
        System.arraycopy(request, 12, response, 16, 4);

        putShort(response, 10, 0);
        putShort(response, 10, checksum(response, 0, 20));

        putShort(response, 20, 53);
        putShort(response, 22, destinationPort);
        putShort(response, 24, udpLength);
        putShort(response, 26, 0);

        System.arraycopy(dnsResponse, 0, response, 28, dnsResponse.length);
        return response;
    }

    private int checksum(byte[] data, int offset, int length) {
        long sum = 0;

        for (int i = offset; i < offset + length; i += 2) {
            int high = data[i] & 0xFF;
            int low = i + 1 < offset + length
                    ? data[i + 1] & 0xFF : 0;
            sum += (high << 8) | low;
        }

        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (int) (~sum) & 0xFFFF;
    }

    private int unsignedShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8)
                | (data[offset + 1] & 0xFF);
    }

    private void putShort(byte[] data, int offset, int value) {
        data[offset] = (byte) ((value >> 8) & 0xFF);
        data[offset + 1] = (byte) (value & 0xFF);
    }

    private void sendThreatAlert(
            String domain,
            boolean blocked,
            String detail) {

        long now = System.currentTimeMillis();
        Long previous = lastAlertTimes.put(domain, now);

        if (previous != null && now - previous < ALERT_COOLDOWN_MS) {
            return;
        }

        String classification = blocked
                ? "BLOCKED — LOCAL DNS BLOCKLIST"
                : "SUSPICIOUS PATTERN — HEURISTIC ONLY";

        getSharedPreferences(
                        "OnDeviceGuardSecurityEvents",
                        MODE_PRIVATE)
                .edit()
                .putString("LATEST_NETWORK_DOMAIN", domain)
                .putString("LATEST_NETWORK_LABEL", classification)
                .putString("LATEST_NETWORK_INDICATORS",
                        detail == null ? "" : detail)
                .putLong("LATEST_NETWORK_TIMESTAMP", now)
                .apply();

        Intent event = new Intent(ACTION_STATUS);
        event.setPackage(getPackageName());
        event.putExtra(EXTRA_STATUS,
                blocked
                        ? "Blocked listed threat domain: " + domain
                        : "Potentially risky domain observed (not blocked): " + domain);
        event.putExtra(EXTRA_DOMAIN, domain);
        event.putExtra(EXTRA_BLOCKED, blocked);
        event.putExtra(EXTRA_DETAIL, detail == null ? "" : detail);
        sendBroadcast(event);

        NotificationManager manager =
                getSystemService(NotificationManager.class);

        if (manager != null) {
            try {
                manager.notify(
                        THREAT_NOTIFICATION_ID,
                        buildThreatNotification(domain, blocked, detail));
            } catch (SecurityException ignored) {
            }
        }
    }

    private void sendStatus(String message) {
        Intent event = new Intent(ACTION_STATUS);
        event.setPackage(getPackageName());
        event.putExtra(EXTRA_STATUS, message);
        sendBroadcast(event);
    }

    private void createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager manager =
                    getSystemService(NotificationManager.class);

            if (manager == null) {
                return;
            }

            NotificationChannel protection = new NotificationChannel(
                    CHANNEL_ID,
                    "Network protection",
                    NotificationManager.IMPORTANCE_LOW);
            protection.setDescription(
                    "Shows whether DNS monitoring is active.");
            manager.createNotificationChannel(protection);

            NotificationChannel threats = new NotificationChannel(
                    THREAT_CHANNEL_ID,
                    "Network threat alerts",
                    NotificationManager.IMPORTANCE_DEFAULT);
            threats.setDescription(
                    "Alerts for domains on the local blocklist or high-risk domain patterns.");
            manager.createNotificationChannel(threats);
        }
    }

    private Notification buildForegroundNotification(String text) {
        Intent stop = new Intent(this, NetworkProtectionService.class);
        stop.setAction(ACTION_STOP);

        PendingIntent pendingStop = PendingIntent.getService(
                this,
                4103,
                stop,
                PendingIntent.FLAG_UPDATE_CURRENT
                        | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder builder = new Notification.Builder(this, CHANNEL_ID);

        return builder
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("OnDeviceGuard network protection")
                .setContentText(text)
                .setOngoing(true)
                .addAction(
                        android.R.drawable.ic_media_pause,
                        "Stop",
                        pendingStop)
                .build();
    }

    private Notification buildThreatNotification(
            String domain,
            boolean blocked,
            String detail) {

        String title = blocked
                ? "OnDeviceGuard blocked a listed domain"
                : "OnDeviceGuard: review this domain";

        String message = blocked
                ? domain + " matched your local blocklist."
                : domain + " has a high-risk pattern. It was not blocked.";

        if (detail != null && !detail.trim().isEmpty()) {
            message += " " + detail;
        }

        return new Notification.Builder(this, THREAT_CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(title)
                .setContentText(message)
                .setStyle(new Notification.BigTextStyle().bigText(message))
                .setAutoCancel(true)
                .build();
    }

    private String safeMessage(Exception error) {
        String message = error.getMessage();
        return message == null
                ? error.getClass().getSimpleName()
                : message;
    }

    private void stopProtection() {
        running.set(false);

        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception ignored) {
            }
            vpnInterface = null;
        }

        if (workerThread != null
                && workerThread != Thread.currentThread()) {
            workerThread.interrupt();
            workerThread = null;
        }

        sendStatus("DNS threat monitoring is stopped.");
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    @Override
    public void onRevoke() {
        stopProtection();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        running.set(false);

        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception ignored) {
            }
            vpnInterface = null;
        }

        super.onDestroy();
    }
}
