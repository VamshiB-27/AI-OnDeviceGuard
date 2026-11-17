package com.vcs.ondeviceguard.network;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import com.vcs.ondeviceguard.R;
import com.vcs.ondeviceguard.security.UrlScanResult;
import com.vcs.ondeviceguard.security.UrlThreatScanner;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
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

    private static final String CHANNEL_ID = "network_protection";
    private static final int NOTIFICATION_ID = 4102;
    private static final String VPN_ADDRESS = "10.77.0.1";
    private static final String DNS_ADDRESS = "10.77.0.2";
    private static final String UPSTREAM_DNS = "1.1.1.1";

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final UrlThreatScanner scanner = new UrlThreatScanner();

    private ParcelFileDescriptor vpnInterface;
    private Thread workerThread;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopProtection();
            return START_NOT_STICKY;
        }

        if (running.get()) {
            return START_STICKY;
        }

        createNotificationChannel();
        startForeground(NOTIFICATION_ID, buildNotification(
                "DNS protection is active"));

        try {
            establishVpn();
            running.set(true);
            sendStatus("DNS threat protection is active");
            workerThread = new Thread(this::readDnsPackets,
                    "OnDeviceGuard-DNS");
            workerThread.start();
        } catch (Exception error) {
            sendStatus("Network protection failed: " + safeMessage(error));
            stopProtection();
        }

        return START_NOT_STICKY;
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

        int destinationPort = unsignedShort(packet,
                headerLength + 2);

        return destinationPort == 53;
    }

    private void processDnsPacket(
            byte[] packet,
            FileOutputStream output) {

        try {
            int ipHeaderLength = (packet[0] & 0x0F) * 4;
            int udpOffset = ipHeaderLength;
            int dnsOffset = udpOffset + 8;
            int dnsLength = packet.length - dnsOffset;

            if (dnsLength < 17) {
                return;
            }

            int sourcePort = unsignedShort(packet, udpOffset);
            byte[] dnsQuery = new byte[dnsLength];
            System.arraycopy(packet, dnsOffset,
                    dnsQuery, 0, dnsLength);

            String domain = extractDomain(dnsQuery);

            if (domain == null || domain.isEmpty()) {
                return;
            }

            UrlScanResult scan = scanner.scanUrl("https://" + domain);

            if (scan.isSuspicious()) {
                byte[] blockedResponse = makeNxDomain(dnsQuery);
                byte[] responsePacket = buildIpv4UdpResponse(
                        packet, sourcePort, blockedResponse);
                output.write(responsePacket);
                output.flush();

                sendDomainAlert(domain, true, scan.getIndicators());
                return;
            }

            byte[] dnsResponse = forwardDns(dnsQuery);

            if (dnsResponse != null) {
                byte[] responsePacket = buildIpv4UdpResponse(
                        packet, sourcePort, dnsResponse);
                output.write(responsePacket);
                output.flush();
            }

            sendDomainAlert(domain, false, null);

        } catch (Exception error) {
            sendStatus("DNS request processing error: " + safeMessage(error));
        }
    }

    private byte[] forwardDns(byte[] query) throws Exception {
        DatagramSocket socket = new DatagramSocket();
        try {
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
            System.arraycopy(received.getData(),
                    received.getOffset(), exact, 0, exact.length);
            return exact;
        } finally {
            socket.close();
        }
    }

    private String extractDomain(byte[] dns) {
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
                    dns, cursor, labelLength,
                    StandardCharsets.US_ASCII));
            cursor += labelLength;
        }

        if (domain.length() == 0 || cursor + 4 > dns.length) {
            return null;
        }

        return domain.toString().toLowerCase(java.util.Locale.ROOT);
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
        int flags = 0x8000 | 0x0080 | (originalFlags & 0x0100) | 0x0003;
        putShort(response, 2, flags);
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

        System.arraycopy(dnsResponse, 0,
                response, 28, dnsResponse.length);

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

    private void sendDomainAlert(
            String domain,
            boolean blocked,
            List<String> indicators) {

        Intent event = new Intent(ACTION_STATUS);
        event.setPackage(getPackageName());
        event.putExtra(EXTRA_STATUS,
                blocked
                        ? "Blocked suspicious DNS domain: " + domain
                        : "DNS request checked: " + domain);
        event.putExtra(EXTRA_DOMAIN, domain);
        event.putExtra(EXTRA_BLOCKED, blocked);
        sendBroadcast(event);

        if (blocked) {
            NotificationManager manager =
                    getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.notify(
                        (int) (System.currentTimeMillis() & 0x7fffffff),
                        buildThreatNotification(domain, indicators));
            }
        }
    }

    private void sendStatus(String message) {
        Intent event = new Intent(ACTION_STATUS);
        event.setPackage(getPackageName());
        event.putExtra(EXTRA_STATUS, message);
        sendBroadcast(event);
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Network threat protection",
                    NotificationManager.IMPORTANCE_LOW);
            channel.setDescription(
                    "Shows when OnDeviceGuard DNS protection is active.");

            NotificationManager manager =
                    getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }

            NotificationChannel threats = new NotificationChannel(
                    "network_threats",
                    "Network threat alerts",
                    NotificationManager.IMPORTANCE_HIGH);
            manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(threats);
            }
        }
    }

    private Notification buildNotification(String text) {
        Intent stop = new Intent(this, NetworkProtectionService.class);
        stop.setAction(ACTION_STOP);
        PendingIntent pendingStop = PendingIntent.getService(
                this, 4103, stop,
                PendingIntent.FLAG_UPDATE_CURRENT
                        | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);

        return builder
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("OnDeviceGuard network protection")
                .setContentText(text)
                .setOngoing(true)
                .addAction(android.R.drawable.ic_media_pause,
                        "Stop", pendingStop)
                .build();
    }

    private Notification buildThreatNotification(
            String domain,
            List<String> indicators) {

        String detail = "Suspicious domain blocked: " + domain;
        if (indicators != null && !indicators.isEmpty()) {
            detail += ". " + indicators.get(0);
        }

        Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, "network_threats")
                : new Notification.Builder(this);

        return builder
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("OnDeviceGuard blocked a domain")
                .setContentText(detail)
                .setStyle(new Notification.BigTextStyle().bigText(detail))
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

        sendStatus("DNS threat protection is stopped");
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
