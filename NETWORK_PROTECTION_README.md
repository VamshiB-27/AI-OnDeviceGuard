# OnDeviceGuard – Network protection update

## What was added

This update adds an Android `VpnService` that intercepts DNS requests sent to the VPN's local DNS address. It checks each queried domain with the existing local `UrlThreatScanner`.

- Domains flagged by the local URL heuristic scanner receive an NXDOMAIN response and are blocked.
- Other DNS requests are forwarded to Cloudflare DNS (`1.1.1.1`) through a protected UDP socket.
- A foreground notification shows that network protection is active.
- The app displays network protection status and posts a notification when a domain is blocked.
- The VPN route is limited to the virtual DNS address; it does not route all device traffic through the service.

## Enable it

1. Install and open OnDeviceGuard.
2. Scroll to **Network threat protection**.
3. Press **Enable network protection**.
4. Approve Android's VPN permission prompt.
5. Keep the service running; use **Stop network protection** or the notification action to stop it.

Android permits only one active VPN per user/profile. Starting this service can replace another VPN.

## Important technical scope

This is live **DNS-based domain threat protection**, not a full packet-flow IDS.

The existing `network_model.json` and `NetworkFlowClassifier.java` remain in the project. That model expects 20 CICIDS2017-style flow statistics (duration, packet counts, byte counts, IAT statistics, TCP flags, etc.). DNS query packets do not contain those 20 features. The app does not fabricate those values or pass DNS data into that model.

A complete live CICIDS2017-style flow IDS would additionally need a packet-forwarding VPN engine or another approved packet/flow capture mechanism, bidirectional flow aggregation, correct extraction of all 20 model features, and performance/accuracy validation. This update does not claim that functionality.

## Limitations of DNS monitoring

- It inspects IPv4 DNS over UDP port 53 routed to the VPN's local DNS address.
- DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), encrypted DNS inside apps, IPv6 DNS, and hard-coded IP connections can bypass this DNS monitor.
- Domain decisions use the existing heuristic URL scanner. They are indicators, not verified threat-intelligence or reputation results. False positives and false negatives are possible.
- Safe DNS requests are forwarded to Cloudflare (`1.1.1.1`), so DNS queries are sent to that resolver.
- The service does not decrypt HTTPS traffic or inspect message contents.

## Build

From the project root on Windows:

```cmd
gradlew clean
gradlew :app:assembleDebug
gradlew :app:testDebugUnitTest
```

## Device tests

1. Enable protection and approve the VPN prompt.
2. Open a normal site and confirm DNS resolution still works.
3. Query a domain that triggers one of the configured heuristic indicators (for example a configured URL shortener domain) and confirm it is blocked.
4. Stop protection and confirm DNS returns to the device's normal resolver.
5. Test with another VPN already active and note that Android allows only one active VPN per profile.
6. Test on Wi-Fi and mobile data.
7. Test with Android Private DNS enabled/disabled. Private DNS / DoT may bypass this monitor.
