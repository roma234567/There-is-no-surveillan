package org.privacysentinel.vector;

import android.content.ContentResolver;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.location.Location;
import android.location.LocationManager;
import android.net.wifi.WifiInfo;
import android.os.Process;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.DisplayMetrics;
import android.webkit.WebSettings;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

/**
 * Data Spoofing & Anti-Fingerprinting Hooks (Vector / LibXposed API 102).
 *
 * Modes supported per-UID:
 *  - POL_SPOOF_DETERMINISTIC : Persistent HMAC-SHA256 mask per package (prevents session loss)
 *  - POL_SPOOF_EPHEMERAL     : Fresh randomized fingerprint on every process launch
 *  - POL_SPOOF_CUSTOM        : User-supplied custom profile values
 */
public final class PrivacySpoofHooks {

    private PrivacySpoofHooks() {}

    public static void install(final XposedModule module, final String pkg, final int uid) {
        hookAndroidId(module, pkg, uid);
        hookTelephonyIdentifiers(module, pkg, uid);
        hookWifiIdentifiers(module, pkg, uid);
        hookLocationSpoofWithJitter(module, pkg, uid);
        hookPackageVisibilityFilter(module, pkg, uid);
        hookAntiFingerprintingEntropy(module, pkg, uid);
    }

    private static boolean isSpoofActive(int flags) {
        return (flags & (SentinelBridgeClient.POL_SPOOF_DETERMINISTIC
                | SentinelBridgeClient.POL_SPOOF_EPHEMERAL
                | SentinelBridgeClient.POL_SPOOF_CUSTOM)) != 0;
    }

    private static boolean isEphemeral(int flags) {
        return (flags & SentinelBridgeClient.POL_SPOOF_EPHEMERAL) != 0;
    }

    private static void hookAndroidId(final XposedModule module, final String pkg, final int uid) {
        try {
            Method getStr = Settings.Secure.class.getDeclaredMethod("getString", ContentResolver.class, String.class);
            module.hook(getStr)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .setId("spoof_android_id")
                    .intercept(chain -> {
                        Object keyObj = chain.getArg(1);
                        if (Settings.Secure.ANDROID_ID.equals(keyObj)) {
                            int fl = SentinelBridgeClient.getUidFlags(uid);
                            if (isSpoofActive(fl)) {
                                byte[] b = SentinelBridgeClient.deriveSpoofBytes(pkg, "android_id", isEphemeral(fl));
                                String fakeAid = toHex(b, 8); // 16 hex chars
                                SentinelBridgeClient.emitTelemetryAsync(
                                        uid, 0, SentinelBridgeClient.CAT_DATA, 2,
                                        SentinelBridgeClient.ACT_SPOOFED,
                                        SentinelBridgeClient.isCurrentProcessBackground(),
                                        pkg, "SPOOF_ANDROID_ID", "Settings.Secure.ANDROID_ID",
                                        "Returned synthetic ID " + fakeAid);
                                return fakeAid;
                            }
                        }
                        return chain.proceed();
                    });
        } catch (Throwable ignored) {}
    }

    private static void hookTelephonyIdentifiers(final XposedModule module, final String pkg, final int uid) {
        String[] methods = {"getImei", "getDeviceId", "getMeid", "getSubscriberId", "getSimSerialNumber", "getLine1Number"};
        for (final String mName : methods) {
            for (Method m : TelephonyManager.class.getDeclaredMethods()) {
                if (!m.getName().equals(mName)) continue;
                try {
                    module.hook(m)
                            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                            .setId("spoof_tel_" + mName + "_" + m.getParameterCount())
                            .intercept(chain -> {
                                int fl = SentinelBridgeClient.getUidFlags(uid);
                                if (isSpoofActive(fl)) {
                                    byte[] b = SentinelBridgeClient.deriveSpoofBytes(pkg, mName, isEphemeral(fl));
                                    String spoofed = mName.equals("getLine1Number")
                                            ? "+79" + toDigits(b, 9)
                                            : generateLuhnImei("86492006", b); // Realistic Xiaomi/POCO TAC prefix
                                    SentinelBridgeClient.emitTelemetryAsync(
                                            uid, 0, SentinelBridgeClient.CAT_DATA, 3,
                                            SentinelBridgeClient.ACT_SPOOFED,
                                            SentinelBridgeClient.isCurrentProcessBackground(),
                                            pkg, "SPOOF_TELEPHONY", "TelephonyManager." + mName,
                                            "Replaced hardware identifier with synthetic Luhn-valid value");
                                    return spoofed;
                                }
                                return chain.proceed();
                            });
                } catch (Throwable ignored) {}
            }
        }
    }

    private static void hookWifiIdentifiers(final XposedModule module, final String pkg, final int uid) {
        try {
            Method getMac = WifiInfo.class.getDeclaredMethod("getMacAddress");
            module.hook(getMac)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .setId("spoof_wifi_mac")
                    .intercept(chain -> {
                        int fl = SentinelBridgeClient.getUidFlags(uid);
                        if (isSpoofActive(fl)) {
                            byte[] b = SentinelBridgeClient.deriveSpoofBytes(pkg, "wifi_mac", isEphemeral(fl));
                            String mac = String.format(Locale.US, "02:%02x:%02x:%02x:%02x:%02x",
                                    b[0] & 0xFF, b[1] & 0xFF, b[2] & 0xFF, b[3] & 0xFF, b[4] & 0xFF);
                            SentinelBridgeClient.emitTelemetryAsync(
                                    uid, 0, SentinelBridgeClient.CAT_DATA, 2,
                                    SentinelBridgeClient.ACT_SPOOFED,
                                    SentinelBridgeClient.isCurrentProcessBackground(),
                                    pkg, "SPOOF_MAC", "WifiInfo.getMacAddress()",
                                    "Returned locally-administered MAC " + mac);
                            return mac;
                        }
                        return chain.proceed();
                    });
        } catch (Throwable ignored) {}
    }

    private static void hookLocationSpoofWithJitter(final XposedModule module, final String pkg, final int uid) {
        try {
            for (Method m : LocationManager.class.getDeclaredMethods()) {
                if (!m.getName().equals("getLastKnownLocation")) continue;
                module.hook(m)
                        .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                        .setId("spoof_loc_last_" + m.getParameterCount())
                        .intercept(chain -> {
                            int fl = SentinelBridgeClient.getUidFlags(uid);
                            if (isSpoofActive(fl)) {
                                byte[] b = SentinelBridgeClient.deriveSpoofBytes(pkg, "gps_coord", isEphemeral(fl));
                                double baseLat = 55.7558 + (((b[0] & 0xFF) - 128) * 0.0004);
                                double baseLon = 37.6173 + (((b[1] & 0xFF) - 128) * 0.0004);
                                // Micro-jitter so anti-fraud never sees frozen static coordinates
                                double jitterLat = ((System.currentTimeMillis() % 97) - 48) * 0.000003;
                                double jitterLon = ((System.currentTimeMillis() % 89) - 44) * 0.000003;
                                Location fake = new Location("gps");
                                fake.setLatitude(baseLat + jitterLat);
                                fake.setLongitude(baseLon + jitterLon);
                                fake.setAccuracy(6.5f);
                                fake.setTime(System.currentTimeMillis());
                                SentinelBridgeClient.emitTelemetryAsync(
                                        uid, 0, SentinelBridgeClient.CAT_DATA, 3,
                                        SentinelBridgeClient.ACT_SPOOFED,
                                        SentinelBridgeClient.isCurrentProcessBackground(),
                                        pkg, "SPOOF_LOCATION", "LocationManager.getLastKnownLocation()",
                                        String.format(Locale.US, "Synthetic GPS %.5f, %.5f (+jitter)", fake.getLatitude(), fake.getLongitude()));
                                return fake;
                            }
                            return chain.proceed();
                        });
            }
        } catch (Throwable ignored) {}
    }

    @SuppressWarnings("unchecked")
    private static void hookPackageVisibilityFilter(final XposedModule module, final String pkg, final int uid) {
        try {
            Class<?> apm = Class.forName("android.app.ApplicationPackageManager");
            for (Method m : apm.getDeclaredMethods()) {
                final String name = m.getName();
                if (!name.equals("getInstalledPackages") && !name.equals("getInstalledApplications")) continue;
                module.hook(m)
                        .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                        .setId("spoof_pkg_list_" + name + "_" + m.getParameterCount())
                        .intercept(chain -> {
                            Object raw = chain.proceed();
                            int fl = SentinelBridgeClient.getUidFlags(uid);
                            if ((fl & (SentinelBridgeClient.POL_TRAP_ROOT_SCAN
                                    | SentinelBridgeClient.POL_SPOOF_DETERMINISTIC
                                    | SentinelBridgeClient.POL_SPOOF_EPHEMERAL)) == 0
                                    || !(raw instanceof List)) {
                                return raw;
                            }
                            List<Object> filtered = new ArrayList<>();
                            for (Object item : (List<Object>) raw) {
                                String itemPkg = null;
                                if (item instanceof PackageInfo) itemPkg = ((PackageInfo) item).packageName;
                                else if (item instanceof ApplicationInfo) itemPkg = ((ApplicationInfo) item).packageName;
                                // Keep self + standard Android packages; hide root/Xposed/other user apps
                                if (itemPkg == null || itemPkg.equals(pkg) || itemPkg.startsWith("com.android.")
                                        || itemPkg.equals("android") || itemPkg.equals("com.google.android.gms")) {
                                    if (itemPkg != null && !isRootOrHookManagerPkg(itemPkg)) {
                                        filtered.add(item);
                                    }
                                }
                            }
                            SentinelBridgeClient.emitTelemetryAsync(
                                    uid, 0, SentinelBridgeClient.CAT_DATA, 2,
                                    SentinelBridgeClient.ACT_SPOOFED,
                                    SentinelBridgeClient.isCurrentProcessBackground(),
                                    pkg, "HIDE_APPLIST", "PackageManager." + name,
                                    "Scrubbed installed app list & root/Xposed managers");
                            return filtered;
                        });
            }
        } catch (Throwable ignored) {}
    }

    private static void hookAntiFingerprintingEntropy(final XposedModule module, final String pkg, final int uid) {
        try {
            Method uaMethod = WebSettings.class.getDeclaredMethod("getDefaultUserAgent", android.content.Context.class);
            module.hook(uaMethod)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .setId("antifp_webview_ua")
                    .intercept(chain -> {
                        String origUa = (String) chain.proceed();
                        int fl = SentinelBridgeClient.getUidFlags(uid);
                        if (!isSpoofActive(fl) || origUa == null) return origUa;
                        // Normalize build tag inside WebView User-Agent to defeat ROM build-id fingerprinting
                        return origUa.replaceAll("Build/[A-Za-z0-9._-]+", "Build/BP1A.260905.014");
                    });

            // Subtle sub-pixel xdpi/ydpi noise against Canvas/Display hardware fingerprinting
            Method getMetrics = android.view.Display.class.getDeclaredMethod("getMetrics", DisplayMetrics.class);
            module.hook(getMetrics)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .setId("antifp_display_metrics")
                    .intercept(chain -> {
                        Object r = chain.proceed();
                        int fl = SentinelBridgeClient.getUidFlags(uid);
                        if (isSpoofActive(fl)) {
                            DisplayMetrics dm = (DisplayMetrics) chain.getArg(0);
                            if (dm != null) {
                                byte[] b = SentinelBridgeClient.deriveSpoofBytes(pkg, "dpi_noise", isEphemeral(fl));
                                float delta = ((b[0] & 0x0F) - 8) * 0.03f;
                                dm.xdpi += delta;
                                dm.ydpi -= delta;
                            }
                        }
                        return r;
                    });
        } catch (Throwable ignored) {}
    }

    private static boolean isRootOrHookManagerPkg(String p) {
        String low = p.toLowerCase(Locale.ROOT);
        return low.contains("kernelsu") || low.contains("bakasu") || low.contains("resukisu")
                || low.contains("ksuwebui") || low.contains("lsposed") || low.contains("vector")
                || low.contains("magisk") || low.contains("privacysentinel") || low.contains("viper4android");
    }

    private static String toHex(byte[] bytes, int numBytes) {
        StringBuilder sb = new StringBuilder(numBytes * 2);
        for (int i = 0; i < numBytes && i < bytes.length; i++) {
            sb.append(String.format(Locale.US, "%02x", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    private static String toDigits(byte[] bytes, int count) {
        StringBuilder sb = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            sb.append(Math.abs(bytes[i % bytes.length]) % 10);
        }
        return sb.toString();
    }

    private static String generateLuhnImei(String tac8, byte[] entropy) {
        StringBuilder body = new StringBuilder(15);
        body.append(tac8);
        for (int i = 0; body.length() < 14; i++) {
            body.append(Math.abs(entropy[i % entropy.length]) % 10);
        }
        int sum = 0;
        for (int i = 0; i < 14; i++) {
            int d = body.charAt(i) - '0';
            if (i % 2 == 1) {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
        }
        int checkDigit = (10 - (sum % 10)) % 10;
        body.append(checkDigit);
        return body.toString();
    }
}
