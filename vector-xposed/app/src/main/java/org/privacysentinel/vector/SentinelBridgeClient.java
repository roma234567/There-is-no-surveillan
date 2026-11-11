package org.privacysentinel.vector;

import android.app.ActivityManager;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Process;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Lock-free policy reader (via read-only policy.mmap) & non-blocking UNIX socket
 * telemetry/prompt client for Privacy Sentinel Vector (LibXposed API 102) hooks.
 */
public final class SentinelBridgeClient {

    public static final int MAGIC = 0x50534E54; // "PSNT"
    public static final String POLICY_MMAP_PATH = "/data/adb/privacy_sentinel/run/policy.mmap";
    public static final String CTRL_SOCK_PATH   = "/data/adb/privacy_sentinel/run/sentinel.sock";
    public static final String DGRAM_SOCK_PATH  = "/data/adb/privacy_sentinel/run/telemetry.sock";

    /* Category Bitmasks (match sentinel_protocol.h) */
    public static final int CAT_NETWORK   = 1 << 0;
    public static final int CAT_DATA      = 1 << 1;
    public static final int CAT_AUTOSTART = 1 << 2;
    public static final int CAT_DANGER    = 1 << 3;
    public static final int CAT_IPC       = 1 << 4;
    public static final int CAT_SANDBOX   = 1 << 5;

    /* Actions */
    public static final int ACT_OBSERVED    = 0;
    public static final int ACT_SILENT_DROP = 1;
    public static final int ACT_REJECT_ERR  = 2;
    public static final int ACT_SPOOFED     = 3;

    /* Per-UID Policy Flags (match SentinelUidFlags in sentinel_protocol.h) */
    public static final int POL_EXEMPT_ZERO_TOUCH   = 1 << 0;
    public static final int POL_BLOCK_NETWORK       = 1 << 1;
    public static final int POL_SLEEP_SELECTED      = 1 << 2;
    public static final int POL_BLOCK_BG_IPC        = 1 << 3;
    public static final int POL_BLOCK_AUTOSTART     = 1 << 4;
    public static final int POL_IPC_REJECT_EXPLICIT = 1 << 5;
    public static final int POL_SANDBOX_FS_L1       = 1 << 6;
    public static final int POL_SANDBOX_KERNEL_L2   = 1 << 7;
    public static final int POL_ASK_INTERACTIVE     = 1 << 8;
    public static final int POL_SPOOF_DETERMINISTIC = 1 << 9;
    public static final int POL_SPOOF_EPHEMERAL     = 1 << 10;
    public static final int POL_SPOOF_CUSTOM        = 1 << 11;
    public static final int POL_ANTISPY_BG_MIC_CAM  = 1 << 12;
    public static final int POL_ANTISPY_BG_CLIP     = 1 << 13;
    public static final int POL_TRAP_ROOT_SCAN      = 1 << 14;

    private static volatile MappedByteBuffer sPolicyMap;
    private static final int EPHEMERAL_SALT = (int) (System.nanoTime() & 0x7FFFFFFFL);

    private SentinelBridgeClient() {}

    public static boolean isZeroTouchPackage(String pkg) {
        if (pkg == null) return true;
        return pkg.equals("com.google.android.gms")
                || pkg.startsWith("com.google.android.gms.")
                || pkg.equals("com.google.android.gsf")
                || pkg.equals("com.android.vending")
                || pkg.equals("com.xiaomi.finddevice");
    }

    private static MappedByteBuffer ensureMapped() {
        MappedByteBuffer existing = sPolicyMap;
        if (existing != null) return existing;
        synchronized (SentinelBridgeClient.class) {
            if (sPolicyMap != null) return sPolicyMap;
            try {
                File f = new File(POLICY_MMAP_PATH);
                if (!f.exists() || !f.canRead()) return null;
                try (RandomAccessFile raf = new RandomAccessFile(f, "r");
                     FileChannel ch = raf.getChannel()) {
                    MappedByteBuffer buf = ch.map(FileChannel.MapMode.READ_ONLY, 0, ch.size());
                    buf.order(ByteOrder.LITTLE_ENDIAN);
                    if (buf.getInt(0) == MAGIC) {
                        sPolicyMap = buf;
                    }
                }
            } catch (Throwable ignored) {
                // Fail-open cleanly if SELinux or startup order hasn't created mmap yet
            }
            return sPolicyMap;
        }
    }

    public static int getUidFlags(int uid) {
        MappedByteBuffer buf = ensureMapped();
        if (buf == null) return 0;
        try {
            byte safeBypass = buf.get(21);
            if (safeBypass != 0) return 0;
            int appId = uid % 100000;
            if (appId < 0 || appId >= 32768) return 0;
            return buf.getInt(24 + appId * 4);
        } catch (Throwable ignored) {
            return 0;
        }
    }

    public static int getMasterSeed() {
        MappedByteBuffer buf = ensureMapped();
        if (buf == null) return 0xA17B510;
        try {
            return buf.getInt(16);
        } catch (Throwable ignored) {
            return 0xA17B510;
        }
    }

    public static boolean isCurrentProcessBackground() {
        try {
            ActivityManager.RunningAppProcessInfo info = new ActivityManager.RunningAppProcessInfo();
            ActivityManager.getMyMemoryState(info);
            return info.importance > ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Generates a deterministic per-package (HMAC-like SHA-256) or ephemeral hex digest
     * so each app receives a realistic, consistent device identity across restarts.
     */
    public static byte[] deriveSpoofBytes(String packageName, String domain, boolean ephemeral) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            int seed = ephemeral ? EPHEMERAL_SALT : getMasterSeed();
            String input = seed + ":" + packageName + ":" + domain;
            return md.digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (Throwable t) {
            return new byte[]{0x42, 0x17, 0x51, 0x0A, 0x33, 0x7F, 0x19, 0x2C, 0x61, 0x55, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        }
    }

    /**
     * Fire-and-forget binary datagram matching struct SentinelTelemetryPacket (448 bytes).
     */
    public static void emitTelemetryAsync(
            final int uid,
            final int targetUid,
            final int category,
            final int severity,
            final int action,
            final boolean isBg,
            final String pkg,
            final String type,
            final String target,
            final String detail) {
        try {
            ByteBuffer bb = ByteBuffer.allocate(448).order(ByteOrder.LITTLE_ENDIAN);
            bb.putInt(MAGIC);
            bb.putInt(uid);
            bb.putInt(Process.myPid());
            bb.putInt(targetUid);
            bb.putShort((short) category);
            bb.put((byte) severity);
            bb.put((byte) action);
            bb.put((byte) (isBg ? 1 : 0));
            bb.put(new byte[3]); // reserved[3]
            putFixedCString(bb, pkg, 96);
            putFixedCString(bb, type, 40);
            putFixedCString(bb, target, 128);
            putFixedCString(bb, detail, 160);

            try (LocalSocket sock = new LocalSocket(LocalSocket.SOCKET_DGRAM)) {
                sock.connect(new LocalSocketAddress(DGRAM_SOCK_PATH, LocalSocketAddress.Namespace.FILESYSTEM));
                sock.setSoTimeout(5);
                OutputStream os = sock.getOutputStream();
                os.write(bb.array());
            }
        } catch (Throwable ignored) {
            // Never disrupt host process if telemetry socket is busy
        }
    }

    /**
     * Sends a bounded RPC command to sentineld (used by system_server Power/Prompt hooks).
     */
    public static String sendControlRpc(String jsonLine, int timeoutMs) {
        try (LocalSocket sock = new LocalSocket(LocalSocket.SOCKET_STREAM)) {
            sock.connect(new LocalSocketAddress(CTRL_SOCK_PATH, LocalSocketAddress.Namespace.FILESYSTEM));
            sock.setSoTimeout(timeoutMs);
            OutputStream os = sock.getOutputStream();
            if (!jsonLine.endsWith("\n")) jsonLine = jsonLine + "\n";
            os.write(jsonLine.getBytes(StandardCharsets.UTF_8));
            os.flush();
            BufferedReader br = new BufferedReader(new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
            return br.readLine();
        } catch (Throwable ignored) {
            return null; // Fail-Open
        }
    }

    private static void putFixedCString(ByteBuffer bb, String s, int maxLen) {
        byte[] out = new byte[maxLen];
        if (s != null && !s.isEmpty()) {
            byte[] raw = s.getBytes(StandardCharsets.UTF_8);
            int copy = Math.min(raw.length, maxLen - 1);
            System.arraycopy(raw, 0, out, 0, copy);
        }
        bb.put(out);
    }
}
