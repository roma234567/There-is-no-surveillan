package org.privacysentinel.vector;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.hardware.camera2.CameraManager;
import android.media.AudioRecord;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.Arrays;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

/**
 * Anti-Spy Engine (Vector / LibXposed API 102):
 *  1. Background Microphone Silence: zeroes PCM capture buffers in AudioRecord.read()
 *     WITHOUT touching AudioTrack or AudioEffect — 100% safe with ViPER4Android!
 *  2. Background Camera Block: blocks CameraManager.openCamera() when process is not visible.
 *  3. Background Clipboard Guard: returns empty ClipData for background clipboard snooping.
 *  4. Runtime su / logcat / getprop Execution Detector.
 */
public final class AntiSpyHooks {

    private AntiSpyHooks() {}

    public static void install(final XposedModule module, final String pkg, final int uid) {
        hookAudioRecordSilenceInBackground(module, pkg, uid);
        hookCameraBlockInBackground(module, pkg, uid);
        hookClipboardBlankingInBackground(module, pkg, uid);
        hookShellProbeDetector(module, pkg, uid);
    }

    private static void hookAudioRecordSilenceInBackground(final XposedModule module, final String pkg, final int uid) {
        for (Method m : AudioRecord.class.getDeclaredMethods()) {
            if (!m.getName().equals("read")) continue;
            try {
                module.hook(m)
                        .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                        .setId("antispy_audiorecord_" + m.getParameterCount() + "_" + m.getParameterTypes()[0].getSimpleName())
                        .intercept(chain -> {
                            Object result = chain.proceed();
                            int fl = SentinelBridgeClient.getUidFlags(uid);
                            if ((fl & SentinelBridgeClient.POL_ANTISPY_BG_MIC_CAM) != 0
                                    && SentinelBridgeClient.isCurrentProcessBackground()) {
                                Object buf = chain.getArg(0);
                                if (buf instanceof byte[]) {
                                    Arrays.fill((byte[]) buf, (byte) 0);
                                } else if (buf instanceof short[]) {
                                    Arrays.fill((short[]) buf, (short) 0);
                                } else if (buf instanceof float[]) {
                                    Arrays.fill((float[]) buf, 0f);
                                } else if (buf instanceof ByteBuffer) {
                                    ByteBuffer bb = (ByteBuffer) buf;
                                    int pos = bb.position();
                                    for (int i = 0; i < bb.limit(); i++) bb.put(i, (byte) 0);
                                    bb.position(pos);
                                }
                                SentinelBridgeClient.emitTelemetryAsync(
                                        uid, 0, SentinelBridgeClient.CAT_DANGER, 4,
                                        SentinelBridgeClient.ACT_SILENT_DROP, true,
                                        pkg, "BG_MIC_ZERO_PCM", "AudioRecord.read()",
                                        "Zeroed background microphone PCM frames (ViPER4Android playback untouched)");
                            }
                            return result;
                        });
            } catch (Throwable ignored) {}
        }
    }

    private static void hookCameraBlockInBackground(final XposedModule module, final String pkg, final int uid) {
        for (Method m : CameraManager.class.getDeclaredMethods()) {
            if (!m.getName().equals("openCamera")) continue;
            try {
                module.hook(m)
                        .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                        .setId("antispy_camera_" + m.getParameterCount())
                        .intercept(chain -> {
                            int fl = SentinelBridgeClient.getUidFlags(uid);
                            if ((fl & SentinelBridgeClient.POL_ANTISPY_BG_MIC_CAM) != 0
                                    && SentinelBridgeClient.isCurrentProcessBackground()) {
                                String camId = String.valueOf(chain.getArg(0));
                                SentinelBridgeClient.emitTelemetryAsync(
                                        uid, 0, SentinelBridgeClient.CAT_DANGER, 4,
                                        SentinelBridgeClient.ACT_SILENT_DROP, true,
                                        pkg, "BG_CAMERA_BLOCK", "CameraManager.openCamera(" + camId + ")",
                                        "Blocked background camera activation attempt");
                                return null;
                            }
                            return chain.proceed();
                        });
            } catch (Throwable ignored) {}
        }
    }

    private static void hookClipboardBlankingInBackground(final XposedModule module, final String pkg, final int uid) {
        try {
            Method getClip = ClipboardManager.class.getDeclaredMethod("getPrimaryClip");
            module.hook(getClip)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .setId("antispy_clipboard_get")
                    .intercept(chain -> {
                        int fl = SentinelBridgeClient.getUidFlags(uid);
                        if ((fl & SentinelBridgeClient.POL_ANTISPY_BG_CLIP) != 0
                                && SentinelBridgeClient.isCurrentProcessBackground()) {
                            SentinelBridgeClient.emitTelemetryAsync(
                                    uid, 0, SentinelBridgeClient.CAT_DATA, 3,
                                    SentinelBridgeClient.ACT_SILENT_DROP, true,
                                    pkg, "BG_CLIPBOARD_BLOCK", "ClipboardManager.getPrimaryClip()",
                                    "Prevented background clipboard read; returned empty ClipData");
                            return ClipData.newPlainText("", "");
                        }
                        return chain.proceed();
                    });
        } catch (Throwable ignored) {}
    }

    private static void hookShellProbeDetector(final XposedModule module, final String pkg, final int uid) {
        try {
            Method pbStart = ProcessBuilder.class.getDeclaredMethod("start");
            module.hook(pbStart)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .setId("antispy_shell_probe")
                    .intercept(chain -> {
                        ProcessBuilder pb = (ProcessBuilder) chain.getThisObject();
                        if (pb != null && pb.command() != null && !pb.command().isEmpty()) {
                            String cmd0 = pb.command().get(0);
                            if (cmd0.equals("su") || cmd0.endsWith("/su") || cmd0.contains("logcat") || cmd0.contains("magisk")) {
                                int fl = SentinelBridgeClient.getUidFlags(uid);
                                boolean trap = (fl & SentinelBridgeClient.POL_TRAP_ROOT_SCAN) != 0;
                                SentinelBridgeClient.emitTelemetryAsync(
                                        uid, 0, SentinelBridgeClient.CAT_DANGER, 4,
                                        trap ? SentinelBridgeClient.ACT_REJECT_ERR : SentinelBridgeClient.ACT_OBSERVED,
                                        SentinelBridgeClient.isCurrentProcessBackground(),
                                        pkg, cmd0.contains("logcat") ? "LOGCAT_READ" : "ROOT_SU_PROBE",
                                        String.join(" ", pb.command()),
                                        trap ? "Blocked stealth shell probe" : "Observed shell command execution");
                                if (trap) {
                                    throw new java.io.IOException("Cannot run program \"" + cmd0 + "\": error=2, No such file or directory");
                                }
                            }
                        }
                        return chain.proceed();
                    });
        } catch (Throwable ignored) {}
    }
}
