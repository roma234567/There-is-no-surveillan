package org.privacysentinel.vector;

import android.app.AlertDialog;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Binder;
import android.os.Handler;
import android.os.Looper;
import android.view.WindowManager;

import java.lang.reflect.Method;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

/**
 * System-Server IPC Firewall, Deep-Sleep Screen Monitor, and Native Android 17
 * Interactive Allow/Deny Permission Dialog Engine (runs inside "android" process).
 */
public final class SystemServerIpcHooks {

    private SystemServerIpcHooks() {}

    public static void install(final XposedModule module, final ClassLoader sysClassLoader) {
        hookBroadcastDispatch(module, sysClassLoader);
        hookServiceWakeups(module, sysClassLoader);
        hookContentProviderIpc(module, sysClassLoader);
        hookPowerScreenState(module, sysClassLoader);
    }

    private static void hookBroadcastDispatch(final XposedModule module, ClassLoader cl) {
        try {
            Class<?> amsClass = Class.forName("com.android.server.am.ActivityManagerService", false, cl);
            for (Method m : amsClass.getDeclaredMethods()) {
                if (!m.getName().equals("broadcastIntentWithFeature")) continue;
                module.hook(m)
                        .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                        .setId("ams_broadcast_ipc")
                        .intercept(chain -> {
                            int callingUid = Binder.getCallingUid();
                            if (callingUid >= 10000) {
                                Intent intent = findIntentArg(chain.getArgs().toArray());
                                if (intent != null) {
                                    Decision dec = evaluateIpcCall(callingUid, "BROADCAST", intent);
                                    if (dec == Decision.SILENT_DROP) {
                                        return 0; // ActivityManager.BROADCAST_SUCCESS (silent drop)
                                    } else if (dec == Decision.REJECT_EXPLICIT) {
                                        throw new SecurityException("Privacy Sentinel: IPC Broadcast blocked");
                                    }
                                }
                            }
                            return chain.proceed();
                        });
            }
        } catch (Throwable t) {
            module.log(android.util.Log.WARN, "PrivacySentinel", "AMS broadcast hook skipped: " + t.getMessage());
        }
    }

    private static void hookServiceWakeups(final XposedModule module, ClassLoader cl) {
        try {
            Class<?> activeServices = Class.forName("com.android.server.am.ActiveServices", false, cl);
            for (Method m : activeServices.getDeclaredMethods()) {
                String name = m.getName();
                if (!name.equals("startServiceLocked") && !name.equals("bindServiceLocked")) continue;
                module.hook(m)
                        .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                        .setId("ams_service_" + name + "_" + m.getParameterCount())
                        .intercept(chain -> {
                            int callingUid = Binder.getCallingUid();
                            if (callingUid >= 10000) {
                                Intent serviceIntent = findIntentArg(chain.getArgs().toArray());
                                if (serviceIntent != null) {
                                    String targetPkg = extractTargetPackage(serviceIntent);
                                    int flags = SentinelBridgeClient.getUidFlags(callingUid);
                                    if ((flags & (SentinelBridgeClient.POL_BLOCK_BG_IPC
                                            | SentinelBridgeClient.POL_SANDBOX_KERNEL_L2)) != 0
                                            && targetPkg != null) {
                                        Decision dec = evaluateIpcCall(callingUid, "SERVICE_WAKEUP", serviceIntent);
                                        if (dec == Decision.SILENT_DROP) {
                                            return name.equals("bindServiceLocked") ? 0 : null;
                                        } else if (dec == Decision.REJECT_EXPLICIT) {
                                            throw new SecurityException("Privacy Sentinel: Cross-app Service wakeup denied");
                                        }
                                    }
                                }
                            }
                            return chain.proceed();
                        });
            }
        } catch (Throwable t) {
            module.log(android.util.Log.WARN, "PrivacySentinel", "ActiveServices hook skipped: " + t.getMessage());
        }
    }

    private static void hookContentProviderIpc(final XposedModule module, ClassLoader cl) {
        try {
            Class<?> cph = Class.forName("com.android.server.am.ContentProviderHelper", false, cl);
            for (Method m : cph.getDeclaredMethods()) {
                if (!m.getName().equals("getContentProviderImpl")) continue;
                module.hook(m)
                        .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                        .setId("ams_provider_ipc")
                        .intercept(chain -> {
                            int callingUid = Binder.getCallingUid();
                            if (callingUid >= 10000) {
                                Object[] args = chain.getArgs().toArray();
                                String authority = args.length > 1 && args[1] instanceof String ? (String) args[1] : null;
                                if (authority != null && isSensitiveProviderAuthority(authority)) {
                                    int flags = SentinelBridgeClient.getUidFlags(callingUid);
                                    SentinelBridgeClient.emitTelemetryAsync(
                                            callingUid, 1000,
                                            SentinelBridgeClient.CAT_DATA | SentinelBridgeClient.CAT_IPC,
                                            2,
                                            (flags & SentinelBridgeClient.POL_SANDBOX_KERNEL_L2) != 0
                                                    ? SentinelBridgeClient.ACT_SILENT_DROP
                                                    : SentinelBridgeClient.ACT_OBSERVED,
                                            false, "", "CONTENT_PROVIDER", authority,
                                            "Cross-process ContentProvider query intercepted in system_server");
                                    if ((flags & SentinelBridgeClient.POL_SANDBOX_KERNEL_L2) != 0) {
                                        return null;
                                    }
                                }
                            }
                            return chain.proceed();
                        });
            }
        } catch (Throwable t) {
            module.log(android.util.Log.WARN, "PrivacySentinel", "ContentProviderHelper hook skipped: " + t.getMessage());
        }
    }

    private static void hookPowerScreenState(final XposedModule module, ClassLoader cl) {
        try {
            Class<?> pms = Class.forName("com.android.server.power.PowerManagerService", false, cl);
            for (Method m : pms.getDeclaredMethods()) {
                final String name = m.getName();
                if (!name.equals("goToSleepInternal") && !name.equals("wakeUpInternal")) continue;
                module.hook(m)
                        .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                        .setId("pms_" + name)
                        .intercept(chain -> {
                            Object res = chain.proceed();
                            final boolean sleeping = name.equals("goToSleepInternal");
                            new Thread(() -> SentinelBridgeClient.sendControlRpc(
                                    "{\"cmd\":\"set_global\",\"screen_sleeping\":" + sleeping + "}", 1500
                            )).start();
                            return res;
                        });
            }
        } catch (Throwable ignored) {}
    }

    private enum Decision { ALLOW, SILENT_DROP, REJECT_EXPLICIT }

    private static Decision evaluateIpcCall(int callingUid, String ipcKind, Intent intent) {
        int flags = SentinelBridgeClient.getUidFlags(callingUid);
        if ((flags & SentinelBridgeClient.POL_EXEMPT_ZERO_TOUCH) != 0) return Decision.ALLOW;

        String action = intent.getAction() != null ? intent.getAction() : "(explicit)";
        String targetPkg = extractTargetPackage(intent);
        String summary = ipcKind + " -> " + (targetPkg != null ? targetPkg : "*") + " [" + action + "]";

        boolean shouldBlock = (flags & (SentinelBridgeClient.POL_BLOCK_BG_IPC
                | SentinelBridgeClient.POL_SANDBOX_KERNEL_L2)) != 0;

        if (!shouldBlock) {
            SentinelBridgeClient.emitTelemetryAsync(
                    callingUid, 0, SentinelBridgeClient.CAT_IPC, 1,
                    SentinelBridgeClient.ACT_OBSERVED, false, "", ipcKind, summary,
                    "Cross-app Intent observed in ActivityManagerService");
            return Decision.ALLOW;
        }

        if ((flags & SentinelBridgeClient.POL_ASK_INTERACTIVE) != 0) {
            boolean allowed = promptUserInSystemUiOrDaemon(callingUid, summary);
            if (allowed) return Decision.ALLOW;
        }

        boolean explicitErr = (flags & SentinelBridgeClient.POL_IPC_REJECT_EXPLICIT) != 0;
        SentinelBridgeClient.emitTelemetryAsync(
                callingUid, 0, SentinelBridgeClient.CAT_IPC, 3,
                explicitErr ? SentinelBridgeClient.ACT_REJECT_ERR : SentinelBridgeClient.ACT_SILENT_DROP,
                true, "", ipcKind + "_BLOCK", summary,
                explicitErr ? "Rejected with SecurityException" : "Silently dropped in ActivityManagerService");
        return explicitErr ? Decision.REJECT_EXPLICIT : Decision.SILENT_DROP;
    }

    /**
     * Displays an Android 17 System Permission AlertDialog directly from system_server UI Context
     * (and mirrors it to sentineld so WebUI can also answer). Bounded by 9s latch so AMS never deadlocks.
     */
    public static boolean promptUserInSystemUiOrDaemon(final int uid, final String actionSummary) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            // Never block system_server main UI thread; delegate to sentineld fast check
            return false;
        }
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<Boolean> result = new AtomicReference<>(false);

        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Object currentAt = atClass.getMethod("currentActivityThread").invoke(null);
            final Context uiCtx = (Context) atClass.getMethod("getSystemUiContext").invoke(currentAt);

            new Handler(Looper.getMainLooper()).post(() -> {
                try {
                    AlertDialog dialog = new AlertDialog.Builder(uiCtx)
                            .setTitle("Privacy Sentinel • Запрос доступа")
                            .setMessage("Заблокированное приложение (UID " + uid + ") пытается выполнить:\n\n"
                                    + actionSummary + "\n\nРазрешить это действие?")
                            .setPositiveButton("Разрешить (1 раз)", (d, w) -> {
                                result.set(true);
                                latch.countDown();
                            })
                            .setNegativeButton("Запретить (Silent Drop)", (d, w) -> {
                                result.set(false);
                                latch.countDown();
                            })
                            .setOnCancelListener(d -> {
                                result.set(false);
                                latch.countDown();
                            })
                            .create();
                    if (dialog.getWindow() != null) {
                        dialog.getWindow().setType(WindowManager.LayoutParams.TYPE_SYSTEM_ALERT);
                    }
                    dialog.show();
                } catch (Throwable t) {
                    latch.countDown();
                }
            });

            latch.await(9, TimeUnit.SECONDS);
        } catch (Throwable ignored) {
            return false;
        }
        return Boolean.TRUE.equals(result.get());
    }

    private static Intent findIntentArg(Object[] args) {
        if (args == null) return null;
        for (Object a : args) {
            if (a instanceof Intent) return (Intent) a;
        }
        return null;
    }

    private static String extractTargetPackage(Intent intent) {
        if (intent.getPackage() != null) return intent.getPackage();
        ComponentName cn = intent.getComponent();
        return cn != null ? cn.getPackageName() : null;
    }

    private static boolean isSensitiveProviderAuthority(String auth) {
        return auth.contains("contacts") || auth.contains("call_log")
                || auth.contains("telephony") || auth.contains("sms")
                || auth.contains("media") || auth.contains("settings");
    }
}
