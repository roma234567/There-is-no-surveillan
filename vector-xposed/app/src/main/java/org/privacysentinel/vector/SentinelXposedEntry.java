package org.privacysentinel.vector;

import android.os.Process;
import android.util.Log;

import androidx.annotation.NonNull;

import java.util.concurrent.atomic.AtomicBoolean;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

/**
 * Privacy Sentinel — Modern Vector / LibXposed API 102 Entry Point.
 *
 * Compatible with:
 *  - Vector v2.2+ (LibXposed API 102, hot reload supported)
 *  - Android 17 (API 37) / HyperOS 4 on POCO X6 5G (garnet, Linux 5.10)
 *  - BakaSU (KernelSU + built-in SuSFS), Play Integrity Fix v4.9, Tricky Store, ViPER4Android
 */
public final class SentinelXposedEntry extends XposedModule {

    private static final String TAG = "PrivacySentinel";
    private final AtomicBoolean mInitialized = new AtomicBoolean(false);
    private volatile String mLastPackage;

    public SentinelXposedEntry() {
        super();
    }

    @Override
    public void onModuleLoaded(@NonNull ModuleLoadedParam param) {
        log(Log.INFO, TAG, "Loaded into process=" + param.getProcessName()
                + " (systemServer=" + param.isSystemServer()
                + ", framework=" + getFrameworkName() + " " + getFrameworkVersion() + ")");
    }

    @Override
    public void onSystemServerStarting(@NonNull SystemServerStartingParam param) {
        if (!mInitialized.compareAndSet(false, true)) return;
        SystemServerIpcHooks.install(this, param.getClassLoader());
        log(Log.INFO, TAG, "Installed Android 17 system_server IPC & Deep-Sleep hooks");
    }

    @Override
    public void onPackageReady(@NonNull PackageReadyParam param) {
        if (!param.isFirstPackage()) return;

        final String pkg = param.getPackageName();
        final int uid = param.getApplicationInfo().uid;

        /* Zero-Touch Compatibility Guard for Play Integrity Fix, Tricky Store & Root Apps */
        if (uid < 10000 || SentinelBridgeClient.isZeroTouchPackage(pkg)) {
            return;
        }
        int flags = SentinelBridgeClient.getUidFlags(uid);
        if ((flags & SentinelBridgeClient.POL_EXEMPT_ZERO_TOUCH) != 0) {
            return;
        }

        if (!mInitialized.compareAndSet(false, true)) return;
        mLastPackage = pkg;

        PrivacySpoofHooks.install(this, pkg, uid);
        AntiSpyHooks.install(this, pkg, uid);
    }

    @Override
    public boolean onHotReloading(@NonNull HotReloadingParam param) {
        if (mLastPackage != null) {
            param.setSavedInstanceState(mLastPackage);
        }
        return true;
    }

    @Override
    public void onHotReloaded(@NonNull HotReloadedParam param) {
        for (XposedInterface.HookHandle handle : param.getOldHookHandles()) {
            handle.unhook();
        }
        mInitialized.set(false);
        if (!param.isSystemServer() && param.getSavedInstanceState() instanceof String) {
            String pkg = (String) param.getSavedInstanceState();
            int uid = Process.myUid();
            if (uid >= 10000 && !SentinelBridgeClient.isZeroTouchPackage(pkg)) {
                PrivacySpoofHooks.install(this, pkg, uid);
                AntiSpyHooks.install(this, pkg, uid);
            }
        }
        log(Log.INFO, TAG, "LibXposed API 102 hot-reload completed cleanly");
    }
}
