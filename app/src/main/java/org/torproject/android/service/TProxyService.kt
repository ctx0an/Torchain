package org.torproject.android.service

import com.torchain.android.util.Logger

/**
 * JNI bridge for `libhev-socks5-tunnel.so` (extracted from Orbot).
 *
 * WHY THIS CLASS EXISTS (root cause of the "VPN doesn't connect / crashes
 * after connect" bug):
 *
 * The bundled `libhev-socks5-tunnel.so` was built by the Orbot project. In its
 * `JNI_OnLoad` it calls `RegisterNatives` to bind its native C functions to
 * Java methods on the class whose fully-qualified name is exactly
 *
 *     org.torproject.android.service.TProxyService
 *
 * (confirmed by inspecting the .so: the only JNI class-name string it embeds
 * is `org/torproject/android/service/TProxyService`, and the method names are
 * `TProxyStartService` / `TProxyStopService` / `TProxyGetStats`).
 *
 * The previous Torchain wrapper declared these as `@JvmStatic external` on a
 * class at `hev.sockstun.TProxyService`. Because that class path does NOT
 * match what `RegisterNatives` is looking for, the native methods were never
 * bound. The very first call to `TProxyService.TProxyStartService(...)` then
 * threw `UnsatisfiedLinkError` — an `Error` subclass that the original
 * `catch (Exception)` did not catch, which aborted the process (the
 * "crash after connect" symptom) or, with my Throwable catch, silently left
 * the VPN tunnel dead (the "VPN doesn't connect" symptom).
 *
 * The fix is to declare the bridge class at the exact package/class name the
 * native library expects, so `RegisterNatives` succeeds and the JNI binding
 * is established at `System.loadLibrary("hev-socks5-tunnel")` time.
 *
 * Method signatures (verified against Orbot 17.9.5 classes3.dex):
 *   TProxyStartService(Ljava/lang/String;I)V   — (configPath, tunFd)
 *   TProxyStopService()V
 *   TProxyGetStats()[J
 */
class TProxyService {
    companion object {
        @Volatile
        private var isLibLoaded = false

        init {
            try {
                System.loadLibrary("hev-socks5-tunnel")
                isLibLoaded = true
                Logger.i("TProxyService", "libhev-socks5-tunnel loaded + JNI natives registered")
            } catch (e: Throwable) {
                isLibLoaded = false
                Logger.e("TProxyService", "Failed to load libhev-socks5-tunnel: ${e.message}", e)
            }
        }

        fun isAvailable(): Boolean = isLibLoaded

        @JvmStatic
        external fun TProxyStartService(configPath: String, fd: Int)

        @JvmStatic
        external fun TProxyStopService()

        @JvmStatic
        external fun TProxyGetStats(): LongArray
    }
}
