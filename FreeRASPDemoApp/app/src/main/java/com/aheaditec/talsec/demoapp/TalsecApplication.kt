package com.aheaditec.talsec.demoapp

import android.app.Activity
import android.app.Application
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.WindowManager.SCREEN_RECORDING_STATE_VISIBLE
import com.aheaditec.talsec_security.security.api.SuspiciousAppInfo
import com.aheaditec.talsec_security.security.api.Talsec
import com.aheaditec.talsec_security.security.api.TalsecConfig
import com.aheaditec.talsec_security.security.api.ThreatListener
import java.util.function.Consumer

class TalsecApplication : Application(), ThreatListener.ThreatDetected {

    private var currentActivity: Activity? = null
    private var screenCaptureCallback: Activity.ScreenCaptureCallback? = null
    private val screenRecordCallback: Consumer<Int> = Consumer<Int> { state ->
        if (state == SCREEN_RECORDING_STATE_VISIBLE) {
            Talsec.onScreenRecordingDetected()
        }
    }

    override fun onCreate() {
        super.onCreate()

        // Uncomment the following Log.e(...) to get your expectedSigningCertificateHashBase64
        // Copy the result from logcat and assign to expectedSigningCertificateHashBase64
         Log.e("SigningCertificateHash", Utils.computeSigningCertificateHash(this))

        FridaDetector.startMonitoring(this) { reason ->
            Log.e(TAG, "Frida detected: $reason")

            android.os.Handler(mainLooper).post {
                currentActivity?.finishAffinity()
                android.os.Process.killProcess(android.os.Process.myPid())
                kotlin.system.exitProcess(0)
            }
        }

        val config = TalsecConfig.Builder(
            expectedPackageName,
            expectedSigningCertificateHashBase64)
            .watcherMail(watcherMail)
            .supportedAlternativeStores(supportedAlternativeStores)
            .prod(isProd)
            .build()
        
        ThreatListener(this, deviceStateListener).registerListener(this)
        Talsec.start(this, config)

        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: Activity, bundle: Bundle?) {

                // Set to 'true' to block screen capture
                Talsec.blockScreenCapture(activity, false)
            }

            override fun onActivityStarted(activity: Activity) {
                unregisterCallbacks()
                currentActivity = activity
                registerCallbacks(activity)
            }

            override fun onActivityResumed(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}

            override fun onActivityStopped(activity: Activity) {
                if (activity == currentActivity) {
                    unregisterCallbacks()
                    currentActivity = null
                }
            }

            override fun onActivitySaveInstanceState(activity: Activity, bundle: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        })
    }

    private fun registerCallbacks(activity: Activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            screenCaptureCallback = Activity.ScreenCaptureCallback {
                Talsec.onScreenshotDetected()
            }
            activity.registerScreenCaptureCallback(
                baseContext.mainExecutor, screenCaptureCallback!!
            )
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            val initialState = activity.windowManager.addScreenRecordingCallback(
                mainExecutor, screenRecordCallback
            )
            screenRecordCallback.accept(initialState)
        }
    }

    private fun unregisterCallbacks() {
        currentActivity?.let { activity ->
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE && screenCaptureCallback != null) {
                activity.unregisterScreenCaptureCallback(screenCaptureCallback!!)
                screenCaptureCallback = null
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
                activity.windowManager.removeScreenRecordingCallback(screenRecordCallback)
            }
        }
    }
    override fun onRootDetected() =
        SecurityState.setRoot(true).also {
            Log.d(TAG, "onRootDetected → setRoot(true)")
        }

    override fun onEmulatorDetected() =
        SecurityState.setEmulator(true).also {
            Log.d(TAG, "onEmulatorDetected → setEmulator(true)")
        }

    override fun onDebuggerDetected() =
        SecurityState.setDebugger(true).also {
            Log.d(TAG, "onDebuggerDetected → setDebugger(true)")
        }

    override fun onTamperDetected() =
        SecurityState.setTamper(true).also {
            Log.d(TAG, "onTamperDetected → setTamper(true)")
        }

    override fun onUntrustedInstallationSourceDetected() =
        SecurityState.setUntrustedSource(true).also {
            Log.d(TAG, "onUntrustedInstallationSourceDetected → setUntrustedSource(true)")
        }

    override fun onHookDetected() =
        SecurityState.setHook(true).also {
            Log.d(TAG, "onHookDetected → setHook(true)")
        }

    override fun onDeviceBindingDetected() =
        SecurityState.setDeviceBinding(true).also {
            Log.d(TAG, "onDeviceBindingDetected → setDeviceBinding(true)")
        }

    override fun onObfuscationIssuesDetected() =
        SecurityState.setObfuscationIssues(true).also {
            Log.d(TAG, "onObfuscationIssuesDetected → setObfuscationIssues(true)")
        }

    override fun onScreenshotDetected() =
        SecurityState.setScreenshot(true).also {
            Log.d(TAG, "onScreenshotDetected → setScreenshot(true)")
        }

    override fun onScreenRecordingDetected() =
        SecurityState.setScreenRecording(true).also {
            Log.d(TAG, "onScreenRecordingDetected → setScreenRecording(true)")
        }

    override fun onMultiInstanceDetected() =
        SecurityState.setMultiInstance(true).also {
            Log.d(TAG, "onMultiInstanceDetected → setMultiInstance(true)")
        }

    override fun onMalwareDetected(list: List<SuspiciousAppInfo?>?) =
        SecurityState.setMalware(list?.filterNotNull()?.isNotEmpty() == true).also {
            Log.d(TAG, "onMalwareDetected → ${list?.size ?: 0} suspicious apps")
        }




    // This is optional. Use only if you are interested in device state information like device lock and HW backed keystore state
    private val deviceStateListener = object : ThreatListener.DeviceState {
        override fun onUnlockedDeviceDetected() =
            SecurityState.setUnlockedDevice(true).also {
                Log.d(TAG, "onUnlockedDeviceDetected → setUnlockedDevice(true)")
            }

        override fun onHardwareBackedKeystoreNotAvailableDetected() =
            SecurityState.setHwKeystoreMissing(true).also {
                Log.d(TAG, "onHardwareBackedKeystoreNotAvailableDetected → setHwKeystoreMissing(true)")
            }

        override fun onDeveloperModeDetected() =
            SecurityState.setDeveloperMode(true).also {
                Log.d(TAG, "onDeveloperModeDetected → setDeveloperMode(true)")
            }

        override fun onADBEnabledDetected() =
            SecurityState.setAdbEnabled(true).also {
                Log.d(TAG, "onADBEnabledDetected → setAdbEnabled(true)")
            }

        override fun onSystemVPNDetected() =
            SecurityState.setSystemVpn(true).also {
                Log.d(TAG, "onSystemVPNDetected → setSystemVpn(true)")
            }
    }
    override fun onTerminate() {
        super.onTerminate()
        FridaDetector.stopMonitoring()
    }
    companion object {
        private const val expectedPackageName = "com.aheaditec.talsec.demoapp" // Don't use Context.getPackageName!
        val expectedSigningCertificateHashBase64 = arrayOf(
            "mVr/qQLO8DKTwqlL+B1qigl9NoBnbiUs8b4c2Ewcz0k=",
            "cVr/qQLO8DKTwqlL+B1qigl9NoBnbiUs8b4c2Ewcz0m=",
            "R5nxbQKTORHylpuWiuSeDnI2UnRAROqgri41xaNNyqU=",
            "ysAbnW7/bbtjvkEBdebcNtJn7yLn1yPgwD/zkejWOXo="
        ) // Replace with your release (!) signing certificate hashes
        private const val watcherMail = "john@example.com" // for Alerts and Reports
        private val supportedAlternativeStores = arrayOf(
            // Google Play Store and Huawei AppGallery are supported out of the box, you can pass empty array or null or add other stores like the Samsung's one:
            "com.sec.android.app.samsungapps" // Samsung Store
        )
        private val isProd = true
        private const val TAG = "TalsecEvents"



    }
}
