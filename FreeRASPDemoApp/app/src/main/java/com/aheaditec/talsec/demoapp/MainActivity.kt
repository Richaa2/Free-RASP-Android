package com.aheaditec.talsec.demoapp

import android.os.Bundle
import android.view.LayoutInflater
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.aheaditec.talsec_security.security.api.SuspiciousAppInfo
import com.aheaditec.talsec_security.security.api.ThreatListener
import com.google.android.material.chip.Chip
import com.google.android.material.snackbar.Snackbar

class MainActivity : AppCompatActivity() {

    private lateinit var chipRoot: Chip
    private lateinit var chipDebugger: Chip
    private lateinit var chipEmulator: Chip
    private lateinit var chipTamper: Chip
    private lateinit var chipUntrustedSource: Chip
    private lateinit var chipHook: Chip
    private lateinit var chipDeviceBinding: Chip
    private lateinit var chipObfuscation: Chip
    private lateinit var chipScreenshot: Chip
    private lateinit var chipScreenRecord: Chip
    private lateinit var chipMultiInstance: Chip
    private lateinit var chipMalware: Chip
    private lateinit var chipUnlockedDevice: Chip
    private lateinit var chipHardwareBackedKeystore: Chip
    private lateinit var chipDeveloperMode: Chip
    private lateinit var chipAdbEnabled: Chip
    private lateinit var chipSystemVpn: Chip
    private lateinit var signingCertificateHash: TextView

    private lateinit var tvLog: TextView
    private lateinit var malwareContainer: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        chipRoot = findViewById(R.id.chipRoot)
        chipDebugger = findViewById(R.id.chipDebugger)
        chipEmulator = findViewById(R.id.chipEmulator)
        chipTamper = findViewById(R.id.chipTamper)
        chipUntrustedSource = findViewById(R.id.chipUntrustedSource)
        chipHook = findViewById(R.id.chipHook)
        chipDeviceBinding = findViewById(R.id.chipDeviceBinding)
        chipObfuscation = findViewById(R.id.chipObfuscation)
        chipScreenshot = findViewById(R.id.chipScreenshot)
        chipScreenRecord = findViewById(R.id.chipScreenRecord)
        chipMultiInstance = findViewById(R.id.chipMultiInstance)
        chipMalware = findViewById(R.id.chipMalware)
        chipUnlockedDevice = findViewById(R.id.chipUnlockedDevice)
        chipHardwareBackedKeystore = findViewById(R.id.chipHardwareBackedKeystore)
        chipDeveloperMode = findViewById(R.id.chipDeveloperMode)
        chipAdbEnabled = findViewById(R.id.chipAdbEnabled)
        chipSystemVpn = findViewById(R.id.chipSystemVpn)
        tvLog = findViewById(R.id.tvLog)
        malwareContainer = findViewById(R.id.malwareContainer)
        signingCertificateHash = findViewById(R.id.tvSigningCertificateHash)


        listOf(
            chipRoot, chipDebugger, chipEmulator, chipTamper, chipUntrustedSource,
            chipHook, chipDeviceBinding, chipObfuscation, chipScreenshot, chipScreenRecord, chipMultiInstance,
            chipMalware, chipUnlockedDevice, chipHardwareBackedKeystore, chipDeveloperMode, chipAdbEnabled, chipSystemVpn
        ).forEach { setChipSafe(it) }


        lifecycleScope.launchWhenStarted {
            SecurityState.flags.collect { f ->
                renderFlags(f)
            }
        }

        signingCertificateHash.append("\n\n${Utils.computeSigningCertificateHash(this)} \n\n Expected:\n ${TalsecApplication.expectedSigningCertificateHashBase64.joinToString(",\n\n")}")

        log("Security dashboard ready")
    }
    private fun renderFlags(f: SecurityFlags) {

        if (f.isRoot) setChipAlert(chipRoot, "Root detected") else setChipSafe(chipRoot)
        if (f.isEmulator) setChipAlert(chipEmulator, "Emulator detected") else setChipSafe(chipEmulator)
        if (f.isDebugger) setChipAlert(chipDebugger, "Debugger detected") else setChipSafe(chipDebugger)
        if (f.isTamper) setChipAlert(chipTamper, "Tamper detected") else setChipSafe(chipTamper)
        if (f.isUntrustedInstallationSource) setChipAlert(chipUntrustedSource, "Untrusted source detected") else setChipSafe(chipUntrustedSource)
        if (f.isHook) setChipAlert(chipHook, "Hooking detected") else setChipSafe(chipHook)
        if (f.isDeviceBinding) setChipAlert(chipDeviceBinding, "Device binding detected") else setChipSafe(chipDeviceBinding)
        if (f.isObfuscationIssues) setChipAlert(chipObfuscation, "Obfuscation issues") else setChipSafe(chipObfuscation)
        if (f.isScreenshot) setChipAlert(chipScreenshot, "Screenshot captured") else setChipSafe(chipScreenshot)
        if (f.isScreenRecording) setChipAlert(chipScreenRecord, "Screen recording detected") else setChipSafe(chipScreenRecord)
        if (f.isMultiInstance) setChipAlert(chipMultiInstance, "Multi-instance detected") else setChipSafe(chipMultiInstance)

        if (f.isMalware) setChipAlert(chipMalware, "Malware detected") else setChipSafe(chipMalware)
        if (f.isUnlockedDevice) setChipAlert(chipUnlockedDevice, "Unlocked device") else setChipSafe(chipUnlockedDevice)
        if (f.isHardwareBackedKeystoreNotAvailable) setChipAlert(chipHardwareBackedKeystore, "HW Keystore missing") else setChipSafe(chipHardwareBackedKeystore)
        if (f.isDeveloperMode) setChipAlert(chipDeveloperMode, "Developer mode enabled") else setChipSafe(chipDeveloperMode)
        if (f.isADBEnabled) setChipAlert(chipAdbEnabled, "ADB enabled") else setChipSafe(chipAdbEnabled)
        if (f.isSystemVPN) setChipAlert(chipSystemVpn, "System VPN active") else setChipSafe(chipSystemVpn)
    }

    private fun setChipAlert(chip: Chip, message: String) = runOnUiThread {
        chip.apply {
            isCheckable = false
            isClickable = false
            text = message
            setChipBackgroundColorResource(android.R.color.holo_red_light)
            setTextColor(getColor(android.R.color.white))
        }
        Snackbar.make(findViewById(android.R.id.content), message, Snackbar.LENGTH_LONG).show()
        log("⚠️ $message")
    }

    private fun setChipSafe(chip: Chip) = runOnUiThread {
        chip.apply {
            isCheckable = false
            isClickable = false

            setChipBackgroundColorResource(android.R.color.holo_green_light)
            setTextColor(getColor(android.R.color.black))
        }
    }

    private fun log(text: String) = runOnUiThread {
        tvLog.append("• $text\n")
    }

//    private fun addMalwareRow(app: SuspiciousAppInfo) = runOnUiThread {
//        val row = LayoutInflater.from(this).inflate(android.R.layout.simple_list_item_2, malwareContainer, false)
//        row.findViewById<TextView>(android.R.id.text1).text = app.b ?: app.packageInfo.packageName ?: "(unknown)"
//        row.findViewById<TextView>(android.R.id.text2).text = app.packageInfo.packageName ?: ""
//        malwareContainer.addView(row)
//    }
}