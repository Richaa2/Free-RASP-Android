package com.aheaditec.talsec.demoapp
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

data class SecurityFlags(
    val isRoot: Boolean = false,
    val isEmulator: Boolean = false,
    val isDebugger: Boolean = false,
    val isTamper: Boolean = false,
    val isUntrustedInstallationSource: Boolean = false,
    val isHook: Boolean = false,
    val isDeviceBinding: Boolean = false,
    val isObfuscationIssues: Boolean = false,
    val isMalware: Boolean = false,
    val isScreenshot: Boolean = false,
    val isScreenRecording: Boolean = false,
    val isMultiInstance: Boolean = false,
    val isUnlockedDevice: Boolean = false,
    val isHardwareBackedKeystoreNotAvailable: Boolean = false,
    val isDeveloperMode: Boolean = false,
    val isADBEnabled: Boolean = false,
    val isSystemVPN: Boolean = false,
)

object SecurityState {
    private val _flags = MutableStateFlow(SecurityFlags())
    val flags: StateFlow<SecurityFlags> = _flags

    fun setRoot(v: Boolean = true) = _flags.update { it.copy(isRoot = v) }
    fun setEmulator(v: Boolean = true) = _flags.update { it.copy(isEmulator = v) }
    fun setDebugger(v: Boolean = true) = _flags.update { it.copy(isDebugger = v) }
    fun setTamper(v: Boolean = true) = _flags.update { it.copy(isTamper = v) }
    fun setUntrustedSource(v: Boolean = true) = _flags.update { it.copy(isUntrustedInstallationSource = v) }
    fun setHook(v: Boolean = true) = _flags.update { it.copy(isHook = v) }
    fun setDeviceBinding(v: Boolean = true) = _flags.update { it.copy(isDeviceBinding = v) }
    fun setObfuscationIssues(v: Boolean = true) = _flags.update { it.copy(isObfuscationIssues = v) }
    fun setMalware(v: Boolean = true) = _flags.update { it.copy(isMalware = v) }
    fun setScreenshot(v: Boolean = true) = _flags.update { it.copy(isScreenshot = v) }
    fun setScreenRecording(v: Boolean = true) = _flags.update { it.copy(isScreenRecording = v) }
    fun setMultiInstance(v: Boolean = true) = _flags.update { it.copy(isMultiInstance = v) }
    fun setUnlockedDevice(v: Boolean = true) = _flags.update { it.copy(isUnlockedDevice = v) }
    fun setHwKeystoreMissing(v: Boolean = true) = _flags.update { it.copy(isHardwareBackedKeystoreNotAvailable = v) }
    fun setDeveloperMode(v: Boolean = true) = _flags.update { it.copy(isDeveloperMode = v) }
    fun setAdbEnabled(v: Boolean = true) = _flags.update { it.copy(isADBEnabled = v) }
    fun setSystemVpn(v: Boolean = true) = _flags.update { it.copy(isSystemVPN = v) }
}