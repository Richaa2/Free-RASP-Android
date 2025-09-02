package com.aheaditec.talsec.demoapp

import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

object FridaDetector {

    private const val TAG = "FridaDetector"
    private val running = AtomicBoolean(false)
    private val handler = Handler(Looper.getMainLooper())
    private var task: Runnable? = null


    private val suspectLibs = listOf(
        "frida", "gadget", "frida-gadget", "frida-agent", "libfrida", "libfrida-gadget",
        "gum-js-loop", "frida-agent-32", "frida-agent-64"
    )

    private const val INTERVAL_MS = 3_000L

    fun startMonitoring(ctx: Context, onDetected: (String) -> Unit) {
        if (running.getAndSet(true)) return
        task = object : Runnable {
            override fun run() {
                try {
                    if (fridaPortsPresent()) {
                        onDetected("Frida server ports visible in /proc/net (27042/27043)")
                    }


                    if (isTracedNow()) {
                        onDetected("Process is traced (TracerPid > 0) — likely Frida attached")
                    }
                    hasFridaLibsInMemoryMaps().let {
                        if (it.first) onDetected("Frida library in /proc/self/maps ${it.second}")
                    }


                    if (hasFridaLibsOnDisk(ctx)) {
                        onDetected("Frida lib found in nativeLibraryDir")
                    }

                } catch (t: Throwable) {
                    Log.w(TAG, "Detection tick error: ${t.message}")
                } finally {
                    if (running.get()) handler.postDelayed(this, INTERVAL_MS)
                }
            }
        }
        handler.post(task!!)
    }

    fun stopMonitoring() {
        running.set(false)
        task?.let { handler.removeCallbacks(it) }
        task = null
    }



    private fun hasFridaLibsInMemoryMaps(): Pair<Boolean, String> {
        return try {
            val maps = File("/proc/self/maps")
            if (!maps.canRead()) return   Pair(false, "")
            val text = maps.readText().lowercase(Locale.US)
            Pair(suspectLibs.any { sig -> text.contains(sig) }, suspectLibs.filter { sig -> text.contains(sig) }.joinToString { it })
        } catch (_: Throwable) {
            Pair(false, "")
        }
    }

    private fun hasFridaLibsOnDisk(context: Context): Boolean {
        return try {
            val libDir = context.applicationInfo.nativeLibraryDir ?: return false
            val dir = File(libDir)
            if (!dir.exists()) return false
            dir.listFiles()?.any { f ->
                val name = f.name.lowercase(Locale.US)
                suspectLibs.any { sig -> name.contains(sig) }
            } ?: false
        } catch (_: Throwable) {
            false
        }
    }

    private val suspectPorts = setOf(27042, 27043, 23946)

    private fun hexPortToInt(hex: String): Int =
        hex.toIntOrNull(16) ?: -1

    private fun isPortInProcNet(file: String, ports: Set<Int>): Boolean {
        return try {
            val f = java.io.File(file)
            if (!f.canRead()) return false
            f.useLines { lines ->
                lines.drop(1).any { line ->

                    val parts = line.trim().split(Regex("\\s+"))
                    if (parts.size > 2) {
                        val local = parts[1]
                        val hexPort = local.substringAfterLast(':')
                        val port = hexPortToInt(hexPort)
                        port in ports
                    } else false
                }
            }
        } catch (_: Throwable) { false }
    }

    private fun fridaPortsPresent(): Boolean =
        isPortInProcNet("/proc/net/tcp", suspectPorts) ||
                isPortInProcNet("/proc/net/tcp6", suspectPorts)

    private fun isTracedNow(): Boolean {
        return try {
            val text = java.io.File("/proc/self/status").readText()
            val line = text.lineSequence().firstOrNull { it.startsWith("TracerPid:") } ?: return false
            val pid = line.substringAfter(":").trim().toIntOrNull() ?: 0
            pid > 0
        } catch (_: Throwable) { false }
    }
}