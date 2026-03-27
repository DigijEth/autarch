package com.darkhal.archon.util

import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit

data class ShellResult(
    val stdout: String,
    val stderr: String,
    val exitCode: Int
)

object ShellExecutor {

    private const val DEFAULT_TIMEOUT_SEC = 10L

    fun execute(command: String, timeoutSec: Long = DEFAULT_TIMEOUT_SEC): ShellResult {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", command))
            val completed = process.waitFor(timeoutSec, TimeUnit.SECONDS)

            if (!completed) {
                process.destroyForcibly()
                return ShellResult("", "Command timed out after ${timeoutSec}s", -1)
            }

            val stdout = BufferedReader(InputStreamReader(process.inputStream)).readText().trim()
            val stderr = BufferedReader(InputStreamReader(process.errorStream)).readText().trim()

            ShellResult(stdout, stderr, process.exitValue())
        } catch (e: Exception) {
            ShellResult("", "Error: ${e.message}", -1)
        }
    }

    fun executeAsRoot(command: String, timeoutSec: Long = DEFAULT_TIMEOUT_SEC): ShellResult {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", command))
            val completed = process.waitFor(timeoutSec, TimeUnit.SECONDS)

            if (!completed) {
                process.destroyForcibly()
                return ShellResult("", "Command timed out after ${timeoutSec}s", -1)
            }

            val stdout = BufferedReader(InputStreamReader(process.inputStream)).readText().trim()
            val stderr = BufferedReader(InputStreamReader(process.errorStream)).readText().trim()

            ShellResult(stdout, stderr, process.exitValue())
        } catch (e: Exception) {
            ShellResult("", "Root error: ${e.message}", -1)
        }
    }

    fun isRootAvailable(): Boolean {
        val result = execute("which su")
        return result.exitCode == 0 && result.stdout.isNotEmpty()
    }
}
