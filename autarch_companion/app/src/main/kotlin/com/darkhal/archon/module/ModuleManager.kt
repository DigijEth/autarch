package com.darkhal.archon.module

import android.content.Context
import android.util.Log

/**
 * Central registry for Archon modules.
 * Modules register at init time and can be discovered/invoked by the UI.
 */
object ModuleManager {

    private const val TAG = "ModuleManager"
    private val modules = mutableListOf<ArchonModule>()
    private var initialized = false

    fun init() {
        if (initialized) return
        register(ShieldModule())
        register(HoneypotModule())
        register(ReverseShellModule())
        initialized = true
        Log.i(TAG, "Initialized with ${modules.size} modules")
    }

    fun register(module: ArchonModule) {
        if (modules.none { it.id == module.id }) {
            modules.add(module)
            Log.i(TAG, "Registered module: ${module.id} (${module.name})")
        }
    }

    fun getAll(): List<ArchonModule> = modules.toList()

    fun get(id: String): ArchonModule? = modules.find { it.id == id }

    fun executeAction(moduleId: String, actionId: String, context: Context): ModuleResult {
        val module = get(moduleId)
            ?: return ModuleResult(false, "Module not found: $moduleId")
        return module.executeAction(actionId, context)
    }
}
