package com.darkhal.archon.module

import android.content.Context

/**
 * Interface for Archon extension modules.
 * Modules provide security/privacy actions that run through PrivilegeManager.
 */
interface ArchonModule {
    val id: String
    val name: String
    val description: String
    val version: String

    fun getActions(): List<ModuleAction>
    fun executeAction(actionId: String, context: Context): ModuleResult
    fun getStatus(context: Context): ModuleStatus
}

data class ModuleAction(
    val id: String,
    val name: String,
    val description: String,
    val privilegeRequired: Boolean = true,
    val rootOnly: Boolean = false
)

data class ModuleResult(
    val success: Boolean,
    val output: String,
    val details: List<String> = emptyList()
)

data class ModuleStatus(
    val active: Boolean,
    val summary: String,
    val details: Map<String, String> = emptyMap()
)
