package com.cyenx.clashmi.clashmi_vpn_service

import java.io.File
import org.json.JSONObject

/**
 * Per-app routing selected in Clash Mi ("extension.tun.per_app" of the final
 * patch). [whiteList] true means only [packageIds] are routed into the VPN,
 * otherwise [packageIds] are excluded from it.
 */
internal data class PerAppConfig(
    val whiteList: Boolean,
    val packageIds: List<String>,
) {
    companion object {
        fun fromFinalPatchFile(path: String, ownPackage: String): PerAppConfig? {
            if (path.isBlank()) {
                return null
            }
            val file = File(path)
            if (!file.isFile) {
                return null
            }
            return fromFinalPatch(JSONObject(file.readText()), ownPackage)
        }

        fun fromFinalPatch(root: JSONObject, ownPackage: String): PerAppConfig? {
            val perApp = root.optJSONObject("extension")
                ?.optJSONObject("tun")
                ?.optJSONObject("per_app")
                ?: return null
            if (!perApp.optBoolean("enable", false)) {
                return null
            }
            val ids = perApp.optJSONArray("package_ids") ?: return null
            val packageIds = (0 until ids.length())
                .map { ids.optString(it).trim() }
                .filter { it.isNotEmpty() && it != ownPackage }
                .distinct()
            if (packageIds.isEmpty()) {
                return null
            }
            return PerAppConfig(perApp.optBoolean("white_list", false), packageIds)
        }
    }
}
