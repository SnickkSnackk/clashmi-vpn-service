package com.cyenx.clashmi.clashmi_vpn_service

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.system.OsConstants
import android.util.Log
import com.cyenx.clashmi.core.clashmicore.PackageNameResolver
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Resolves the package that owns a connection seen on the TUN interface.
 *
 * ConnectivityManager.getConnectionOwnerUid only answers for connections the
 * VPN applies to. An app excluded from the VPN that binds its socket to the tun
 * interface (SO_BINDTODEVICE) gets INVALID_UID, so an empty result lets core
 * rules reject such connections.
 */
internal class ConnectionOwnerResolver(private val context: Context) : PackageNameResolver {
    private val connectivityManager = context.getSystemService(ConnectivityManager::class.java)
    private val packageNames = ConcurrentHashMap<Int, String>()

    override fun findPackageName(
        network: String,
        srcIP: String,
        srcPort: Long,
        dstIP: String,
        dstPort: Long,
    ): String {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return ""
        }
        val protocol = when (network) {
            "tcp" -> OsConstants.IPPROTO_TCP
            "udp" -> OsConstants.IPPROTO_UDP
            else -> return ""
        }
        return try {
            val uid = connectivityManager.getConnectionOwnerUid(
                protocol,
                InetSocketAddress(InetAddress.getByName(srcIP), srcPort.toInt()),
                InetSocketAddress(InetAddress.getByName(dstIP), dstPort.toInt()),
            )
            if (uid == Process.INVALID_UID) "" else packageNameForUid(uid)
        } catch (error: Throwable) {
            Log.w(TAG, "connection owner lookup failed network=$network: ${error.message}")
            ""
        }
    }

    private fun packageNameForUid(uid: Int): String {
        packageNames[uid]?.let { return it }
        val name = if (uid == Process.myUid()) {
            context.packageName
        } else {
            val packageManager = context.packageManager
            val packages = packageManager.getPackagesForUid(uid)
            when {
                packages != null && packages.size == 1 -> packages[0]
                else -> packageManager.getNameForUid(uid)
            }
        }
        // A known uid without a package (system services) is still a
        // connection the VPN applies to, so it must not look unknown.
        val resolved = name?.takeIf { it.isNotEmpty() } ?: "android.uid.$uid"
        packageNames[uid] = resolved
        return resolved
    }

    companion object {
        private const val TAG = "ClashMiVpnService"
    }
}
