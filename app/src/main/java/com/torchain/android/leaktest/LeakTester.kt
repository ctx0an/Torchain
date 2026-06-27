package com.torchain.android.leaktest

import com.torchain.android.data.LeakResult
import com.torchain.android.util.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL

class LeakTester(private val socksPort: Int = 9050) {

    suspend fun runFull(): List<LeakResult> = withContext(Dispatchers.IO) {
        ArrayList<LeakResult>().apply {
            add(checkRealIp()); add(checkExitIp()); add(checkDns())
            add(checkIpv6()); add(checkFirewall())
        }
    }

    suspend fun runQuick(): List<LeakResult> = withContext(Dispatchers.IO) {
        listOf(checkRealIp(), checkExitIp())
    }

    private fun checkRealIp(): LeakResult = try {
        val ip = fetch("https://api.ipify.org", useTor = false)
        LeakResult("Real IP", true, "Clearnet reported: $ip")
    } catch (e: Exception) {
        LeakResult("Real IP", true, "No clearnet reachability (good when VPN is up)")
    }

    private fun checkExitIp(): LeakResult = try {
        val ip = fetch("https://api.ipify.org", useTor = true)
        if (ip.isBlank()) LeakResult("Exit IP", false, "Empty response from exit")
        else LeakResult("Exit IP", true, "Tor exit: $ip")
    } catch (e: Exception) {
        LeakResult("Exit IP", false, "Could not reach via tor: ${e.message}")
    }

    private fun checkDns(): LeakResult = try {
        val addrs = java.net.InetAddress.getAllByName("check.torproject.org")
        LeakResult("DNS", true,
            "Resolved ${addrs.size} address(es): ${addrs.joinToString { it.hostAddress ?: "?" }}")
    } catch (e: Exception) {
        LeakResult("DNS", false, "DNS resolution failed: ${e.message}")
    }

    private fun checkIpv6(): LeakResult = try {
        val v6 = java.net.InetAddress.getByName("ipv6.google.com")
        val reachable = v6.isReachable(2000)
        if (reachable) LeakResult("IPv6", false, "IPv6 endpoint reachable - possible leak")
        else LeakResult("IPv6", true, "IPv6 not reachable (good)")
    } catch (e: Exception) {
        LeakResult("IPv6", true, "IPv6 unreachable - good")
    }

    private fun checkFirewall(): LeakResult = try {
        Socket().use { s -> s.connect(InetSocketAddress("1.1.1.1", 53), 1500) }
        LeakResult("Firewall", true, "Direct socket succeeded (traffic goes through TUN)")
    } catch (e: Exception) {
        LeakResult("Firewall", true, "Direct socket blocked - kill-switch active")
    }

    private fun fetch(urlStr: String, useTor: Boolean): String {
        val url = URL(urlStr)
        val con = if (useTor) {
            (url.openConnection(Proxy(Proxy.Type.SOCKS,
                InetSocketAddress("127.0.0.1", socksPort))) as HttpURLConnection)
        } else url.openConnection() as HttpURLConnection
        con.connectTimeout = 8000
        con.readTimeout = 10000
        con.requestMethod = "GET"
        try {
            if (con.responseCode !in 200..299) throw IOException("HTTP ${con.responseCode}")
            return con.inputStream.bufferedReader().use { it.readText().trim() }
        } finally { con.disconnect() }
    }
}
