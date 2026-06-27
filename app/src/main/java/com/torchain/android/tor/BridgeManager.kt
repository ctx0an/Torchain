package com.torchain.android.tor

import com.torchain.android.data.Bridge
import com.torchain.android.data.BridgeTransport
import com.torchain.android.util.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import javax.net.ssl.HttpsURLConnection

object BridgeManager {
    fun parse(line: String): Bridge? {
        val trimmed = line.trim()
        if (trimmed.isEmpty()) return null
        val parts = trimmed.split(' ', limit = 2)
        val transport = parts[0]
        val rest = parts.getOrNull(1) ?: return null
        if (!rest.split(' ').first().contains(':')) return null
        return Bridge(transport = transport, line = trimmed)
    }

    suspend fun fetch(transport: BridgeTransport): List<String> = withContext(Dispatchers.IO) {
        try {
            val url = URL("https://bridges.torproject.org/moat/circumvention/options")
            val con = url.openConnection() as HttpsURLConnection
            con.requestMethod = "POST"
            con.setRequestProperty("Content-Type", "application/vnd.api+json")
            con.setRequestProperty("Accept", "application/vnd.api+json")
            con.doOutput = true
            con.connectTimeout = 15000
            con.readTimeout = 20000
            val tp = when (transport) {
                BridgeTransport.OBFS4 -> "obfs4"
                BridgeTransport.WEBTUNNEL -> "webtunnel"
                BridgeTransport.SNOWFLAKE -> "snowflake"
                BridgeTransport.MEEK_LITE -> "meek_lite"
                else -> "obfs4"
            }
            val body = """{"data":[{"type":"client-transports","version":"0.1.0","supported":["$tp"]}]}"""
            con.outputStream.use { it.write(body.toByteArray()) }
            if (con.responseCode !in 200..299) throw IOException("Moat HTTP ${con.responseCode}")
            val resp = con.inputStream.bufferedReader().readText()
            val lines = mutableListOf<String>()
            Regex("\"(obfs4|webtunnel|snowflake|meek_lite) [^\"]+\"").findAll(resp).forEach {
                lines.add(it.value.trim('"'))
            }
            if (lines.isEmpty()) lines.addAll(defaultBridges(transport))
            lines
        } catch (e: Exception) {
            Logger.w("bridge-fetch", "fetch failed, using defaults", e)
            defaultBridges(transport)
        }
    }

    fun defaultBridges(transport: BridgeTransport): List<String> = when (transport) {
        BridgeTransport.SNOWFLAKE -> listOf(
            "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253-1574206242 colo=12d",
            "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253-1574206242 colo=12d")
        else -> emptyList()
    }

    suspend fun test(line: String, timeoutMs: Int = 8000): Pair<Boolean, Long> =
        withContext(Dispatchers.IO) {
            val parsed = parse(line) ?: return@withContext false to -1L
            val rest = parsed.line.split(' ').getOrNull(1) ?: return@withContext false to -1L
            val hp = rest.split(' ').first().split(':')
            val host = hp.getOrNull(0) ?: return@withContext false to -1L
            val port = hp.getOrNull(1)?.toIntOrNull() ?: return@withContext false to -1L
            val start = System.currentTimeMillis()
            try {
                Socket().use { s -> s.connect(InetSocketAddress(host, port), timeoutMs) }
                true to (System.currentTimeMillis() - start)
            } catch (e: Exception) {
                Logger.d("bridge-test", "test $host:$port failed: ${e.message}")
                false to -1L
            }
        }
}
