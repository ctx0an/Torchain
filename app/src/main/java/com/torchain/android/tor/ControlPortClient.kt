package com.torchain.android.tor

import com.torchain.android.util.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class ControlPortClient(
    private val host: String = "127.0.0.1",
    private val port: Int = 9051,
    private val cookieFile: java.io.File? = null
) {
    private var sock: Socket? = null
    private var writer: OutputStreamWriter? = null
    private var reader: BufferedReader? = null
    private var listenerThread: Thread? = null
    private var eventListener: ((Event) -> Unit)? = null
    @Volatile private var running = false
    private val replyQueue = LinkedBlockingQueue<String>()

    sealed class Event {
        data class Bootstrap(val progress: Int, val tag: String) : Event()
        data class Status(val severity: String, val action: String, val args: String) : Event()
        data class Bandwidth(val read: Long, val written: Long) : Event()
        data class Circuit(
            val id: String,
            val status: String,
            val path: String,
            val buildFlags: String = "",
            val purpose: String = "",
            val confluxId: String = ""
        ) : Event()
        data class Log(val severity: String, val msg: String) : Event()
    }

    fun setEventListener(l: (Event) -> Unit) { eventListener = l }

    suspend fun connect() = withContext(Dispatchers.IO) {
        val s = Socket()
        s.connect(InetSocketAddress(host, port), 5000)
        s.keepAlive = true
        sock = s
        writer = OutputStreamWriter(s.getOutputStream(), Charsets.UTF_8)
        reader = BufferedReader(InputStreamReader(s.getInputStream(), Charsets.UTF_8))
        running = true
        authenticate()
        startReader()
    }

    private fun authenticate() {
        val cookie = cookieFile?.takeIf { it.exists() }?.readBytes()
        if (cookie != null && cookie.isNotEmpty()) {
            val clientNonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val clientNonceHex = clientNonce.toHex()
            send("AUTHCHALLENGE SAFECOOKIE $clientNonceHex")
            val resp = readReplyDirect().joinToString(" ")
            if (!resp.contains("AUTHCHALLENGE")) {
                throw IOException("AUTHCHALLENGE rejected: $resp")
            }
            val serverHashHex = extractHex(resp, "SERVERHASH=")
                ?: throw IOException("No SERVERHASH in challenge reply: $resp")
            val serverNonceHex = extractHex(resp, "SERVERNONCE=")
                ?: throw IOException("No SERVERNONCE in challenge reply: $resp")
            val serverNonce = serverNonceHex.fromHex()

            val message = cookie + clientNonce + serverNonce

            val expectedServerHash =
                hmacSha256(SERVER_TO_CONTROLLER_KEY.toByteArray(Charsets.US_ASCII), message)
            if (!expectedServerHash.contentEquals(serverHashHex.fromHex())) {
                throw IOException("SAFECOOKIE server hash mismatch (MITM?)")
            }

            val clientHash =
                hmacSha256(CONTROLLER_TO_SERVER_KEY.toByteArray(Charsets.US_ASCII), message)
            send("AUTHENTICATE ${clientHash.toHex()}")
        } else {
            send("AUTHENTICATE")
        }
        readReplyDirect().forEach { line ->
            if (!line.startsWith("250")) throw IOException("Tor auth failed: $line")
        }
        Logger.i("tor-ctl", "control port authenticated")
    }

    private fun startReader() {
        listenerThread = Thread({ readerLoop() }, "tor-ctl-reader").apply {
            isDaemon = true; start()
        }
    }

    private fun readerLoop() {
        val r = reader ?: return
        try {
            while (running) {
                val line = r.readLine() ?: break
                if (line.isBlank()) continue
                Logger.d("tor-ctl", "<< $line")
                if (line.startsWith("650")) {
                    parseAsyncLine(line)?.let { ev -> eventListener?.invoke(ev) }
                } else {
                    replyQueue.put(line)
                }
            }
        } catch (e: Exception) {
            if (running) Logger.w("tor-ctl", "reader loop ended", e)
        }
    }

    private fun parseAsyncLine(line: String): Event? {
        if (!line.startsWith("650 ")) return null
        val body = line.removePrefix("650 ").trim()
        return when {
            body.startsWith("STATUS_CLIENT ") || body.startsWith("STATUS_GENERAL ") ||
            body.startsWith("STATUS_BOOTSTRAP ") -> {
                // Tor control spec: 650 STATUS_CLIENT <Severity> <Action> <Args...>
                // e.g. 650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=5 TAG=conn SUMMARY="..."
                // parts = [<Severity>, <Action>, <arg>, ...]
                // The previous code read `action = parts.firstOrNull()` which is the
                // SEVERITY ("NOTICE"), so the `action == "BOOTSTRAP"` check was always
                // false and every bootstrap event was misclassified as a Status event.
                // That left the dashboard stuck at "Bootstrap 0%" and (with the
                // VPN-waits-for-Running fix) the VPN never came up.
                val parts = body.split(' ').drop(1)
                val severity = parts.firstOrNull() ?: ""
                val action = parts.getOrNull(1) ?: ""
                val kv = parseKv(parts.drop(2).joinToString(" "))
                if (action == "BOOTSTRAP") {
                    Event.Bootstrap((kv["PROGRESS"] ?: "0").toIntOrNull() ?: 0, kv["TAG"] ?: "")
                } else {
                    Event.Status(severity, action, kv.toString())
                }
            }
            body.startsWith("BW ") -> {
                val p = body.removePrefix("BW ").split(' ')
                Event.Bandwidth(p.getOrNull(0)?.toLongOrNull() ?: 0, p.getOrNull(1)?.toLongOrNull() ?: 0)
            }
            body.startsWith("CIRC ") -> {
                val tokens = body.removePrefix("CIRC ").split(' ')
                val cid = tokens.getOrNull(0) ?: ""
                val cstatus = tokens.getOrNull(1) ?: ""
                val meta = mutableMapOf<String, String>()
                val pathParts = mutableListOf<String>()
                for (i in 2 until tokens.size) {
                    val t = tokens[i]
                    if (t.contains('=') && t[0].isUpperCase()) {
                        val eq = t.indexOf('=')
                        meta[t.substring(0, eq)] = t.substring(eq + 1)
                    } else {
                        pathParts.add(t)
                    }
                }
                Event.Circuit(
                    id = cid,
                    status = cstatus,
                    path = pathParts.joinToString(" "),
                    buildFlags = meta["BUILD_FLAGS"] ?: "",
                    purpose = meta["PURPOSE"] ?: "",
                    confluxId = meta["CONFLUX_ID"] ?: ""
                )
            }
            body.startsWith("NOTICE ") || body.startsWith("WARN ") || body.startsWith("ERR ") -> {
                val sp = body.indexOf(' ')
                Event.Log(body.substring(0, sp), body.substring(sp + 1))
            }
            else -> null
        }
    }

    private fun parseKv(s: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        Regex("(\\w+)=(\\S+)").findAll(s).forEach { out[it.groupValues[1]] = it.groupValues[2] }
        return out
    }

    suspend fun setEvents(vararg events: String) {
        send("SETEVENTS ${events.joinToString(" ")}"); readReply()
    }

    suspend fun getInfo(vararg keys: String): Map<String, String> = withContext(Dispatchers.IO) {
        send("GETINFO ${keys.joinToString(" ")}")
        val replies = readReply()
        val out = LinkedHashMap<String, String>()
        replies.forEach { line ->
            if (line.startsWith("250-") || line.startsWith("250+")) {
                val body = line.removePrefix("250-").removePrefix("250+")
                val eq = body.indexOf('=')
                if (eq > 0) out[body.substring(0, eq)] = body.substring(eq + 1)
            }
        }
        out
    }

    suspend fun setConf(vararg pairs: Pair<String, String>) {
        val s = pairs.joinToString(" ") { (k, v) ->
            "$k=${if (v.contains(' ') || v.isEmpty()) "\"$v\"" else v}"
        }
        send("SETCONF $s"); readReply()
    }

    suspend fun signal(sig: String) { send("SIGNAL $sig"); readReply() }

    suspend fun close() = withContext(Dispatchers.IO) {
        running = false
        try { send("QUIT") } catch (_: Exception) {}
        try { sock?.close() } catch (_: Exception) {}
        try { listenerThread?.join(500) } catch (_: Exception) {}
    }

    private fun send(line: String) {
        val w = writer ?: throw IOException("not connected")
        Logger.d("tor-ctl", ">> $line")
        w.write(line + "\r\n"); w.flush()
    }

    private fun readReply(): List<String> {
        val out = ArrayList<String>()
        while (true) {
            val line = replyQueue.poll(20, TimeUnit.SECONDS)
                ?: throw IOException("control port reply timeout")
            out.add(line)
            if (line.length >= 4 && line[3] == ' ') break
        }
        return out
    }

    private fun readReplyDirect(): List<String> {
        val r = reader ?: throw IOException("not connected")
        val out = ArrayList<String>()
        while (true) {
            val line = r.readLine() ?: throw IOException("control port closed")
            Logger.d("tor-ctl", "<< $line")
            out.add(line)
            if (line.length >= 4 && line[3] == ' ') break
        }
        return out
    }

    private fun extractHex(s: String, key: String): String? {
        val i = s.indexOf(key)
        if (i < 0) return null
        val rest = s.substring(i + key.length)
        val end = rest.indexOf(' ').let { if (it < 0) rest.length else it }
        return rest.substring(0, end).trim()
    }

    private fun hmacSha256(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(msg)
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
    private fun String.fromHex(): ByteArray {
        val clean = trim()
        require(clean.length % 2 == 0) { "odd-length hex string" }
        return ByteArray(clean.length / 2) { i ->
            ((Character.digit(clean[i * 2], 16) shl 4) +
              Character.digit(clean[i * 2 + 1], 16)).toByte()
        }
    }

    companion object {
        private const val SERVER_TO_CONTROLLER_KEY =
            "Tor safe cookie authentication server-to-controller hash"
        private const val CONTROLLER_TO_SERVER_KEY =
            "Tor safe cookie authentication controller-to-server hash"
    }
}
