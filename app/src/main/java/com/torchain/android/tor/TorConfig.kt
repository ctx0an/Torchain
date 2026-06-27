package com.torchain.android.tor

import com.torchain.android.data.TorchainConfig
import java.io.File

object TorConfig {
    fun write(
        dataDir: File,
        config: TorchainConfig,
        socksPort: Int = 9050,
        controlPort: Int = 9051,
        dnsPort: Int = 5400,
        transports: File? = null,
        geoipFile: File? = null,
        geoip6File: File? = null
    ): File {
        dataDir.mkdirs()
        val torrc = File(dataDir, "torrc")
        val lines = build(config, dataDir, socksPort, controlPort, dnsPort,
                          transports, geoipFile, geoip6File)
        torrc.writeText(lines.joinToString("\n") + "\n")
        return torrc
    }

    private fun build(c: TorchainConfig, dataDir: File, socksPort: Int,
        controlPort: Int, dnsPort: Int, transports: File?,
        geoipFile: File?, geoip6File: File?): List<String> = buildList {
        add("# Torchain torrc - generated")
        add("DataDirectory ${dataDir.absolutePath}")
        add("AvoidDiskWrites 1")
        add("SocksPort 127.0.0.1:$socksPort")
        add("ControlPort 127.0.0.1:$controlPort")
        add("ControlPortWriteToFile ${File(dataDir, "control_port").absolutePath}")
        add("CookieAuthentication 1")
        add("CookieAuthFile ${File(dataDir, "control_auth_cookie").absolutePath}")
        add("DNSPort 127.0.0.1:$dnsPort")
        add("AutomapHostsOnResolve 1")
        add("AutomapHostsSuffixes .onion,.exit")
        add("LearnCircuitBuildTimeout 1")
        add("CircuitBuildTimeout 30")
        add("NumEntryGuards 4")
        add("KeepalivePeriod 60")
        add("NewCircuitPeriod 30")
        add("Log notice file ${File(dataDir, "notice.log").absolutePath}")
        add("Log notice stdout")
        if (c.blockIpv6) {
            add("ClientPreferIPv6ORPort 0")
            add("ClientUseIPv4 1")
        }
        if (c.exitCountry.isNotBlank()) {
            val cc = c.exitCountry.lowercase().trim()
            add("ExitNodes {$cc}")
            add("StrictNodes 1")
        }
        geoipFile?.let { if (it.exists()) add("GeoIPFile ${it.absolutePath}") }
        geoip6File?.let { if (it.exists()) add("GeoIPv6File ${it.absolutePath}") }
        if (c.bridgesEnabled && c.bridgeTransport != "vanilla") {
            add("UseBridges 1")
            val t = c.bridgeTransport
            if (t == "snowflake") {
                transports?.let { add("ClientTransportPlugin snowflake exec ${it.absolutePath}") }
                add("Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253-1574206242 colo=12d")
            } else {
                val tpName = if (t == "custom") "obfs4" else t
                transports?.let { add("ClientTransportPlugin $tpName exec ${it.absolutePath}") }
                c.bridgeLines.forEach { line -> if (line.isNotBlank()) add("Bridge $line") }
            }
        }
    }
}
