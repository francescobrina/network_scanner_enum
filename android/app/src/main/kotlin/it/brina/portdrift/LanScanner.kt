package it.brina.portdrift

import android.net.Network
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.io.IOException
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Only IPv4 host addresses on the selected, actually connected Wi-Fi link. */
object LanScope {
    fun ipv4ToLong(value: String): Long {
        val parts = value.split(".")
        require(parts.size == 4) { "Serve un indirizzo IPv4 della LAN." }
        return parts.fold(0L) { acc, v ->
            require(v.isNotEmpty() && v.length <= 3 && v.all(Char::isDigit)) { "IPv4 non valido." }
            val part = v.toIntOrNull() ?: throw IllegalArgumentException("IPv4 non valido.")
            require(part in 0..255) { "IPv4 non valido." }
            (acc shl 8) or part.toLong()
        }
    }
    fun longToIpv4(n: Long): String =
        (24 downTo 0 step 8).joinToString(".") { ((n shr it) and 255L).toString() }

    fun inSubnet(host: String, local: String, prefix: Int): Boolean {
        require(prefix in 1..32)
        val mask = (0xffff_ffffL shl (32 - prefix)) and 0xffff_ffffL
        return (ipv4ToLong(host) and mask) == (ipv4ToLong(local) and mask)
    }

    /** Restrict large networks to the device's own /24, max 253 peer addresses. */
    fun peers(local: String, prefix: Int): List<String> {
        require(prefix in 1..32) { "Maschera di rete non valida." }
        if (prefix >= 31) return emptyList()
        val effective = maxOf(prefix, 24)
        val mask = (0xffff_ffffL shl (32 - effective)) and 0xffff_ffffL
        val me = ipv4ToLong(local)
        val network = me and mask
        val last = network or (0xffff_ffffL xor mask)
        return (network + 1 until last).asSequence()
            .filter { it != me }
            .take(254)
            .map(::longToIpv4)
            .toList()
    }
}

data class TcpFinding(
    val port: Int,
    val state: String,
    val service: String,
    val latencyMs: Long? = null
)
data class DiscoveredHost(val ip: String, val openPorts: List<Int>)

object TcpCatalog {
    val discovery = listOf(22, 80, 443, 445, 8080, 1234, 11434)
    val detailed = listOf(
        21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993,
        1234, 1883, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11434
    )
    private val names = mapOf(
        21 to "FTP",22 to "SSH",25 to "SMTP",53 to "DNS TCP",
        80 to "HTTP",110 to "POP3",139 to "NetBIOS",143 to "IMAP",
        443 to "HTTPS",445 to "SMB",587 to "SMTP",993 to "IMAPS",
        1234 to "Local AI (possible)",1883 to "MQTT",3306 to "MySQL",
        3389 to "RDP",5432 to "PostgreSQL",5900 to "VNC",6379 to "Redis",
        8080 to "HTTP-alt",8443 to "HTTPS-alt",9200 to "Elasticsearch",
        11434 to "Local AI (possible)"
    )
    fun name(port: Int) = names[port] ?: "Unknown"
}

class LanScanner(private val wifiNetwork: Network) {
    private fun probe(host: String, port: Int, timeoutMs: Int): TcpFinding {
        val start = System.nanoTime()
        return try {
            wifiNetwork.socketFactory.createSocket().use { socket ->
                socket.connect(InetSocketAddress(host, port), timeoutMs)
            }
            TcpFinding(port, "open", TcpCatalog.name(port),
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start))
        } catch (_: java.net.ConnectException) {
            TcpFinding(port, "closed", TcpCatalog.name(port))
        } catch (_: SocketTimeoutException) {
            TcpFinding(port, "timeout", TcpCatalog.name(port))
        } catch (_: IOException) {
            TcpFinding(port, "error", TcpCatalog.name(port))
        } catch (_: SecurityException) {
            TcpFinding(port, "error", TcpCatalog.name(port))
        }
    }

    /** Concurrent but bounded; no ping, exploit, fingerprinting or credential attempts. */
    fun discover(localIp: String, prefix: Int, cancelled: AtomicBoolean,
                 progress: (Int, Int) -> Unit): List<DiscoveredHost> {
        val hosts = LanScope.peers(localIp, prefix)
        if (hosts.isEmpty()) return emptyList()
        val workers = Executors.newFixedThreadPool(24)
        val service = ExecutorCompletionService<DiscoveredHost?>(workers)
        val submitted = hosts.map { host ->
            service.submit<DiscoveredHost?> {
                if (cancelled.get()) null else {
                    val open = mutableListOf<Int>()
                    for (p in TcpCatalog.discovery) {
                        if (cancelled.get() || Thread.currentThread().isInterrupted) break
                        if (probe(host, p, 200).state == "open") open.add(p)
                    }
                    if (open.isEmpty()) null else DiscoveredHost(host, open)
                }
            }
        }
        val found = ArrayList<DiscoveredHost>()
        var completed = 0
        try {
            while (completed < submitted.size && !cancelled.get()) {
                val item = service.poll(200, TimeUnit.MILLISECONDS) ?: continue
                completed++
                try { item.get()?.let(found::add) } catch (_: Exception) {}
                progress(completed, submitted.size)
            }
        } finally {
            cancelled.set(cancelled.get())
            workers.shutdownNow()
        }
        return found.sortedBy { LanScope.ipv4ToLong(it.ip) }
    }

    fun scanHost(ip: String, cancelled: AtomicBoolean,
                 onProgress: (Int, Int) -> Unit): List<TcpFinding> {
        val result = ArrayList<TcpFinding>()
        for ((i, port) in TcpCatalog.detailed.withIndex()) {
            if (cancelled.get()) break
            result += probe(ip, port, 450)
            onProgress(i + 1, TcpCatalog.detailed.size)
        }
        return result
    }
}
