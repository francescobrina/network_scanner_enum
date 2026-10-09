package it.brina.portdrift

import org.junit.Assert.*
import org.junit.Test

class LanScopeTest {
    @Test fun peersBoundedToLocalSubnet() {
        val peers = LanScope.peers("192.168.1.77", 16)
        assertEquals(253, peers.size)
        assertFalse(peers.contains("192.168.1.77"))
        assertTrue(peers.contains("192.168.1.1"))
        assertFalse(peers.contains("192.168.2.1"))
    }
    @Test fun rejectsInvalidAddresses() {
        for (v in listOf("192.168.1", "1.2.3.999", "example.com", "1.2.3.-4")) {
            try { LanScope.ipv4ToLong(v); fail(v) } catch (_: IllegalArgumentException) { }
        }
    }
    @Test fun shortSubnetsAreRespected() {
        val peers = LanScope.peers("192.168.10.2", 30)
        assertEquals(listOf("192.168.10.1"), peers)
    }
    @Test fun directHostMustBelongToWifiSubnet() {
        assertTrue(LanScope.inSubnet("192.168.1.10", "192.168.1.77", 24))
        assertFalse(LanScope.inSubnet("8.8.8.8", "192.168.1.77", 24))
    }
    @Test fun catalogContainsAiPorts() {
        assertTrue(TcpCatalog.discovery.contains(1234))
        assertTrue(TcpCatalog.discovery.contains(11434))
    }
}
