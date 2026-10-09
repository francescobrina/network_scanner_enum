package io.github.francescobrina.portdrift;
import org.junit.Test;
import java.util.List;
import static org.junit.Assert.*;

public class ScanEngineTest {
    @Test public void publicAddressesRejected() {
        assertFalse(ScanEngine.isPermittedPrivateAddress("8.8.8.8"));
        assertFalse(ScanEngine.isPermittedPrivateAddress("192.0.2.10"));
        assertFalse(ScanEngine.isPermittedPrivateAddress("256.1.1.1"));
        assertFalse(ScanEngine.isPermittedPrivateAddress("invalid"));
        assertTrue(ScanEngine.isPermittedPrivateAddress("192.168.1.7"));
        assertTrue(ScanEngine.isPermittedPrivateAddress("172.16.5.1"));
        assertTrue(ScanEngine.isPermittedPrivateAddress("100.64.1.2"));
    }
    @Test public void subnetBounded() {
        List<String> ips=ScanEngine.candidates24("192.168.50.5");
        assertEquals(253,ips.size());
        assertTrue(ips.contains("192.168.50.1"));
        assertTrue(ips.contains("192.168.50.254"));
        assertFalse(ips.contains("192.168.50.5"));
        assertFalse(ips.contains("192.168.51.1"));
    }
    @Test(expected=IllegalArgumentException.class)
    public void noExternalDiscovery() {ScanEngine.candidates24("8.8.8.8");}
    @Test public void serviceNames() {
        assertEquals("Local AI",ScanEngine.service(1234));
        assertEquals("SMB",ScanEngine.service(445));
        assertEquals("TCP",ScanEngine.service(7777));
    }
    @Test public void vpnNotUsedForAutomaticWifiSweep(){
        assertFalse(ScanEngine.isLanWifiAddress("100.64.1.2"));
        assertTrue(ScanEngine.isPermittedPrivateAddress("100.64.1.2"));
        assertTrue(ScanEngine.isLanWifiAddress("192.168.1.20"));
        try{ScanEngine.candidates24("100.64.1.2");fail("VPN must not be swept");}
        catch(IllegalArgumentException expected){assertTrue(expected.getMessage().contains("Wi-Fi"));}
    }
    @Test public void wifiPrefixRespected(){
        java.util.List<String> result=ScanEngine.candidatesSubnet("192.168.1.130",25);
        assertFalse(result.contains("192.168.1.10"));
        assertTrue(result.contains("192.168.1.129"));
        assertFalse(result.contains("192.168.1.255"));
        assertEquals(125,result.size());
        assertTrue(ScanEngine.inSameSubnet("192.168.1.254","192.168.1.130",25));
        assertFalse(ScanEngine.inSameSubnet("192.168.1.20","192.168.1.130",25));
    }

    @Test public void refusedResponseMeansHostIsPresent(){
        assertEquals("closed",ScanEngine.classifyConnectionError(
            new java.net.ConnectException("connect failed: ECONNREFUSED (Connection refused)")));
        assertTrue(ScanEngine.isTcpResponse(new ScanEngine.Port(443,"closed",-1)));
        assertTrue(ScanEngine.isTcpResponse(new ScanEngine.Port(80,"open",5)));
        assertFalse(ScanEngine.isTcpResponse(new ScanEngine.Port(80,"timeout",-1)));
    }
    @Test public void networkPermissionIsNotClosed(){
        assertEquals("blocked",ScanEngine.classifyConnectionError(
            new java.net.SocketException("socket failed: EPERM (Operation not permitted)")));
        assertEquals("blocked",ScanEngine.classifyConnectionError(
            new java.net.SocketException("EACCES (Permission denied)")));
        assertEquals("unreachable",ScanEngine.classifyConnectionError(
            new java.net.NoRouteToHostException("No route to host")));
        assertEquals("unreachable",ScanEngine.classifyConnectionError(
            new java.net.ConnectException("Network is unreachable")));
        assertEquals("timeout",ScanEngine.classifyConnectionError(
            new java.net.SocketTimeoutException("timeout")));
        assertEquals("error",ScanEngine.classifyConnectionError(
            new java.net.ConnectException("Unexpected address failure")));
    }

}
