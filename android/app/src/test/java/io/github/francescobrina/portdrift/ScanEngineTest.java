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
        assertTrue(ScanEngine.isPermittedPrivateAddress("100.104.53.3"));
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
}
