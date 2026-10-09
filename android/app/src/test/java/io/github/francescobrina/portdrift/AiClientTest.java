package io.github.francescobrina.portdrift;
import org.junit.Test;
import static org.junit.Assert.*;
public class AiClientTest {
    @Test public void addsDefaultPortAndV1() throws Exception {
        assertEquals("http://100.64.1.2:1234/v1",AiClient.normalizeBaseUrl("http://100.64.1.2"));
        assertEquals("http://100.64.1.2:1234/v1",AiClient.normalizeBaseUrl("100.64.1.2"));
        assertEquals("http://192.168.1.4:1234/v1",AiClient.normalizeBaseUrl("http://192.168.1.4:1234/v1"));
    }
    @Test public void publicHttpRejected() {
        try{AiClient.normalizeBaseUrl("http://example.com");fail("public HTTP must fail");}
        catch(Exception expected){assertTrue(expected.getMessage().contains("HTTP"));}
    }
    @Test public void rejectsUserinfoAndInvalidPath() {
        for(String url:new String[]{"http://user:pass@192.168.1.3",
                "http://192.168.1.3/private","http://192.168.1.3/?secret=true"}){
            try{AiClient.normalizeBaseUrl(url);fail(url);}
            catch(Exception expected){assertNotNull(expected.getMessage());}
        }
    }
}
