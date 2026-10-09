package io.github.francescobrina.portdrift;
import org.json.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** User-initiated LM Studio guidance; strips target/IP/credentials from payload. */
public final class AiClient {
    private AiClient(){}
    public static String explain(List<ScanEngine.Port> ports,String url,String model,String bearer)throws Exception{
        if(model==null||model.isBlank()||model.length()>150)throw new IllegalArgumentException("ID modello mancante.");
        URI uri=new URI(url);
        if(uri.getHost()==null||uri.getRawUserInfo()!=null||uri.getQuery()!=null||uri.getFragment()!=null)
            throw new IllegalArgumentException("Indirizzo server non valido.");
        String scheme=uri.getScheme(),host=uri.getHost();
        if(!"https".equalsIgnoreCase(scheme) && !"http".equalsIgnoreCase(scheme))
            throw new IllegalArgumentException("Usa HTTP o HTTPS.");
        if("http".equalsIgnoreCase(scheme)&&!ScanEngine.isPermittedPrivateAddress(host)&&!"localhost".equalsIgnoreCase(host))
            throw new IllegalArgumentException("HTTP consentito solo per indirizzi privati o Tailscale.");
        String path=uri.getPath();
        if(path==null)path="";
        if(!path.isEmpty()&&!path.equals("/")&&!path.equals("/v1")&&!path.equals("/v1/"))
            throw new IllegalArgumentException("Usa l'URL base /v1.");
        String endpoint=uri.toASCIIString().replaceAll("/+$","")+(path.isEmpty()||path.equals("/")?"/v1":"")+"/chat/completions";
        JSONArray entries=new JSONArray();
        for(ScanEngine.Port p:ports)entries.put(new JSONObject().put("port",p.number).put("state",p.state).put("service",p.service));
        JSONArray messages=new JSONArray()
            .put(new JSONObject().put("role","system").put("content",
            "Sei un assistente per verifiche difensive autorizzate. Rispondi in italiano, max 5 consigli. "+
            "Le porte TCP aperte non provano vulnerabilita. Non inventare CVE, credenziali o exploit."))
            .put(new JSONObject().put("role","user").put("content","Ecco porte e stati anonimizzati: "+entries));
        byte[] data=new JSONObject().put("model",model).put("max_tokens",450).put("messages",messages)
            .toString().getBytes(StandardCharsets.UTF_8);
        HttpURLConnection c=(HttpURLConnection)new URL(endpoint).openConnection();
        try{
            c.setConnectTimeout(7000);c.setReadTimeout(25000);c.setRequestMethod("POST");
            c.setDoOutput(true);c.setRequestProperty("Content-Type","application/json");
            if(bearer!=null&&!bearer.isEmpty()){
                if(bearer.contains("\r")||bearer.contains("\n"))throw new IllegalArgumentException("Token non valido.");
                c.setRequestProperty("Authorization","Bearer "+bearer);
            }
            try(OutputStream output=c.getOutputStream()){output.write(data);}
            if(c.getResponseCode()!=200)throw new IOException("Server AI: HTTP "+c.getResponseCode());
            try(InputStream input=c.getInputStream();ByteArrayOutputStream out=new ByteArrayOutputStream()){
                byte[] b=new byte[4096];int n;
                while((n=input.read(b))!=-1){out.write(b,0,n);if(out.size()>131072)throw new IOException("Risposta troppo lunga.");}
                String answer=new JSONObject(out.toString(StandardCharsets.UTF_8))
                    .getJSONArray("choices").getJSONObject(0).getJSONObject("message").getString("content");
                return answer.length()>10000?answer.substring(0,10000):answer;
            }
        }finally{c.disconnect();}
    }
}
