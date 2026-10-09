package io.github.francescobrina.portdrift;

import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Optional local-model assistance; never sends hostnames, IP addresses or credentials in prompts. */
public final class AiClient {
    private AiClient(){}
    private static final int MAX_BYTES=131072;

    /** Normalize a server URL. Port 1234 and /v1 are automatically supplied for LM Studio. */
    public static String normalizeBaseUrl(String value) throws Exception {
        if(value==null||value.trim().isEmpty())
            throw new IllegalArgumentException("Inserisci l'IP del PC con LM Studio.");
        String raw=value.trim();
        if(!raw.contains("://"))raw="http://"+raw;
        URI uri=new URI(raw);
        String scheme=uri.getScheme(),host=uri.getHost();
        if(host==null||uri.getRawUserInfo()!=null||uri.getRawQuery()!=null||uri.getRawFragment()!=null)
            throw new IllegalArgumentException("URL LM Studio non valido.");
        if(!"http".equalsIgnoreCase(scheme)&&!"https".equalsIgnoreCase(scheme))
            throw new IllegalArgumentException("Usa http o https.");
        if("http".equalsIgnoreCase(scheme)&&!ScanEngine.isPermittedPrivateAddress(host)
                &&!"localhost".equalsIgnoreCase(host))
            throw new IllegalArgumentException("HTTP consentito solo su localhost, IP privati e Tailscale.");
        String path=uri.getPath()==null?"":uri.getPath();
        if(!path.isEmpty()&&!"/".equals(path)&&!"/v1".equals(path)&&!"/v1/".equals(path))
            throw new IllegalArgumentException("Usa l'URL base LM Studio, con /v1 facoltativo.");
        int port=uri.getPort();
        if(port==0||port>65535)throw new IllegalArgumentException("Porta server non valida.");
        if(port<0&&"http".equalsIgnoreCase(scheme))port=1234;
        return new URI(scheme.toLowerCase(Locale.ROOT),null,host,port,"/v1",null,null).toASCIIString();
    }

    private static HttpURLConnection open(String endpoint,String method,String token)throws Exception {
        HttpURLConnection c=(HttpURLConnection)new URL(endpoint).openConnection();
        c.setConnectTimeout(6000);c.setReadTimeout(25000);
        c.setRequestMethod(method);
        c.setRequestProperty("Accept","application/json");
        if(token!=null&&!token.isEmpty()){
            if(token.contains("\r")||token.contains("\n"))
                throw new IllegalArgumentException("Token non valido.");
            c.setRequestProperty("Authorization","Bearer "+token);
        }
        return c;
    }
    private static JSONObject response(HttpURLConnection c)throws Exception {
        int status=c.getResponseCode();
        if(status<200||status>=300)
            throw new IOException("LM Studio HTTP "+status+
                (status==401?" — controlla il token API.":""));
        try(InputStream input=c.getInputStream(); ByteArrayOutputStream out=new ByteArrayOutputStream()){
            byte[] chunk=new byte[4096];int count;
            while((count=input.read(chunk))!=-1){
                out.write(chunk,0,count);
                if(out.size()>MAX_BYTES)throw new IOException("Risposta server troppo grande.");
            }
            return new JSONObject(out.toString(StandardCharsets.UTF_8));
        }
    }

    /** Explicit, user-initiated model discovery. No host scan contents are transmitted. */
    public static List<String> listModels(String baseUrl,String token)throws Exception {
        String base=normalizeBaseUrl(baseUrl);
        HttpURLConnection c=open(base+"/models","GET",token);
        try{
            JSONArray data=response(c).getJSONArray("data");
            List<String> models=new ArrayList<>();
            for(int i=0;i<data.length();i++){
                String id=data.getJSONObject(i).optString("id","");
                if(!id.isBlank()&&id.length()<=180)models.add(id);
            }
            if(models.isEmpty())throw new IOException("Nessun modello restituito da LM Studio.");
            return models;
        }finally{c.disconnect();}
    }

    /** The caller must obtain explicit sharing consent before invoking this method. */
    public static String explain(List<ScanEngine.Port> ports,String baseUrl,String model,String token)throws Exception {
        if(ports==null||ports.isEmpty())
            throw new IllegalArgumentException("Esegui prima una scansione TCP.");
        String base=normalizeBaseUrl(baseUrl);
        if(model==null||model.isBlank()){
            List<String> detected=listModels(base,token);
            model=detected.get(0);
        }
        if(model.length()>180)throw new IllegalArgumentException("ID modello troppo lungo.");
        JSONArray observations=new JSONArray();
        for(ScanEngine.Port port:ports){
            observations.put(new JSONObject()
                .put("port",port.number).put("state",port.state).put("service",port.service));
        }
        JSONArray messages=new JSONArray()
            .put(new JSONObject().put("role","system").put("content",
                "Sei un assistente difensivo per amministratori di reti autorizzate. Rispondi in italiano "+
                "con non più di cinque indicazioni pratiche. Le porte TCP aperte non dimostrano "+
                "vulnerabilità. Non inventare CVE, exploit o evidenze non presenti. "+
                "Se tutte le porte sono chiuse, spiega i limiti della scansione."))
            .put(new JSONObject().put("role","user").put("content",
                "Analizza queste sole osservazioni TCP anonimizzate: "+observations));
        byte[] payload=new JSONObject().put("model",model).put("max_tokens",500)
            .put("messages",messages).toString().getBytes(StandardCharsets.UTF_8);
        if(payload.length>MAX_BYTES)throw new IOException("Report troppo grande.");
        HttpURLConnection c=open(base+"/chat/completions","POST",token);
        try {
            c.setDoOutput(true);c.setRequestProperty("Content-Type","application/json");
            try(OutputStream out=c.getOutputStream()){out.write(payload);}
            String answer=response(c).getJSONArray("choices").getJSONObject(0)
                .getJSONObject("message").getString("content");
            if(answer.isBlank())throw new IOException("LM Studio non ha restituito testo.");
            return answer.length()>10000?answer.substring(0,10000):answer;
        }finally{c.disconnect();}
    }
}
