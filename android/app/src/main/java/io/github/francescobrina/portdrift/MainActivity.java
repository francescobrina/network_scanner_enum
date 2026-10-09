package io.github.francescobrina.portdrift;

import android.app.*;
import android.os.*;
import android.content.*;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.*;
import android.view.*;
import android.widget.*;
import android.text.InputType;
import java.io.OutputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.*;

/** All network scans are explicitly initiated by the user and are bounded. */
public final class MainActivity extends Activity {
    private static final String LAN_PERMISSION="android.permission.ACCESS_LOCAL_NETWORK";
    private static final int REQUEST_LAN=100, REQUEST_SAVE=101;
    private static final int BG=0xff0b1220,PANEL=0xff162236,TEXT=0xffebf5ff,FADED=0xffa0b1ca,
        TEAL=0xff69dce4,GREEN=0xff81eabc,AMBER=0xfff4c57b;
    private final AtomicBoolean stop=new AtomicBoolean(false);
    private final Handler ui=new Handler(Looper.getMainLooper());
    private String ownIp="",gateway="",lastHost="",startedAt="";
    private long startedMillis;
    private Runnable pending;
    private boolean busy,complete;
    private List<ScanEngine.Port> lastScan=new ArrayList<>();
    private LinearLayout hosts,ports;
    private TextView wifiInfo,status,hostTitle,portTitle,recommendations;
    private EditText target;
    private CheckBox authorized;
    private Button discover,scan,cancel,export,ai;
    private ProgressBar progress;

    @Override public void onCreate(Bundle state){
        super.onCreate(state);
        getWindow().setStatusBarColor(BG);getWindow().setNavigationBarColor(BG);
        drawUI();detectWifi();
    }
    private int d(int dp){return Math.round(getResources().getDisplayMetrics().density*dp);}
    private GradientDrawable bg(int color,int border,int radius){
        GradientDrawable b=new GradientDrawable();
        b.setColor(color);b.setCornerRadius(d(radius));
        if(border!=0)b.setStroke(d(1),border);
        return b;
    }
    private LinearLayout vertical(){LinearLayout l=new LinearLayout(this);l.setOrientation(1);return l;}
    private TextView label(String msg,int size,int color,boolean bold){
        TextView t=new TextView(this);t.setText(msg);t.setTextSize(size);t.setTextColor(color);
        if(bold)t.setTypeface(null,Typeface.BOLD);
        return t;
    }
    private void put(LinearLayout box,View v,int top){
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,-2);p.topMargin=d(top);box.addView(v,p);
    }
    private LinearLayout card(LinearLayout box){
        LinearLayout c=vertical();c.setPadding(d(17),d(16),d(17),d(17));
        c.setBackground(bg(PANEL,0xff30445b,15));put(box,c,15);return c;
    }
    private Button button(String value,boolean primary){
        Button b=new Button(this);b.setAllCaps(false);b.setText(value);b.setTextSize(14);
        b.setTypeface(null,Typeface.BOLD);b.setTextColor(primary?BG:TEXT);
        b.setBackground(bg(primary?TEAL:0xff293d53,0,11));b.setPadding(d(10),d(10),d(10),d(10));
        return b;
    }
    private void drawUI(){
        ScrollView sc=new ScrollView(this);sc.setBackgroundColor(BG);sc.setFillViewport(true);
        LinearLayout root=vertical();root.setPadding(d(17),d(25),d(17),d(40));sc.addView(root);
        setContentView(sc);
        put(root,label("◈  PORTDRIFT  /  ANDROID",14,TEAL,true),1);
        put(root,label("Esplora la tua rete.\nVerifica le esposizioni.",29,TEXT,true),13);
        put(root,label("Scansioni TCP direttamente sul Pixel. Nessun root, abbonamento o cloud richiesto.",13,FADED,false),11);

        LinearLayout wifi=card(root);
        put(wifi,label("RETE ATTIVA",11,TEAL,true),0);
        wifiInfo=label("Rilevamento Wi-Fi…",14,TEXT,true);put(wifi,wifiInfo,9);
        put(wifi,label("La ricerca è limitata alla sottorete privata /24. I dispositivi silenziosi possono non essere rilevati.",11,FADED,false),8);

        LinearLayout control=card(root);
        put(control,label("SCANSIONE AUTORIZZATA",11,TEAL,true),0);
        target=new EditText(this);target.setSingleLine(true);target.setTextSize(16);
        target.setTextColor(TEXT);target.setHintTextColor(FADED);
        target.setHint("IPv4 privato · es. 192.168.1.1");
        target.setBackground(bg(0xff0a1728,0xff3b5771,10));target.setPadding(d(12),d(11),d(12),d(11));
        target.setInputType(InputType.TYPE_CLASS_TEXT);put(control,target,11);
        authorized=new CheckBox(this);authorized.setText("Ho il permesso di verificare questa rete / questo dispositivo.");
        authorized.setTextSize(13);authorized.setTextColor(TEXT);authorized.setButtonTintList(
            android.content.res.ColorStateList.valueOf(TEAL));put(control,authorized,12);
        discover=button("⌁  Trova dispositivi Wi-Fi",true);put(control,discover,11);
        scan=button("▣  Scansiona le porte dell'host",false);put(control,scan,8);
        cancel=button("■  Interrompi",false);cancel.setEnabled(false);put(control,cancel,8);
        progress=new ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal);
        progress.setMax(100);progress.setProgressTintList(android.content.res.ColorStateList.valueOf(TEAL));
        put(control,progress,13);
        status=label("Pronto. Le operazioni partono soltanto quando premi un pulsante.",12,FADED,false);
        put(control,status,8);

        LinearLayout devices=card(root);
        hostTitle=label("DISPOSITIVI RILEVATI",14,TEXT,true);put(devices,hostTitle,0);
        hosts=vertical();put(devices,hosts,12);
        put(hosts,label("Premi «Trova dispositivi Wi-Fi» per iniziare.",12,FADED,false),0);

        LinearLayout results=card(root);
        portTitle=label("PORTE TCP  ·  NESSUNA SCANSIONE",14,TEXT,true);put(results,portTitle,0);
        ports=vertical();put(results,ports,11);
        put(ports,label("Seleziona un dispositivo o inserisci un IP privato.",12,FADED,false),0);
        export=button("↓  Esporta JSON per PortDrift Web",false);export.setEnabled(false);
        put(results,export,14);

        LinearLayout intelligence=card(root);
        put(intelligence,label("INTELLIGENCE  /  AI LOCALE",11,TEAL,true),0);
        recommendations=label("I risultati genereranno suggerimenti difensivi. È inoltre possibile usare il tuo LM Studio sul PC.",13,FADED,false);
        put(intelligence,recommendations,11);
        ai=button("✧  Analizza con LM Studio",false);ai.setEnabled(false);put(intelligence,ai,13);
        put(intelligence,label("Privacy: all'AI sono inviati soltanto numero della porta, servizio e stato. L'IP non viene trasmesso.",11,FADED,false),10);
        put(root,label("PortDrift Mobile 0.5 beta · MIT · Solo su reti autorizzate\nUna porta aperta non dimostra una vulnerabilità.",11,FADED,false),21);

        discover.setOnClickListener(v->permissionThen(this::startDiscovery));
        scan.setOnClickListener(v->permissionThen(this::startScan));
        cancel.setOnClickListener(v->{stop.set(true);say("Interruzione in corso…");});
        export.setOnClickListener(v->save());
        ai.setOnClickListener(v->askAI());
    }
    private void detectWifi(){
        ConnectivityManager cm=(ConnectivityManager)getSystemService(CONNECTIVITY_SERVICE);
        if(cm==null)return;
        for(Network network:cm.getAllNetworks()){
            NetworkCapabilities caps=cm.getNetworkCapabilities(network);
            if(caps==null||!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))continue;
            LinkProperties lp=cm.getLinkProperties(network);if(lp==null)continue;
            for(LinkAddress la:lp.getLinkAddresses()){
                InetAddress ip=la.getAddress();
                if(ip instanceof Inet4Address&&ScanEngine.isPermittedPrivateAddress(ip.getHostAddress())){
                    ownIp=ip.getHostAddress();break;
                }
            }
            for(RouteInfo rt:lp.getRoutes()){
                InetAddress ip=rt.getGateway();
                if(rt.isDefaultRoute()&&ip instanceof Inet4Address
                    &&ScanEngine.isPermittedPrivateAddress(ip.getHostAddress())){
                    gateway=ip.getHostAddress();break;
                }
            }
            if(!ownIp.isEmpty())break;
        }
        if(!ownIp.isEmpty()){
            wifiInfo.setText("Wi-Fi  ·  "+ownIp+(gateway.isEmpty()?"":"\nRouter  ·  "+gateway));
            target.setText(gateway.isEmpty()?ownIp:gateway);
        }else wifiInfo.setText("Nessuna rete Wi-Fi privata identificata. Puoi indicare un IP manualmente.");
    }
    private void say(String message){ui.post(()->status.setText(message));}
    private void setBusy(boolean running){
        busy=running;discover.setEnabled(!running);scan.setEnabled(!running);
        cancel.setEnabled(running);
    }
    private void permissionThen(Runnable task){
        if(busy)return;
        if(!authorized.isChecked()){
            new AlertDialog.Builder(this).setTitle("Autorizzazione obbligatoria")
                .setMessage("Dichiara di essere autorizzato prima di effettuare qualsiasi verifica.")
                .setPositiveButton("OK",null).show();return;
        }
        if(Build.VERSION.SDK_INT>=37 &&
            checkSelfPermission(LAN_PERMISSION)!=PackageManager.PERMISSION_GRANTED){
            pending=task;requestPermissions(new String[]{LAN_PERMISSION},REQUEST_LAN);
        }else task.run();
    }
    @Override public void onRequestPermissionsResult(int code,String[] perms,int[] grants){
        super.onRequestPermissionsResult(code,perms,grants);
        if(code!=REQUEST_LAN)return;
        Runnable task=pending;pending=null;
        if(grants.length>0&&grants[0]==PackageManager.PERMISSION_GRANTED&&task!=null)task.run();
        else say("Permesso di rete locale negato. Controlla le autorizzazioni Android.");
    }
    private void updateProgress(int done,int total){
        ui.post(()->{progress.setProgress(total==0?0:100*done/total);
            status.setText("Verifica  "+done+" / "+total);});
    }
    private void startDiscovery(){
        if(ownIp.isEmpty()){detectWifi();if(ownIp.isEmpty()){
            say("Connettiti a una rete Wi-Fi privata per il discovery.");return;}}
        stop.set(false);setBusy(true);progress.setProgress(0);
        hostTitle.setText("RICERCA DISPOSITIVI…");hosts.removeAllViews();
        say("Discovery limitato alla LAN privata /24…");
        new Thread(()->{
            List<ScanEngine.Host> result=new ArrayList<>();
            try{result=ScanEngine.discover(ownIp,stop,this::updateProgress);}
            catch(Exception e){say("Errore: "+e.getMessage());}
            List<ScanEngine.Host> found=result;
            ui.post(()->{
                setBusy(false);showHosts(found);
                say(stop.get()?"Discovery interrotto: dati parziali.":"Discovery concluso: possibili dispositivi non rilevati.");
            });
        },"portdrift-discovery").start();
    }
    private void showHosts(List<ScanEngine.Host> found){
        hosts.removeAllViews();hostTitle.setText("DISPOSITIVI RILEVATI  ·  "+found.size());
        if(found.isEmpty()){put(hosts,label("Nessuna risposta. Alcuni dispositivi bloccano i probe TCP/ICMP.",12,FADED,false),0);return;}
        for(ScanEngine.Host h:found){
            LinearLayout row=vertical();row.setPadding(d(12),d(11),d(12),d(11));
            row.setBackground(bg(0xff1b3a4c,0,10));
            put(row,label("◉  "+h.address,15,GREEN,true),0);
            put(row,label(h.openPorts.isEmpty()?"Host raggiungibile":"Porte rilevate: "+h.openPorts,
                11,FADED,false),5);
            put(hosts,row,8);
            row.setOnClickListener(v->{target.setText(h.address);permissionThen(this::startScan);});
        }
    }
    private void startScan(){
        String ip=target.getText().toString().trim();
        if(!ScanEngine.isPermittedPrivateAddress(ip)){
            say("Puoi scansionare soltanto IP privati / loopback / Tailscale.");return;
        }
        lastHost=ip;startedAt=Instant.now().toString();startedMillis=System.currentTimeMillis();
        stop.set(false);setBusy(true);progress.setProgress(0);
        ports.removeAllViews();lastScan=new ArrayList<>();complete=false;
        export.setEnabled(false);ai.setEnabled(false);portTitle.setText("SCANSIONE  ·  "+ip);
        say("Verifica TCP su "+ip+"…");
        new Thread(()->{
            List<ScanEngine.Port> found=new ArrayList<>();
            try{found=ScanEngine.scanHost(ip,stop,this::updateProgress);}
            catch(Exception e){say("Errore TCP: "+e.getMessage());}
            List<ScanEngine.Port> result=found;
            boolean full=!stop.get() && result.size()==ScanEngine.PORTS.length;
            ui.post(()->{
                lastScan=result;complete=full;setBusy(false);progress.setProgress(100);
                showPorts(result);export.setEnabled(!result.isEmpty());ai.setEnabled(!result.isEmpty());
                say(full?"Scansione completata. Esporta il JSON o chiedi all'AI.":"Scansione parziale / interrotta.");
            });
        },"portdrift-tcp").start();
    }
    private void showPorts(List<ScanEngine.Port> data){
        ports.removeAllViews();int count=0;StringBuilder tips=new StringBuilder();
        for(ScanEngine.Port p:data){
            if("open".equals(p.state)){
                count++;
                switch(p.number){
                    case 21:tips.append("• FTP aperto: verifica cifratura e necessità del servizio.\n");break;
                    case 445:tips.append("• SMB aperto: controlla condivisioni e permessi.\n");break;
                    case 3389:tips.append("• RDP aperto: verifica gli accessi remoti.\n");break;
                    case 1234:tips.append("• API AI locale rilevata: verifica autenticazione e binding.\n");break;
                    case 6379:tips.append("• Redis aperto: verifica autenticazione e segmentazione.\n");break;
                }
            }
            LinearLayout row=new LinearLayout(this);row.setOrientation(0);row.setGravity(Gravity.CENTER_VERTICAL);
            TextView left=label(p.number+"/tcp   "+p.service,13,TEXT,true);
            row.addView(left,new LinearLayout.LayoutParams(0,-2,1));
            row.addView(label(p.state.toUpperCase(),11,
                "open".equals(p.state)?GREEN:"timeout".equals(p.state)?AMBER:FADED,true));
            put(ports,row,10);
        }
        portTitle.setText("PORTE TCP  ·  "+count+" APERTE / "+data.size()+" VERIFICATE");
        if(tips.length()==0)tips.append("Le porte e gli stati non provano vulnerabilità. Verifica aggiornamenti, necessità dei servizi e ACL.");
        recommendations.setText(tips.toString().trim());
    }
    private JSONObject report()throws Exception{
        JSONObject obj=new JSONObject();obj.put("target",lastHost);obj.put("resolved_ip",lastHost);
        obj.put("started_at",startedAt);obj.put("duration_s",(System.currentTimeMillis()-startedMillis)/1000.0);
        obj.put("completed",complete);obj.put("generator","PortDrift Mobile native beta");
        JSONArray ports=new JSONArray();
        for(ScanEngine.Port p:lastScan){
            JSONObject q=new JSONObject().put("port",p.number).put("state",p.state).put("service",p.service);
            if(p.latencyMs>=0)q.put("latency_ms",p.latencyMs);
            ports.put(q);
        }
        obj.put("results",ports);return obj;
    }
    private void save(){
        if(lastScan.isEmpty())return;
        Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);intent.setType("application/json");
        intent.putExtra(Intent.EXTRA_TITLE,"portdrift-"+lastHost.replace('.','-')+".json");
        startActivityForResult(intent,REQUEST_SAVE);
    }
    @Override protected void onActivityResult(int code,int result,Intent data){
        super.onActivityResult(code,result,data);
        if(code!=REQUEST_SAVE||result!=RESULT_OK||data==null||data.getData()==null)return;
        try(OutputStream out=getContentResolver().openOutputStream(data.getData())){
            if(out==null)throw new Exception("Documento non disponibile");
            out.write(report().toString(2).getBytes(StandardCharsets.UTF_8));
            say("JSON salvato: puoi importarlo nella dashboard PortDrift Web.");
        }catch(Exception e){say("Impossibile esportare: "+e.getMessage());}
    }
    private EditText field(String hint){
        EditText e=new EditText(this);e.setHint(hint);e.setTextSize(14);e.setSingleLine(true);return e;
    }
    private void askAI(){
        if(lastScan.isEmpty())return;
        LinearLayout box=vertical();box.setPadding(d(18),d(12),d(18),d(8));
        put(box,label("Indica l'endpoint del tuo LM Studio. HTTP è consentito solo su IP locali / Tailscale.",12,FADED,false),0);
        EditText url=field("http://IP-del-PC:1234/v1");put(box,url,12);
        EditText model=field("Nome modello attivo");put(box,model,6);
        EditText token=field("Token opzionale");
        token.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);
        put(box,token,6);
        CheckBox consent=new CheckBox(this);consent.setText("Autorizzo l'invio dei dati TCP anonimizzati.");
        consent.setTextColor(TEXT);consent.setTextSize(12);put(box,consent,10);
        new AlertDialog.Builder(this).setTitle("Analisi con AI locale").setView(box)
            .setNegativeButton("Annulla",null)
            .setPositiveButton("Analizza",(dlg,which)->{
                if(!consent.isChecked()){say("Consenso AI non fornito.");return;}
                ai.setEnabled(false);say("Interrogazione del modello…");
                List<ScanEngine.Port> snapshot=new ArrayList<>(lastScan);
                String endpoint=url.getText().toString(),name=model.getText().toString(),
                    key=token.getText().toString();
                new Thread(()->{
                    try{
                        String result=AiClient.explain(snapshot,endpoint,name,key);
                        ui.post(()->{recommendations.setText("AI (verifica indipendentemente):\n\n"+result);
                            ai.setEnabled(true);say("Risposta AI ricevuta.");});
                    }catch(Exception e){ui.post(()->{ai.setEnabled(true);say("AI: "+e.getMessage());});}
                },"portdrift-ai").start();
            }).show();
    }
    @Override protected void onDestroy(){stop.set(true);super.onDestroy();}
}
