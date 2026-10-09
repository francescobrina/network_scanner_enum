package io.github.francescobrina.portdrift;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.SocketFactory;

/**
 * Read-only TCP connect diagnostics; no root, shell, exploit, stealth or privileged packets.
 * All network operations require explicit user authorization in the calling UI.
 */
public final class ScanEngine {
    private ScanEngine() {}
    public static final int[] PORTS = {21,22,25,53,80,110,139,143,443,445,587,993,1883,3000,3306,3389,5432,5900,6379,8000,8080,8443,9090,1234};
    public static final int[] DISCOVERY = {80,443,22,445,8080,1234};
    public interface Progress { void update(int done, int total); }
    public static final class Port {
        public final int number;
        public final String state;
        public final String service;
        public final long latencyMs;
        public Port(int number,String state,long latencyMs) {
            this.number=number;this.state=state;this.latencyMs=latencyMs;
            this.service=service(number);
        }
    }
    public static final class Host {
        public final String address;
        public final List<Integer> openPorts;
        public Host(String address,List<Integer> openPorts) {
            this.address=address;this.openPorts=Collections.unmodifiableList(new ArrayList<>(openPorts));
        }
    }
    public static String service(int port) {
        switch(port) {
            case 21:return "FTP";case 22:return "SSH";case 25:return "SMTP";
            case 53:return "DNS";case 80:return "HTTP";case 110:return "POP3";
            case 139:return "NetBIOS";case 143:return "IMAP";case 443:return "HTTPS";
            case 445:return "SMB";case 587:return "SMTP";case 993:return "IMAPS";
            case 1883:return "MQTT";case 3000:return "Web";case 3306:return "MySQL";
            case 3389:return "RDP";case 5432:return "PostgreSQL";
            case 5900:return "VNC";case 6379:return "Redis";case 8000:return "HTTP";
            case 8080:return "HTTP";case 8443:return "HTTPS";case 9090:return "Web";
            case 1234:return "Local AI";
            default:return "TCP";
        }
    }
    public static int[] parseIpv4(String raw) {
        if(raw==null || !raw.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) throw new IllegalArgumentException("Inserisci un indirizzo IPv4.");
        String[] pieces=raw.split("\\.");
        int[] result=new int[4];
        for(int i=0;i<4;i++){
            result[i]=Integer.parseInt(pieces[i]);
            if(result[i]>255) throw new IllegalArgumentException("IPv4 non valido.");
        }
        return result;
    }
    public static boolean isPermittedPrivateAddress(String raw) {
        try {
            int[] a=parseIpv4(raw);
            return a[0]==10 || a[0]==127
                || (a[0]==172 && a[1]>=16 && a[1]<=31)
                || (a[0]==192 && a[1]==168)
                || (a[0]==100 && a[1]>=64 && a[1]<=127)
                || (a[0]==169 && a[1]==254);
        } catch(IllegalArgumentException e) {return false;}
    }
    /** LAN auto discovery must never use a VPN/CGNAT 100.64/10 address as its subnet. */
    public static boolean isLanWifiAddress(String ip) {
        try {
            int[] a=parseIpv4(ip);
            return a[0]==10 || (a[0]==172 && a[1]>=16 && a[1]<=31)
                || (a[0]==192 && a[1]==168);
        }catch(IllegalArgumentException e){return false;}
    }
    public static List<String> candidates24(String ip) {
        return candidatesSubnet(ip,24);
    }
    /** At most a single /24, respecting narrower Wi-Fi prefixes (/25..30). */
    public static List<String> candidatesSubnet(String ip,int prefix) {
        if(!isLanWifiAddress(ip) || prefix<1 || prefix>30)
            throw new IllegalArgumentException("Serve un IPv4 Wi-Fi privato e un prefisso valido.");
        int[] a=parseIpv4(ip);
        int bits=Math.max(24,prefix);
        int octetMask=(0xff << (32-bits)) & 0xff;
        int base=a[3]&octetMask;
        int count=1<<(32-bits);
        List<String> out=new ArrayList<>(Math.min(253,count));
        for(int i=base+1;i<base+count-1;i++) {
            if(i!=a[3])out.add(a[0]+"."+a[1]+"."+a[2]+"."+i);
        }
        return out;
    }
    private static boolean connect(SocketFactory factory,String ip,int port,int timeout) {
        try(Socket s=factory.createSocket()) {
            s.connect(new InetSocketAddress(ip,port),timeout);
            return true;
        }catch(IOException | SecurityException ex){return false;}
    }
    public static List<Host> discover(String ownIp,AtomicBoolean cancelled,Progress progress) throws InterruptedException {
        return discover(ownIp,24,cancelled,progress,SocketFactory.getDefault());
    }
    public static List<Host> discover(String ownIp,int prefix,AtomicBoolean cancelled,
                                      Progress progress,SocketFactory factory) throws InterruptedException {
        List<String> hosts=candidatesSubnet(ownIp,prefix);
        ExecutorService pool=Executors.newFixedThreadPool(24);
        CompletionService<Host> cs=new ExecutorCompletionService<>(pool);
        try {
            int submitted=0;
            for(String ip:hosts) {
                if(cancelled.get())break;
                cs.submit(()->{
                    if(cancelled.get()) return null;
                    List<Integer> open=new ArrayList<>();
                    for(int port:DISCOVERY) {
                        if(cancelled.get())break;
                        if(connect(factory,ip,port,350))open.add(port);
                    }
                    // Only report TCP-responsive hosts; Java isReachable() cannot be
                    // bound to the physical Wi-Fi Network and may route through a VPN.
                    return open.isEmpty()?null:new Host(ip,open);
                });
                submitted++;
            }
            List<Host> result=new ArrayList<>();
            for(int i=0;i<submitted;i++){
                if(cancelled.get()) break;
                try {
                    Host h=cs.take().get();
                    if(h!=null)result.add(h);
                }catch(java.util.concurrent.ExecutionException e){/* one unreachable address must not abort discovery */}
                if(progress!=null)progress.update(i+1,submitted);
            }
            result.sort(Comparator.comparingInt(h->parseIpv4(h.address)[3]));
            return result;
        }finally{
            pool.shutdownNow();
            pool.awaitTermination(2,TimeUnit.SECONDS);
        }
    }
    public static List<Port> scanHost(String address,AtomicBoolean cancelled,Progress progress) throws InterruptedException {
        return scanHost(address,cancelled,progress,SocketFactory.getDefault());
    }
    public static List<Port> scanHost(String address,AtomicBoolean cancelled,Progress progress,
                                      SocketFactory factory) throws InterruptedException {
        if(!isPermittedPrivateAddress(address)) throw new IllegalArgumentException("Per questa versione sono consentiti IP privati e Tailscale.");
        ExecutorService pool=Executors.newFixedThreadPool(12);
        CompletionService<Port> cs=new ExecutorCompletionService<>(pool);
        try {
            for(int port:PORTS) {
                cs.submit(()->{
                    if(cancelled.get())return new Port(port,"error",-1);
                    long before=System.nanoTime();
                    try(Socket s=factory.createSocket()) {
                        s.connect(new InetSocketAddress(address,port),800);
                        return new Port(port,"open",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-before));
                    }catch(java.net.SocketTimeoutException ex){return new Port(port,"timeout",-1);}
                    catch(java.net.ConnectException ex){return new Port(port,"closed",-1);}
                    catch(IOException | SecurityException ex){return new Port(port,"error",-1);}
                });
            }
            List<Port> result=new ArrayList<>();
            for(int i=0;i<PORTS.length;i++){
                if(cancelled.get())break;
                try {result.add(cs.take().get());}
                catch(java.util.concurrent.ExecutionException ignored) {}
                if(progress!=null)progress.update(i+1,PORTS.length);
            }
            result.sort(Comparator.comparingInt(p->p.number));
            return result;
        }finally{
            pool.shutdownNow();
            pool.awaitTermination(2,TimeUnit.SECONDS);
        }
    }
}
