
package com.secureworkspace;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/**
 * In-memory readers/writer lock manager.
 * Wait-for graph edges are waiter-user -> owner-user. A detected cycle releases
 * the selected victim's locks. The waiting HTTP request is not a suspended OS thread;
 * clients receive WAITING and may retry. This is application-level concurrency control.
 */
public final class LockManager implements AutoCloseable {
    public record Held(int fileId, int userId, String type, Instant since) {}
    public record Waiting(int fileId, int userId, String type, Instant since) {}
    private final Map<Integer, Map<Integer,Held>> held = new HashMap<>();
    private final Map<Integer,Waiting> waiting = new HashMap<>();
    private final ScheduledExecutorService detector = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "wfg-deadlock-detector"); t.setDaemon(true); return t;
    });
    private volatile String lastDetection = "Detector started; no cycle detected.";
    /** Snapshot of the most recent deadlock (cycle nodes + the wait-for edges at that moment), kept for the dashboard graph. */
    public record Deadlock(List<Integer> cycle,int victim,Map<Integer,Set<Integer>> edges,String at){}
    private volatile Deadlock lastDeadlock=null;
    public LockManager() { detector.scheduleAtFixedRate(this::detectSafely, 3, 3, TimeUnit.SECONDS); }

    public synchronized String acquire(int fileId, int userId, String type) {
        final String lockType = type.toUpperCase(Locale.ROOT);
        if (!lockType.equals("READ") && !lockType.equals("WRITE")) throw new IllegalArgumentException("Lock type must be READ or WRITE");
        Map<Integer,Held> owners = held.computeIfAbsent(fileId, k -> new HashMap<>());
        boolean conflict = owners.values().stream().anyMatch(h -> h.userId()!=userId &&
            (lockType.equals("WRITE") || h.type().equals("WRITE")));
        if (!conflict) {
            owners.put(userId, new Held(fileId,userId,lockType,Instant.now()));
            waiting.remove(userId);
            Db.log(userId,"LOCK_ACQUIRED",lockType+" lock on file "+fileId);
            return "ACQUIRED";
        }
        waiting.put(userId,new Waiting(fileId,userId,lockType,Instant.now()));
        Db.log(userId,"LOCK_WAIT","Waiting for "+lockType+" lock on file "+fileId);
        return "WAITING";
    }
    public synchronized void release(int fileId,int userId) {
        Map<Integer,Held> owners=held.get(fileId);
        if(owners!=null){owners.remove(userId);if(owners.isEmpty())held.remove(fileId);}
        waiting.remove(userId);
        Db.log(userId,"LOCK_RELEASED","Released lock on file "+fileId);
    }
    /** True when ANOTHER user holds any lock on the file, so a write by userId would violate the readers/writer rule. */
    public synchronized boolean writeBlocked(int fileId,int userId){
        return held.getOrDefault(fileId,Map.of()).values().stream().anyMatch(h->h.userId()!=userId);
    }
    /** File moved to trash: every lock and wait on it disappears. */
    public synchronized void dropFile(int fileId){
        held.remove(fileId);
        waiting.values().removeIf(w->w.fileId()==fileId);
    }
    public synchronized void forget(int fileId,int userId){ // access revoked: drop that user's lock/wait on this file (no log noise)
        Map<Integer,Held> owners=held.get(fileId);
        if(owners!=null){owners.remove(userId);if(owners.isEmpty())held.remove(fileId);}
        Waiting w=waiting.get(userId);if(w!=null&&w.fileId()==fileId)waiting.remove(userId);
    }
    public synchronized List<Held> heldList(){List<Held> l=new ArrayList<>();held.values().forEach(m->l.addAll(m.values()));l.sort(Comparator.comparingInt(Held::fileId).thenComparingInt(Held::userId));return l;}
    public synchronized List<Waiting> waitingList(){List<Waiting> l=new ArrayList<>(waiting.values());l.sort(Comparator.comparingInt(Waiting::userId));return l;}
    public Deadlock lastDeadlock(){return lastDeadlock;}
    public synchronized void releaseUser(int userId) {
        for(Integer fileId:new ArrayList<>(held.keySet())){
            Map<Integer,Held> owners=held.get(fileId);
            if(owners!=null){owners.remove(userId);if(owners.isEmpty())held.remove(fileId);}
        }
        waiting.remove(userId);
    }
    public synchronized Map<Integer,Set<Integer>> waitForGraph() {
        Map<Integer,Set<Integer>> graph=new HashMap<>();
        for(Waiting w:waiting.values()){
            for(Held h:held.getOrDefault(w.fileId(),Map.of()).values()){
                if(h.userId()!=w.userId()) graph.computeIfAbsent(w.userId(),k->new HashSet<>()).add(h.userId());
            }
        }
        return graph;
    }
    private void detectSafely(){try{detect();}catch(Throwable t){t.printStackTrace();}}
    public synchronized void detect() {
        Map<Integer,Set<Integer>> graph=waitForGraph();
        Set<Integer> done=new HashSet<>(), active=new HashSet<>();
        List<Integer> cycle=new ArrayList<>();
        for(Integer node:graph.keySet()) if(dfs(node,graph,done,active,cycle)) break;
        if(!cycle.isEmpty()){
            // dfs() collects [A,B,A,...tail]; the real cycle is everything up to the second occurrence of the first node
            int again=cycle.subList(1,cycle.size()).indexOf(cycle.get(0));
            if(again>=0)cycle=new ArrayList<>(cycle.subList(0,again+1));
            int victim=cycle.stream().max(Integer::compareTo).orElse(cycle.get(0));
            Map<Integer,Set<Integer>> edges=new HashMap<>();
            graph.forEach((k,v)->edges.put(k,new HashSet<>(v)));
            lastDeadlock=new Deadlock(List.copyOf(cycle),victim,edges,Instant.now().toString());
            releaseUser(victim);
            lastDetection="DEADLOCK_RESOLVED: cycle "+cycle+"; victim user "+victim+" released locks.";
            Db.log(victim,"DEADLOCK_RESOLVED",lastDetection);
        } else lastDetection="DFS check at "+Instant.now()+" — no cycle.";
    }
    private boolean dfs(int node,Map<Integer,Set<Integer>> g,Set<Integer> done,Set<Integer> active,List<Integer> cycle){
        if(active.contains(node)){cycle.add(node);return true;}
        if(done.contains(node))return false;
        active.add(node);
        for(Integer next:g.getOrDefault(node,Set.of())) if(dfs(next,g,done,active,cycle)){cycle.add(node);return true;}
        active.remove(node);done.add(node);return false;
    }
    public synchronized String snapshot(){
        StringBuilder b=new StringBuilder();
        held.forEach((f,m)->m.values().forEach(h->b.append("FILE ").append(f).append(" · USER ").append(h.userId()).append(" · ").append(h.type()).append("\n")));
        waiting.values().forEach(w->b.append("WAIT USER ").append(w.userId()).append(" · FILE ").append(w.fileId()).append(" · ").append(w.type()).append("\n"));
        return b.toString();
    }
    /** Same text as snapshot(), but only the lines that belong to one user (normal users must not see others' lock activity). */
    public synchronized String snapshotFor(int userId){
        StringBuilder b=new StringBuilder();
        heldList().stream().filter(h->h.userId()==userId).forEach(h->b.append("HOLD FILE ").append(h.fileId()).append(" · ").append(h.type()).append("\n"));
        waitingList().stream().filter(w->w.userId()==userId).forEach(w->b.append("WAIT FILE ").append(w.fileId()).append(" · ").append(w.type()).append("\n"));
        return b.toString();
    }
    public String lastDetection(){return lastDetection;}
    @Override public void close(){detector.shutdownNow();}
}
