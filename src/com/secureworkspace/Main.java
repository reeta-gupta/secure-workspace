
package com.secureworkspace;
import java.util.concurrent.*;
public final class Main {
    public static void main(String[] args)throws Exception{
        Db.init();
        LockManager locks=new LockManager();
        Services services=new Services(locks);
        ScheduledExecutorService reaper=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"session-resource-reaper");t.setDaemon(true);return t;});
        reaper.scheduleAtFixedRate(()->{try{services.reapExpiredSessions();}catch(Exception e){e.printStackTrace();}},15,15,TimeUnit.SECONDS);
        Runtime.getRuntime().addShutdownHook(new Thread(()->{locks.close();reaper.shutdownNow();}));
        new WebServer(services).start();
    }
}
