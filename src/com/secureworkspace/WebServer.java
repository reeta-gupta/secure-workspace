
package com.secureworkspace;
import com.sun.net.httpserver.*;
import java.net.*;import java.io.*;import java.nio.charset.StandardCharsets;import java.util.*;import java.util.concurrent.*;

public final class WebServer {
    private final Services svc; private final HttpServer server;
    public WebServer(Services svc)throws Exception{
        this.svc=svc;server=HttpServer.create(new InetSocketAddress("127.0.0.1",8090),0);
        server.setExecutor(Executors.newCachedThreadPool());server.createContext("/",this::handle);
    }
    private static Map<String,String> form(HttpExchange x)throws Exception{
        Map<String,String> m=new HashMap<>();String body=new String(x.getRequestBody().readAllBytes(),StandardCharsets.UTF_8);
        for(String part:body.split("&")){String[] a=part.split("=",2);if(a.length==2)m.put(URLDecoder.decode(a[0],"UTF-8"),URLDecoder.decode(a[1],"UTF-8"));}
        return m;
    }
    private static String esc(String s){return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;");}
    private static void send(HttpExchange x,int status,String type,String body)throws IOException{
        byte[] b=body.getBytes(StandardCharsets.UTF_8);x.getResponseHeaders().set("Content-Type",type+"; charset=utf-8");x.getResponseHeaders().set("X-Content-Type-Options","nosniff");x.getResponseHeaders().set("Cache-Control","no-store");x.sendResponseHeaders(status,b.length);x.getResponseBody().write(b);x.close();
    }
    private static Map<String,String> query(HttpExchange x)throws Exception{
        Map<String,String> m=new HashMap<>();String q=x.getRequestURI().getRawQuery();
        if(q!=null)for(String part:q.split("&")){String[] a=part.split("=",2);if(a.length==2)m.put(URLDecoder.decode(a[0],"UTF-8"),URLDecoder.decode(a[1],"UTF-8"));}
        return m;
    }
    private static void redirect(HttpExchange x,String to)throws IOException{x.getResponseHeaders().set("Location",to);x.sendResponseHeaders(303,-1);x.close();}
    private static String cookie(HttpExchange x){String c=x.getRequestHeaders().getFirst("Cookie");if(c!=null)for(String p:c.split(";"))if(p.trim().startsWith("SW="))return p.trim().substring(3);return null;}
    private String html(String body){return "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Secure Workspace</title><style>"+css()+"</style></head><body>"+body+"</body></html>";}
    private String css(){return """
      *{box-sizing:border-box}body{margin:0;background:#f7f8fc;color:#293449;font:14px Inter,'Segoe UI',Arial,sans-serif}button,a{cursor:pointer}a{color:#6875c9;text-decoration:none}
      .layout{display:grid;grid-template-columns:240px 1fr;min-height:100vh}.side{background:#f0f1f7;border-right:1px solid #e5e7ef;padding:24px 16px}.brand{font-weight:800;font-size:18px;margin:5px 8px 28px;color:#38415c}.brand span{color:#8d83d8}.profile{background:white;border:1px solid #e8eaf2;border-radius:16px;padding:13px;margin-bottom:25px}.avatar{display:inline-grid;place-items:center;width:36px;height:36px;border-radius:50%;background:#e9e5ff;color:#6c60bb;font-weight:700;margin-right:8px}.nav{display:block;padding:11px 13px;border-radius:10px;color:#697187;margin:4px 0}.nav.active{background:#e6e5fb;color:#5b55a7;font-weight:700}.main{padding:30px 34px;max-width:1500px;width:100%;margin:auto}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}.top h1{font-size:27px;margin:0}.muted{color:#8991a4}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}.card{background:white;border:1px solid #e9ebf2;border-radius:17px;padding:19px;box-shadow:0 4px 18px #28345a08;margin-bottom:17px}.metric{font-size:25px;font-weight:750;margin-top:9px}.label{font-size:12px;color:#8991a4;font-weight:700;text-transform:uppercase;letter-spacing:.06em}.pill{display:inline-block;border-radius:30px;padding:5px 10px;font-size:11px;font-weight:700}.mint{background:#dff5e9;color:#28734e}.amber{background:#fff0d9;color:#99621d}.rose{background:#ffe3e7;color:#a63d50}.lav{background:#ebe9ff;color:#655bb0}.btn{border:0;border-radius:10px;padding:10px 15px;background:#7771c8;color:white;font-weight:650}.btn.soft{background:#eeedff;color:#625bb0}.btn.dark{background:#29334a}.field{width:100%;border:1px solid #e1e5ee;border-radius:10px;padding:11px;background:#fbfcff;margin:7px 0 13px;color:#293449}.editor{min-height:150px;font:13px Consolas,monospace}.row{display:flex;gap:14px;align-items:center;flex-wrap:wrap}.between{display:flex;justify-content:space-between;align-items:center;gap:10px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px;border-bottom:1px solid #f0f1f5}th{color:#8991a4;font-size:11px;text-transform:uppercase}.terminal{background:#20283a;color:#b8e8cd;border-radius:12px;padding:16px;white-space:pre-wrap;min-height:90px;font:12px Consolas,monospace}.bar{height:9px;background:#edf0f5;border-radius:20px;overflow:hidden}.bar i{display:block;height:100%;background:#8bd6b0;border-radius:20px}.auth{max-width:440px;margin:9vh auto}.auth .card{padding:30px}.auth h1{font-size:25px}.small{font-size:12px}.warning{background:#fff1dd;color:#94601c;border:1px solid #ffe1b0;border-radius:12px;padding:12px;margin:12px 0}.error{background:#ffe7e9;color:#a23c50;padding:10px;border-radius:10px}.two{display:grid;grid-template-columns:1.4fr 1fr;gap:16px}@media(max-width:950px){.grid{grid-template-columns:repeat(2,1fr)}.layout{grid-template-columns:1fr}.side{position:static}.nav{display:inline-block}.two{grid-template-columns:1fr}}@media(max-width:560px){.grid{grid-template-columns:1fr}.main{padding:20px 14px}.top{align-items:flex-start;flex-direction:column}}
      """;}
    private String loginPage(){return html("<div class='auth'><div class='card'><div class='brand'>◈ Secure <span>Workspace</span></div><h1>Welcome back</h1><p class='muted'>Sign in to your private workspace.</p><form method='post' action='/login'><label>Username</label><input class='field' name='username' required><label>Password</label><input class='field' type='password' name='password' required><button class='btn' style='width:100%'>Sign in</button></form><p class='small' style='text-align:right'><a href='/forgot-password'>Forgot password?</a></p><hr style='border:0;border-top:1px solid #eee;margin:22px 0'><h3>Create account</h3><form method='post' action='/register'><input class='field' name='username' placeholder='Username (3+ characters)' required><input class='field' type='password' name='password' placeholder='Password (8+ characters)' required><button class='btn soft' style='width:100%'>Register</button></form></div><p class='muted small' style='text-align:center'>Local Windows application · SQLite embedded database</p></div>");}
    private String dashboard(int uid)throws Exception{
        List<Map<String,Object>> files=svc.files(uid);StringBuilder rows=new StringBuilder();
        String accountRole=svc.role(uid);
        for(Map<String,Object> f:files)rows.append("<tr><td>▤ <a href='/file?id=").append(f.get("id")).append("'>").append(esc(f.get("filename").toString())).append("</a></td><td>v").append(f.get("version")).append("</td><td>").append(f.get("bytes")).append(" B</td><td><span class='pill mint'>Private</span></td></tr>");
        String log=svc.logs(uid,12);String safeLog=esc(log);
        StringBuilder pend=new StringBuilder();
        if("ADMIN".equals(accountRole)){
            List<Services.HelpRequest> reqs=svc.pendingRequests(uid);
            pend.append("<div class='label'>Pending help requests ("+reqs.size()+")</div>");
            if(reqs.isEmpty())pend.append("<p class='muted small'>No one is asking for help right now.</p>");
            else{pend.append("<p class='muted small'>These users said they cannot sign in and have no recovery codes. <b>Contact them yourself and be sure it is really them</b> before giving a ticket: anyone holding a ticket can take over that account.</p><table><tr><th>User</th><th>Asked at</th><th>From IP</th><th></th></tr>");
                for(Services.HelpRequest r:reqs)pend.append("<tr><td>").append(esc(r.username())).append("</td><td>").append(esc(Services.fmtTime(java.time.Instant.ofEpochMilli(r.requestedMs()).toString()))).append("</td><td>").append(esc(r.ip())).append("</td><td class='row'><form method='post' action='/admin-ticket'><input type='hidden' name='username' value='").append(esc(r.username())).append("'><button class='btn soft'>Issue ticket</button></form><form method='post' action='/admin-dismiss-request'><input type='hidden' name='id' value='").append(r.id()).append("'><button class='btn dark'>Dismiss</button></form></td></tr>");
                pend.append("</table>");}
        }
        String adminPanel="ADMIN".equals(accountRole)?"<section class='card'><h2 style='margin-top:0'>Account recovery · Administrator</h2><p class='muted small'>If a user lost their recovery codes, issue a one-time reset ticket. You never see or choose their password: the user picks a new one on the Forgot password page. A ticket works once and expires in 15 minutes; every ticket is written to the audit log.</p>"+pend+"<form method='post' action='/admin-ticket'><label>Username</label><input class='field' name='username' required><button class='btn soft'>Issue reset ticket</button></form></section>":"";
        int codesLeft=svc.recoveryCodesLeft(uid);
        String securityCard="<div class='card' id='security'><h2 style='margin-top:0'>Account security</h2><div class='between'><b>Recovery codes left</b><span class='pill "+(codesLeft>=3?"mint":codesLeft>0?"amber":"rose")+"'>"+codesLeft+" of 8</span></div><p class='muted small'>Recovery codes let you reset a forgotten password without any administrator. Generating a new set invalidates the old one.</p><form method='post' action='/recovery-codes'><input class='field' type='password' name='password' placeholder='Current password' required><button class='btn soft'>Generate new recovery codes</button></form></div>";
        String notice=svc.resetNotice(uid);
        String noticeBanner=notice==null?"":"<div class='warning'>🔐 "+esc(notice)+"<form method='post' action='/dismiss-notice' style='margin-top:8px'><button class='btn soft'>Dismiss</button></form></div>";
        Services.Usage us=svc.usage(uid);int pct=us.quota()<=0?0:(int)Math.min(100,Math.max(us.used()>0?1:0,us.used()*100/us.quota()));
        String usageText=Services.formatBytes(us.used())+" of "+Services.formatBytes(us.quota());
        String barClass=pct>=90?"rose":pct>=70?"amber":"mint";
        StringBuilder sharedRows=new StringBuilder();
        for(Map<String,Object> f:svc.sharedWithMe(uid))sharedRows.append("<tr><td>▤ <a href='/file?id=").append(f.get("id")).append("'>").append(esc(f.get("filename").toString())).append("</a></td><td>").append(esc(f.get("owner").toString())).append("</td><td><span class='pill ").append("WRITE".equals(f.get("permission"))?"amber'>Can edit":"lav'>Read only").append("</span></td></tr>");
        String sharedCard=sharedRows.length()==0?"":"<section class='card'><h2 style='margin-top:0'>Shared with me</h2><p class='muted small'>Files other users chose to share with you. You can only do what the owner allowed.</p><table><tr><th>File</th><th>Owner</th><th>Your access</th></tr>"+sharedRows+"</table></section>";
        String deadlockCard=deadlockCard(uid,"ADMIN".equals(accountRole));
        String quotaAdmin="ADMIN".equals(accountRole)?quotaAdminPanel(uid):"";
        return html("<div class='layout'><aside class='side'><div class='brand'>◈ Secure <span>Workspace</span></div><div class='profile'><span class='avatar'>U"+uid+"</span><b>Workspace user</b><div class='muted small'>User ID "+uid+"</div></div><a class='nav active' href='/dashboard'>⌂ &nbsp; Dashboard</a><a class='nav' href='#files'>▤ &nbsp; My Workspace</a><a class='nav' href='#monitor'>◉ &nbsp; OS & Sessions</a><a class='nav' href='#deadlock'>⌘ &nbsp; Deadlock (WFG)</a><a class='nav' href='#activity'>☷ &nbsp; Activity Logs</a><a class='nav' href='/sessions'>⇄ &nbsp; Sessions</a><a class='nav' href='/trash'>🗑 &nbsp; Trash</a>"+("ADMIN".equals(accountRole)?"<a class='nav' href='/admin'>▥ &nbsp; Analytics</a>":"")+"<a class='nav' href='/logout'>↪ &nbsp; Logout</a><div style='margin-top:35px' class='muted small'>SECURE WORKSPACE<br>Windows local edition</div></aside><main class='main'>"+noticeBanner+"<div class='top'><div><div class='muted small'>PERSONAL WORKSPACE / OVERVIEW</div><h1>Good day 👋</h1><div class='muted'>Your files, processes and sessions at a glance.</div></div><span class='pill mint'>● System online</span></div><section class='grid'><div class='card'><div class='label'>My files</div><div class='metric'>"+files.size()+"</div><span class='pill lav'>Workspace items</span></div><div class='card'><div class='label'>Storage used</div><div class='metric'>"+esc(Services.formatBytes(us.used()))+"</div><span class='pill "+barClass+"'>"+pct+"% of quota</span></div><div class='card'><div class='label'>Active session</div><div class='metric'>1</div><span class='pill mint'>● Active</span></div><div class='card'><div class='label'>Account</div><div class='metric'>#"+uid+"</div><span class='pill lav'>"+esc(accountRole)+"</span></div></section><div class='two'><section class='card' id='files'><div class='between'><div><h2 style='margin:0'>Workspace File Explorer</h2><p class='muted small'>Create and manage your private files.</p></div><span class='pill lav'>Private area</span></div><div class='row small' style='margin:8px 0'><a href='/trash'>🗑 Trash</a><a href='/sessions'>⇄ My sessions</a></div><form method='post' action='/save'><input class='field' name='filename' placeholder='File name, e.g. notes.txt' required><textarea class='field editor' name='content' placeholder='Write your file content...'></textarea><input class='field' type='number' name='version' value='0' placeholder='Expected version (0 for new file)'><button class='btn'>＋ Save file</button></form><div class='warning'>Open a file to edit it, take a read/write lock or share it with another user.</div><table><tr><th>File name</th><th>Version</th><th>Size</th><th>Access</th></tr>"+rows+"</table></section><section><div class='card'><h2 style='margin-top:0'>Storage quota</h2><div class='between'><b>Workspace capacity</b><span class='pill "+barClass+"'>"+pct+"% used</span></div><div class='bar' style='margin:14px 0'><i style='width:"+pct+"%'></i></div><div class='muted small'>"+esc(usageText)+". Saves that would go over the limit are rejected by the backend.</div></div>"+securityCard+"<div class='card' id='monitor'><h2 style='margin-top:0'>OS Resource & Session Monitor</h2><p class='muted small'>Launch a real Windows child process.</p><form method='post' action='/worker'><button class='btn soft'>▶ Launch OS worker process</button></form><span class='pill mint'>ProcessBuilder / Windows</span></div>"+deadlockCard+"</section></div>"+sharedCard+adminPanel+quotaAdmin+"<section class='card' id='activity'><div class='between'><h2 style='margin:0'>Activity audit log</h2><span class='pill amber'>Recent events</span></div><div class='terminal'>"+safeLog+"</div></section><p class='muted small'>Secure Workspace · Java HTTP Server · Embedded SQLite</p></main></div>");
    }
    private String changePasswordPage(){return html("<div class='auth'><div class='card'><div class='brand'>◈ Secure <span>Workspace</span></div><h1>Change temporary password</h1><p class='muted'>Your administrator reset your password. Choose a new password to continue.</p><form method='post' action='/change-password'><label>New password</label><input class='field' type='password' name='newPassword' minlength='8' required><button class='btn' style='width:100%'>Update password</button></form></div></div>");}
    private String forgotPasswordPage(String error){return html("<div class='auth'><div class='card'><div class='brand'>◈ Secure <span>Workspace</span></div><h1>Reset your password</h1><p class='muted'>Enter one of your <b>recovery codes</b> (shown when you registered) or a <b>reset ticket</b> from your administrator, then choose a new password. No email is involved and nobody else ever sees your new password.</p>"+(error==null?"":"<div class='error'>"+esc(error)+"</div>")+"<form method='post' action='/forgot-password'><label>Username</label><input class='field' name='username' required autocomplete='username'><label>Recovery code or reset ticket</label><input class='field' name='secret' placeholder='XXXX-XXXX-XXXX-XXXX' required autocomplete='off'><label>New password (8+ characters)</label><input class='field' type='password' name='newPassword' minlength='8' required autocomplete='new-password'><label>Confirm new password</label><input class='field' type='password' name='confirm' minlength='8' required autocomplete='new-password'><button class='btn' style='width:100%'>Reset password</button></form><hr style='border:0;border-top:1px solid #e9ebf2;margin:16px 0'><p class='muted small'><b>Lost your recovery codes too?</b> Ask the administrator for help. They will contact you and must confirm it is really you before giving you a one-time ticket.</p><form method='post' action='/request-help'><input class='field' name='username' placeholder='Your username' required><button class='btn soft' style='width:100%'>Ask administrator for help</button></form><p class='small'><a href='/'>Back to sign in</a></p></div></div>");}
    private String helpSentPage(){return html("<div class='auth'><div class='card'><div class='brand'>◈ Secure <span>Workspace</span></div><h1>Request sent</h1><p class='muted'>If an account with that username exists, the administrator can now see that you need help. They will contact you and may ask you to prove who you are. Nothing changes on your account until they give you a one-time ticket.</p><p class='small'>Then come back to <a href='/forgot-password'>Forgot password</a> and enter the ticket.</p><p class='small'><a href='/'>Back to sign in</a></p></div></div>");}
    private String resetDonePage(Services.ResetResult r){return html("<div class='auth'><div class='card'><div class='brand'>◈ Secure <span>Workspace</span></div><h1>Password updated</h1><p class='muted'>Your password was changed and every existing session of this account was signed out. Sign in with your new password.</p>"+("RECOVERY_CODE".equals(r.via())?"<div class='warning'>Recovery codes left: <b>"+r.codesLeft()+"</b> of 8."+(r.codesLeft()<3?" Generate a fresh set from your dashboard after you sign in.":"")+"</div>":"")+"<a class='btn' href='/'>Sign in</a></div></div>");}
    /** Shows recovery codes. They exist in plain text only in this one response. */
    private String codesPanel(String title,String intro,List<String> codes,String href,String label){
        StringBuilder b=new StringBuilder();for(String c:codes)b.append(esc(c)).append("\n");
        return "<div class='auth'><div class='card'><div class='brand'>◈ Secure <span>Workspace</span></div><h1>"+esc(title)+"</h1><p class='muted'>"+esc(intro)+"</p><div class='terminal'>"+b+"</div><div class='warning'>⚠️ These codes are shown <b>only once</b>. Store them somewhere safe outside this app (paper or a password manager). Each code works one time. Anyone who has a code can reset your password, so never share them.</div><a class='btn' href='"+href+"'>"+esc(label)+"</a></div></div>";
    }
    /** Shows an admin-issued reset ticket (again, only in this one response). */
    private String ticketPanel(String username,String ticket){
        return "<div class='auth'><div class='card'><div class='brand'>◈ Secure <span>Workspace</span></div><h1>Reset ticket for "+esc(username)+"</h1><p class='muted'>Give this ticket to the user in person or over a channel you trust. It works <b>once</b> and expires in <b>15 minutes</b>. The user chooses their own new password on the Forgot password page; you never see or set it.</p><div class='terminal'>"+esc(ticket)+"</div><div class='warning'>⚠️ Until it is used or expires, anyone holding this ticket can take over that account. Do not post it in a group chat. This action is recorded in the audit log.</div><a class='btn' href='/dashboard'>Back to dashboard</a></div></div>";
    }
    private static int intParam(Map<String,String> f,String name){
        try{return Integer.parseInt(f.getOrDefault(name,"").trim());}catch(NumberFormatException e){throw new IllegalArgumentException("Invalid request.");}
    }
    /** Draws a wait-for graph: arrow A -> B means "A waits for a lock that B holds". Edges inside a deadlock cycle are red. */
    private String graphSvg(Map<Integer,Set<Integer>> edges,Collection<Integer> cycle)throws Exception{
        TreeSet<Integer> nodes=new TreeSet<>(cycle);edges.forEach((k,v)->{nodes.add(k);nodes.addAll(v);});
        if(nodes.isEmpty())return "";
        int n=nodes.size(),cx=170,cy=105,r=n==1?0:70;Map<Integer,double[]> pos=new LinkedHashMap<>();int i=0;
        for(int id:nodes){double a=-Math.PI/2+2*Math.PI*i++/n;pos.put(id,new double[]{cx+r*Math.cos(a),cy+r*Math.sin(a)});}
        StringBuilder b=new StringBuilder("<svg viewBox='0 0 340 210' style='width:100%;max-width:380px;background:#fbfcff;border:1px solid #e9ebf2;border-radius:12px' role='img' aria-label='Wait-for graph'><defs><marker id='ag' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='7' markerHeight='7' orient='auto-start-reverse'><path d='M0 0L10 5L0 10z' fill='#9aa3b5'/></marker><marker id='ar' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='7' markerHeight='7' orient='auto-start-reverse'><path d='M0 0L10 5L0 10z' fill='#d1495b'/></marker></defs>");
        Set<Integer> cyc=new HashSet<>(cycle);
        for(Map.Entry<Integer,Set<Integer>> e:edges.entrySet())for(int to:e.getValue()){
            double[] p=pos.get(e.getKey()),q=pos.get(to);double dx=q[0]-p[0],dy=q[1]-p[1],len=Math.max(1,Math.hypot(dx,dy));
            boolean red=cyc.contains(e.getKey())&&cyc.contains(to);
            b.append(String.format(Locale.ROOT,"<line x1='%.1f' y1='%.1f' x2='%.1f' y2='%.1f' stroke='%s' stroke-width='2' marker-end='url(#%s)'/>",p[0]+dx/len*20,p[1]+dy/len*20,q[0]-dx/len*22,q[1]-dy/len*22,red?"#d1495b":"#9aa3b5",red?"ar":"ag"));
        }
        for(int id:nodes){double[] p=pos.get(id);boolean red=cyc.contains(id);
            b.append(String.format(Locale.ROOT,"<circle cx='%.1f' cy='%.1f' r='19' fill='%s' stroke='%s' stroke-width='2'/><text x='%.1f' y='%.1f' text-anchor='middle' font-size='10' fill='#293449'>%s</text>",p[0],p[1],red?"#ffe3e7":"#ebe9ff",red?"#d1495b":"#7771c8",p[0],p[1]+3.5,esc(shorten(svc.usernameOf(id),8))));}
        return b.append("</svg>").toString();
    }
    private static String shorten(String s,int n){return s.length()<=n?s:s.substring(0,n-1)+"…";}
    private String deadlockCard(int uid,boolean admin)throws Exception{
        StringBuilder b=new StringBuilder("<div class='card' id='deadlock'><h2 style='margin-top:0'>Wait-for Graph Monitor</h2>");
        if(admin){
            Map<Integer,Set<Integer>> live=svc.locks().waitForGraph();
            b.append("<div class='label'>Live graph</div>");
            b.append(live.isEmpty()?"<p class='muted small'>Nobody is waiting for a lock right now.</p>":graphSvg(live,List.of())+"<p class='muted small'>An arrow A → B means A is waiting for a lock that B holds.</p>");
            LockManager.Deadlock d=svc.locks().lastDeadlock();
            if(d!=null)b.append("<div class='label' style='margin-top:12px'>Last deadlock (resolved)</div>").append(graphSvg(d.edges(),d.cycle())).append("<p class='muted small'>Detected ").append(esc(Services.fmtTime(d.at()))).append(". Victim: <b>").append(esc(svc.usernameOf(d.victim()))).append("</b> (its locks were released so the others can continue).</p>");
            b.append("<div class='terminal'>").append(esc(svc.lockSnapshot(uid))).append(esc(svc.detectorStatus())).append("</div>");
        }else{
            String mine=svc.lockSnapshot(uid);
            b.append("<div class='terminal'>").append(esc(mine.isEmpty()?"You hold no locks.\n":mine)).append("</div><p class='muted small'>You only see your own locks. Deadlocks involving you are resolved automatically and recorded in your activity log.</p>");
        }
        return b.append("<p class='muted small'>Background DFS detector runs every 3 seconds.</p></div>").toString();
    }
    private String quotaAdminPanel(int adminId)throws Exception{
        StringBuilder rows=new StringBuilder();
        for(Map<String,Object> m:svc.usageAll(adminId)){long used=(Long)m.get("used"),q=(Long)m.get("quota");int pct=q<=0?0:(int)Math.min(100,used*100/q);
            rows.append("<tr><td>").append(esc(m.get("username").toString())).append("</td><td>").append(esc(Services.formatBytes(used))).append(" / ").append(esc(Services.formatBytes(q))).append("</td><td style='width:35%'><div class='bar'><i style='width:").append(pct).append("%'></i></div></td></tr>");}
        return "<section class='card'><h2 style='margin-top:0'>Resource allocation · Storage quotas</h2><p class='muted small'>You see sizes only, never file names or contents.</p><table><tr><th>User</th><th>Used / quota</th><th></th></tr>"+rows+"</table><form method='post' action='/set-quota' class='row' style='margin-top:12px'><input class='field' style='flex:1;margin:0' name='username' placeholder='Username' required><input class='field' style='width:150px;margin:0' type='number' name='quotaKb' placeholder='Quota in KB' min='10' max='102400' required><button class='btn soft'>Set quota</button></form></section>";
    }
    private String filePage(int uid,int fileId)throws Exception{
        Services.FileView f=svc.openFile(uid,fileId);boolean owner="OWNER".equals(f.access()),canWrite=owner||"WRITE".equals(f.access());
        StringBuilder lockInfo=new StringBuilder();
        for(LockManager.Held h:svc.locks().heldList())if(h.fileId()==fileId)lockInfo.append("<span class='pill ").append(h.userId()==uid?"mint":"amber").append("'>").append(esc(svc.usernameOf(h.userId()))).append(": ").append(h.type()).append(" lock</span> ");
        for(LockManager.Waiting w:svc.locks().waitingList())if(w.fileId()==fileId)lockInfo.append("<span class='pill rose'>").append(esc(svc.usernameOf(w.userId()))).append(" waiting (").append(w.type()).append(")</span> ");
        String lockForms="<form method='post' action='/lock' class='row'><input type='hidden' name='fileId' value='"+fileId+"'><input type='hidden' name='ui' value='1'><button class='btn soft' name='type' value='READ'>Take READ lock</button>"+(canWrite?"<button class='btn soft' name='type' value='WRITE'>Take WRITE lock</button>":"")+"</form><form method='post' action='/unlock' style='margin-top:8px'><input type='hidden' name='fileId' value='"+fileId+"'><input type='hidden' name='ui' value='1'><button class='btn dark'>Release my lock</button></form>";
        String editor=canWrite?"<form method='post' action='/save-file'><input type='hidden' name='fileId' value='"+fileId+"'><input type='hidden' name='version' value='"+f.version()+"'><textarea class='field editor' name='content'>"+esc(f.content())+"</textarea><button class='btn'>Save new version</button></form>":"<div class='terminal'>"+esc(f.content())+"</div><p class='muted small'>Read-only: the owner shared this file with read access.</p>";
        StringBuilder share=new StringBuilder();
        if(owner){
            share.append("<div class='card'><h2 style='margin-top:0'>Sharing</h2>");
            List<Services.Share> sh=svc.sharesOf(uid,fileId);
            if(sh.isEmpty())share.append("<p class='muted small'>Private: only you can open this file.</p>");
            for(Services.Share x:sh)share.append("<div class='between' style='margin:6px 0'><span>").append(esc(x.username())).append(" <span class='pill ").append("WRITE".equals(x.permission())?"amber'>can edit":"lav'>read only").append("</span></span><form method='post' action='/unshare'><input type='hidden' name='fileId' value='").append(fileId).append("'><input type='hidden' name='username' value='").append(esc(x.username())).append("'><button class='btn soft'>Remove</button></form></div>");
            share.append("<form method='post' action='/share'><input type='hidden' name='fileId' value='"+fileId+"'><input class='field' name='username' placeholder='Share with username' required><select class='field' name='permission'><option value='READ'>Read only</option><option value='WRITE'>Can edit</option></select><button class='btn'>Share</button></form></div>");
        }
        return html("<div class='main'><div class='top'><div><div class='muted small'>FILE</div><h1>"+esc(f.name())+"</h1><div class='muted'>Owner: "+esc(f.owner())+" · version "+f.version()+" · "+Services.formatBytes(f.bytes())+"</div></div><div class='row'><a class='btn soft' href='/history?id="+fileId+"'>⟲ History</a><a class='btn soft' href='/dashboard'>← Dashboard</a></div></div><div class='two'><section class='card'>"+editor+"</section><section><div class='card'><h2 style='margin-top:0'>Locks</h2><p class='muted small'>A WRITE lock excludes everyone else; READ locks can be shared. Saving is blocked while another user holds a lock.</p><div style='margin-bottom:10px'>"+(lockInfo.length()==0?"<span class='pill mint'>Unlocked</span>":lockInfo)+"</div>"+lockForms+"</div>"+share+(owner?"<div class='card'><h2 style='margin-top:0'>Delete</h2><p class='muted small'>Moves the file to your trash. Sharing is removed; you can restore it later.</p><form method='post' action='/trash-file' onsubmit=\"return confirm('Move this file to trash?')\"><input type='hidden' name='fileId' value='"+fileId+"'><button class='btn dark'>Move to trash</button></form></div>":"")+"</section></div></div>");
    }
    private String page(String crumb,String title,String sub,String body){
        return html("<div class='main'><div class='top'><div><div class='muted small'>"+esc(crumb)+"</div><h1>"+esc(title)+"</h1><div class='muted'>"+esc(sub)+"</div></div><a class='btn soft' href='/dashboard'>← Dashboard</a></div>"+body+"</div>");
    }
    private String sessionsPage(int uid,String token)throws Exception{
        StringBuilder rows=new StringBuilder();int activeN=0;
        for(Services.SessionRow r:svc.mySessions(uid,token)){
            if(r.active())activeN++;
            rows.append("<tr><td>").append(esc(r.ip().isEmpty()?"-":r.ip())).append("</td><td>").append(esc(Services.fmtTime(r.created()))).append("</td><td>").append(esc(Services.fmtTime(r.lastSeen()))).append("</td><td>");
            if(r.current())rows.append("<span class='pill mint'>This session</span>");
            else if(r.active())rows.append("<span class='pill amber'>Active</span> <form method='post' action='/revoke-session' style='display:inline'><input type='hidden' name='id' value='").append(esc(r.id())).append("'><button class='btn soft'>Sign out</button></form>");
            else rows.append("<span class='pill lav'>Ended</span>");
            rows.append("</td></tr>");
        }
        return page("ACCOUNT / SESSIONS","My sessions","Every place you are signed in. Sessions expire after 30 minutes without activity.","<section class='card'><div class='between'><b>"+activeN+" active session(s)</b><form method='post' action='/revoke-others'><button class='btn dark'>Sign out all other sessions</button></form></div><p class='muted small'>If you see an IP address you do not recognise, sign out everywhere else and generate new recovery codes.</p><table><tr><th>IP address</th><th>Signed in</th><th>Last activity</th><th>Status</th></tr>"+rows+"</table></section>");
    }
    private String trashPage(int uid)throws Exception{
        StringBuilder rows=new StringBuilder();List<Map<String,Object>> t=svc.trash(uid);
        for(Map<String,Object> f:t)rows.append("<tr><td>▤ ").append(esc(f.get("filename").toString())).append("</td><td>v").append(f.get("version")).append("</td><td>").append(esc(Services.formatBytes(((Integer)f.get("bytes")).longValue()))).append("</td><td>").append(esc(Services.fmtTime(f.get("deleted").toString()))).append("</td><td class='row'><form method='post' action='/restore-file'><input type='hidden' name='fileId' value='").append(f.get("id")).append("'><button class='btn soft'>Restore</button></form><form method='post' action='/purge-file' onsubmit=\"return confirm('Delete forever? This also removes its history.')\"><input type='hidden' name='fileId' value='").append(f.get("id")).append("'><button class='btn dark'>Delete forever</button></form></td></tr>");
        return page("WORKSPACE / TRASH","Trash","Deleted files do not use your quota. Restoring brings the file back as private.","<section class='card'>"+(t.isEmpty()?"<p class='muted'>Trash is empty.</p>":"<table><tr><th>File</th><th>Version</th><th>Size</th><th>Deleted</th><th></th></tr>"+rows+"</table>")+"</section>");
    }
    private String historyPage(int uid,int fileId,Integer selected)throws Exception{
        Services.FileView f=svc.openFile(uid,fileId);boolean canWrite="OWNER".equals(f.access())||"WRITE".equals(f.access());
        StringBuilder rows=new StringBuilder();
        for(Services.Version v:svc.history(uid,fileId))rows.append("<tr").append(selected!=null&&selected==v.version()?" style='background:#f3f1ff'":"").append("><td>v").append(v.version()).append(v.version()==f.version()?" <span class='pill mint'>current</span>":"").append("</td><td>").append(esc(v.savedBy())).append("</td><td>").append(esc(Services.fmtTime(v.savedAt()))).append("</td><td>").append(esc(Services.formatBytes(v.bytes()))).append("</td><td><a href='/history?id=").append(fileId).append("&v=").append(v.version()).append("'>Compare</a></td></tr>");
        String detail="";
        if(selected!=null){
            String old=svc.versionContent(uid,fileId,selected);StringBuilder d=new StringBuilder();
            List<String[]> ops=Services.diff(old,f.content());
            if(ops==null)d.append("<p class='muted'>Files are too large to compare line by line.</p>");
            else{d.append("<div class='terminal' style='background:#fff;color:#293449;border:1px solid #e9ebf2'>");for(String[] o:ops){String bg=o[0].equals("+")?"background:#e3f6ea":o[0].equals("-")?"background:#ffe7e9":"";d.append("<div style='").append(bg).append("'>").append(o[0].equals("=")?"&nbsp;&nbsp;":o[0]+" ").append(esc(o[1])).append("</div>");}d.append("</div>");}
            detail="<section class='card'><div class='between'><h2 style='margin:0'>Version "+selected+" → current (v"+f.version()+")</h2>"+(canWrite&&selected!=f.version()?"<form method='post' action='/restore-version'><input type='hidden' name='fileId' value='"+fileId+"'><input type='hidden' name='version' value='"+selected+"'><input type='hidden' name='current' value='"+f.version()+"'><button class='btn'>Restore this version</button></form>":"")+"</div><p class='muted small'>Red lines were removed since that version, green lines were added. Restoring saves the old text as a new version; nothing is erased.</p>"+d+"</section>";
        }
        return page("FILE / HISTORY","History of "+f.name(),"Newest 20 versions are kept. Each save records who made it.","<section class='card'><table><tr><th>Version</th><th>Saved by</th><th>When</th><th>Size</th><th></th></tr>"+rows+"</table><p class='small'><a href='/file?id="+fileId+"'>← Back to file</a></p></section>"+detail);
    }
    private String analyticsPage(int uid)throws Exception{
        Services.Analytics a=svc.analytics(uid);
        int max=1;for(Services.Day d:a.days())max=Math.max(max,Math.max(d.logins(),d.failed()));
        StringBuilder chart=new StringBuilder("<svg viewBox='0 0 420 190' style='width:100%;max-width:520px' role='img' aria-label='Logins and failed logins per day'>");
        int i=0;for(Services.Day d:a.days()){int x=20+i*58;int h1=d.logins()*120/max,h2=d.failed()*120/max;
            chart.append("<rect x='").append(x).append("' y='").append(145-h1).append("' width='20' height='").append(h1).append("' rx='3' fill='#8bd6b0'/><rect x='").append(x+22).append("' y='").append(145-h2).append("' width='20' height='").append(h2).append("' rx='3' fill='#d1495b'/>")
                .append("<text x='").append(x+21).append("' y='162' font-size='9' text-anchor='middle' fill='#8991a4'>").append(esc(d.date().substring(5))).append("</text><text x='").append(x+10).append("' y='").append(141-h1).append("' font-size='9' text-anchor='middle' fill='#293449'>").append(d.logins()).append("</text><text x='").append(x+32).append("' y='").append(141-h2).append("' font-size='9' text-anchor='middle' fill='#293449'>").append(d.failed()).append("</text>");i++;}
        chart.append("</svg><div class='small muted'><span class='pill mint'>Successful logins</span> <span class='pill rose'>Failed / throttled</span> · last 7 days (UTC)</div>");
        StringBuilder ev=new StringBuilder();int evMax=1;for(Map.Entry<String,Integer> e:a.events24h())evMax=Math.max(evMax,e.getValue());
        for(Map.Entry<String,Integer> e:a.events24h())ev.append("<tr><td>").append(esc(e.getKey())).append("</td><td style='width:55%'><div class='bar'><i style='width:").append(e.getValue()*100/evMax).append("%'></i></div></td><td>").append(e.getValue()).append("</td></tr>");
        StringBuilder sess=new StringBuilder();
        for(Services.SessionRow r:svc.activeSessions(uid))sess.append("<tr><td>").append(esc(r.username())).append("</td><td>").append(esc(r.ip().isEmpty()?"-":r.ip())).append("</td><td>").append(esc(Services.fmtTime(r.created()))).append("</td><td>").append(esc(Services.fmtTime(r.lastSeen()))).append("</td><td><form method='post' action='/admin-kill-session' onsubmit=\"return confirm('End this session?')\"><input type='hidden' name='id' value='").append(esc(r.id())).append("'><button class='btn soft'>End</button></form></td></tr>");
        StringBuilder stor=new StringBuilder();
        for(Map<String,Object> m:svc.usageAll(uid)){long used=(Long)m.get("used"),q=(Long)m.get("quota");int pct=q<=0?0:(int)Math.min(100,used*100/q);stor.append("<tr><td>").append(esc(m.get("username").toString())).append("</td><td>").append(esc(Services.formatBytes(used))).append(" / ").append(esc(Services.formatBytes(q))).append("</td><td style='width:40%'><div class='bar'><i style='width:").append(pct).append("%'></i></div></td></tr>");}
        String kpi="<section class='grid'>"+kpi("Users",""+a.users(),"registered")+kpi("Active sessions",""+a.activeSessions(),"right now")+kpi("Files",""+a.files(),a.trashed()+" in trash")+kpi("Storage",Services.formatBytes(a.storageUsed()),"of "+Services.formatBytes(a.storageQuota())+" allocated")+kpi("Locks held",""+a.locksHeld(),"live")+kpi("Waiting for a lock",""+a.locksWaiting(),"live")+"</section>";
        return page("ADMIN / ANALYTICS","System analytics","Counts and trends only. File names and contents are never shown here.",kpi+"<div class='two'><section class='card'><h2 style='margin-top:0'>Sign-in activity</h2>"+chart+"</section><section class='card'><h2 style='margin-top:0'>Events in the last 24 hours</h2><table>"+ev+"</table></section></div><section class='card'><h2 style='margin-top:0'>Active sessions</h2><table><tr><th>User</th><th>IP</th><th>Signed in</th><th>Last activity</th><th></th></tr>"+sess+"</table></section><section class='card'><h2 style='margin-top:0'>Storage per user</h2><table>"+stor+"</table></section><section class='card'><h2 style='margin-top:0'>Recent security events</h2><div class='terminal'>"+esc(a.recentSecurity())+"</div></section>");
    }
    private static String kpi(String label,String value,String sub){return "<div class='card'><div class='label'>"+esc(label)+"</div><div class='metric'>"+esc(value)+"</div><span class='pill lav'>"+esc(sub)+"</span></div>";}
    private void handle(HttpExchange x){
        try{
            String path=x.getRequestURI().getPath(),method=x.getRequestMethod(),token=cookie(x);int uid=svc.userForToken(token);
            if(path.equals("/")&&uid<0){send(x,200,"text/html",loginPage());return;}
            if(path.equals("/")){redirect(x,"/dashboard");return;} // already signed in: the home page is the dashboard, not a 404
            if(path.equals("/forgot-password")){
                if(method.equals("POST")){
                    Map<String,String> f=form(x);
                    try{send(x,200,"text/html",resetDonePage(svc.resetPassword(f.get("username"),f.get("secret"),f.get("newPassword"),f.get("confirm"),x.getRemoteAddress().getAddress().getHostAddress())));}
                    catch(SecurityException|IllegalArgumentException e){send(x,400,"text/html",forgotPasswordPage(e.getMessage()));}
                    return;
                }
                send(x,200,"text/html",forgotPasswordPage(null));return;
            }
            if(path.equals("/request-help")&&method.equals("POST")){
                Map<String,String> f=form(x);
                try{svc.requestHelp(f.get("username"),x.getRemoteAddress().getAddress().getHostAddress());send(x,200,"text/html",helpSentPage());}
                catch(SecurityException e){send(x,400,"text/html",forgotPasswordPage(e.getMessage()));}
                return;
            }
            if(path.equals("/register")&&method.equals("POST")){Map<String,String> f=form(x);Services.Registered r=svc.register(f.get("username"),f.get("password"));send(x,200,"text/html",html(codesPanel("Account created","Your account (user "+r.id()+") is ready. Save your recovery codes now: they are the only way to reset a forgotten password without an administrator.",r.codes(),"/","Continue to sign in")));return;}
            if(path.equals("/login")&&method.equals("POST")){Map<String,String> f=form(x);String t=svc.login(f.get("username"),f.get("password"),x.getRemoteAddress().getAddress().getHostAddress());x.getResponseHeaders().add("Set-Cookie","SW="+t+"; HttpOnly; SameSite=Strict; Path=/");send(x,200,"text/html",html("Signed in. <a class='btn' href='/dashboard'>Continue</a>"));return;}
            if(uid<0){send(x,401,"text/html",loginPage());return;}
            if(path.equals("/change-password")&&method.equals("POST")){Map<String,String> f=form(x);svc.changeTemporaryPassword(uid,f.get("newPassword"));send(x,200,"text/html",html("Password updated. <a class='btn' href='/dashboard'>Open dashboard</a>"));return;}
            if(svc.mustChangePassword(uid)&&!path.equals("/change-password")&&!path.equals("/logout")){send(x,200,"text/html",changePasswordPage());return;}
            if(path.equals("/admin-dismiss-request")&&method.equals("POST")){Map<String,String> f=form(x);svc.dismissRequest(uid,intParam(f,"id"));redirect(x,"/dashboard#recovery");return;}
            if(path.equals("/admin-ticket")&&method.equals("POST")){Map<String,String> f=form(x);String t=svc.issueResetTicket(uid,f.get("username"));send(x,200,"text/html",html(ticketPanel(f.get("username").trim(),t)));return;}
            if(path.equals("/recovery-codes")&&method.equals("POST")){Map<String,String> f=form(x);List<String> codes=svc.regenerateRecoveryCodes(uid,f.get("password"));send(x,200,"text/html",html(codesPanel("New recovery codes","Your previous codes no longer work.",codes,"/dashboard","Back to dashboard")));return;}
            if(path.equals("/dismiss-notice")&&method.equals("POST")){svc.dismissResetNotice(uid);x.getResponseHeaders().set("Location","/dashboard");x.sendResponseHeaders(303,-1);x.close();return;}
            if(path.equals("/dashboard")){send(x,200,"text/html",dashboard(uid));return;}
            if(path.equals("/sessions")&&method.equals("GET")){send(x,200,"text/html",sessionsPage(uid,token));return;}
            if(path.equals("/revoke-session")&&method.equals("POST")){Map<String,String> f=form(x);svc.revokeSession(uid,f.get("id"),token);redirect(x,"/sessions");return;}
            if(path.equals("/revoke-others")&&method.equals("POST")){svc.revokeOtherSessions(uid,token);redirect(x,"/sessions");return;}
            if(path.equals("/trash")&&method.equals("GET")){send(x,200,"text/html",trashPage(uid));return;}
            if(path.equals("/trash-file")&&method.equals("POST")){Map<String,String> f=form(x);svc.trashFile(uid,intParam(f,"fileId"));redirect(x,"/trash");return;}
            if(path.equals("/restore-file")&&method.equals("POST")){Map<String,String> f=form(x);svc.restoreFile(uid,intParam(f,"fileId"));redirect(x,"/dashboard#files");return;}
            if(path.equals("/purge-file")&&method.equals("POST")){Map<String,String> f=form(x);svc.purgeFile(uid,intParam(f,"fileId"));redirect(x,"/trash");return;}
            if(path.equals("/history")&&method.equals("GET")){Map<String,String> q=query(x);int id=intParam(q,"id");Integer v=q.containsKey("v")?Integer.valueOf(intParam(q,"v")):null;send(x,200,"text/html",historyPage(uid,id,v));return;}
            if(path.equals("/restore-version")&&method.equals("POST")){Map<String,String> f=form(x);int id=intParam(f,"fileId");svc.restoreVersion(uid,id,intParam(f,"version"),intParam(f,"current"));redirect(x,"/file?id="+id);return;}
            if(path.equals("/admin")&&method.equals("GET")){send(x,200,"text/html",analyticsPage(uid));return;}
            if(path.equals("/admin-kill-session")&&method.equals("POST")){Map<String,String> f=form(x);svc.adminTerminateSession(uid,f.get("id"));redirect(x,"/admin");return;}
            if(path.equals("/file")&&method.equals("GET")){String q=x.getRequestURI().getQuery();int id;try{id=Integer.parseInt(q==null?"":q.replaceFirst("^id=","").trim());}catch(NumberFormatException e){throw new IllegalArgumentException("Invalid request.");}send(x,200,"text/html",filePage(uid,id));return;}
            if(path.equals("/save-file")&&method.equals("POST")){Map<String,String> f=form(x);int id=intParam(f,"fileId");svc.saveFileById(uid,id,f.getOrDefault("content",""),intParam(f,"version"));redirect(x,"/file?id="+id);return;}
            if(path.equals("/share")&&method.equals("POST")){Map<String,String> f=form(x);int id=intParam(f,"fileId");svc.shareFile(uid,id,f.get("username"),f.getOrDefault("permission","READ"));redirect(x,"/file?id="+id);return;}
            if(path.equals("/unshare")&&method.equals("POST")){Map<String,String> f=form(x);int id=intParam(f,"fileId");svc.unshareFile(uid,id,f.get("username"));redirect(x,"/file?id="+id);return;}
            if(path.equals("/set-quota")&&method.equals("POST")){Map<String,String> f=form(x);long kb;try{kb=Long.parseLong(f.getOrDefault("quotaKb","").trim());}catch(NumberFormatException e){throw new IllegalArgumentException("Quota must be a number of KB.");}svc.setQuota(uid,f.get("username"),kb);redirect(x,"/dashboard#quota");return;}
            if(path.equals("/save")&&method.equals("POST")){Map<String,String> f=form(x);svc.saveFile(uid,f.get("filename"),f.getOrDefault("content",""),Integer.parseInt(f.getOrDefault("version","0")));send(x,200,"text/html",html("File saved. <a class='btn' href='/dashboard'>Return to dashboard</a>"));return;}
            if(path.equals("/worker")&&method.equals("POST")){Process p=new ProcessBuilder("cmd.exe","/c","echo","Secure Workspace worker").start();Db.log(uid,"PROCESS_STARTED","Windows PID "+p.pid());send(x,200,"text/html",html("Worker started. PID: "+p.pid()+" <a href='/dashboard'>Dashboard</a>"));return;}
            if(path.equals("/lock")&&method.equals("POST")){Map<String,String> f=form(x);int id=intParam(f,"fileId");String status=svc.acquireLock(id,uid,f.getOrDefault("type","WRITE"));if(f.containsKey("ui")){redirect(x,"/file?id="+id);return;}send(x,200,"application/json","{\"status\":\""+status+"\"}");return;}
            if(path.equals("/unlock")&&method.equals("POST")){Map<String,String> f=form(x);int id=intParam(f,"fileId");svc.releaseLock(id,uid);if(f.containsKey("ui")){redirect(x,"/file?id="+id);return;}send(x,200,"application/json","{\"status\":\"RELEASED\"}");return;}
            if(path.equals("/logout")){svc.logout(token,uid);x.getResponseHeaders().add("Set-Cookie","SW=; Max-Age=0; Path=/");send(x,200,"text/html",html("Signed out. <a href='/'>Login</a>"));return;}
            send(x,404,"text/plain","Not found");
        }catch(Exception e){try{send(x,400,"text/html",html("<div class='card'><span class='pill rose'>Request failed</span><h2>"+esc(e.getMessage()==null?e.toString():e.getMessage())+"</h2><a href='/dashboard'>Back to dashboard</a></div>"));}catch(Exception ignored){}}
    }
    // separate helper prevents accidental duplicate request-body reads
    private String formAgainNotUsed(){return "";}
    public void start(){server.start();System.out.println("Secure Workspace running at http://localhost:8090");}
}
