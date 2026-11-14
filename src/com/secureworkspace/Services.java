
package com.secureworkspace;
import java.sql.*;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public final class Services {
    private final LockManager locks;
    public Services(LockManager locks){this.locks=locks;}
    /** Returned by register(): the new user id plus the recovery codes, which are shown to the user exactly once. */
    public record Registered(int id,List<String> codes){}
    /** Returned by resetPassword(): how the reset was authorised and how many recovery codes remain. */
    public record ResetResult(String via,int codesLeft){}
    private static final long ATTEMPT_WINDOW_MS=15*60*1000L, TICKET_TTL_MS=15*60*1000L;
    private static final int MAX_ATTEMPTS_PER_USER=5, MAX_ATTEMPTS_PER_IP=30, RECOVERY_CODE_COUNT=8;
    private static final int LOGIN_MAX_PER_PAIR=5, LOGIN_MAX_PER_USER=25, LOGIN_MAX_PER_IP=30;
    private static final String LOGIN_FAILED="Invalid username or password", LOGIN_LOCKED="Too many failed sign-in attempts. Please wait 15 minutes and try again.";
    private static final String NO_ACCESS="You do not have access to this file.";
    private static final String RESET_FAILED="Invalid username, recovery code or ticket. Check them and try again.";
    public Registered register(String username,String password)throws Exception{
        username=username==null?"":username.trim();
        if(username.length()<3||username.length()>50||password==null||password.length()<8||password.length()>128)throw new IllegalArgumentException("Username must be 3-50 characters and password 8-128 characters.");
        String salt=Security.newSalt();int id;List<String> codes;
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("INSERT INTO users(username,password_hash,salt,created_at) VALUES(?,?,?,?)",Statement.RETURN_GENERATED_KEYS)){
            c.setAutoCommit(false); // user + workspace + recovery codes are created together or not at all
            p.setString(1,username);p.setString(2,Security.hash(password,salt));p.setString(3,salt);p.setString(4,Instant.now().toString());p.executeUpdate();
            try(ResultSet r=p.getGeneratedKeys()){r.next();id=r.getInt(1);}
            try(PreparedStatement a=c.prepareStatement("UPDATE users SET role='ADMIN' WHERE id=? AND NOT EXISTS (SELECT 1 FROM users WHERE role='ADMIN')")){a.setInt(1,id);a.executeUpdate();}
            try(PreparedStatement w=c.prepareStatement("INSERT INTO workspaces(user_id,created_at) VALUES(?,?)")){w.setInt(1,id);w.setString(2,Instant.now().toString());w.executeUpdate();}
            codes=newRecoveryCodes(c,id);c.commit();
        }
        Files.createDirectories(Path.of("workspaces","user_"+id));Db.log(id,"REGISTER","Workspace provisioned; recovery codes issued");return new Registered(id,codes);
    }
    public String login(String username,String password,String ip)throws Exception{
        username=username==null?"":username.trim();if(username.length()>100)username=username.substring(0,100);
        if(ip==null)ip="";
        long now=System.currentTimeMillis();
        pruneLoginAttempts(now);
        // Per user+IP (5) stops guessing; per user (25) and per IP (30) stop distributed/spray attacks without letting a stranger lock a victim out from everywhere.
        if(loginFails("SELECT COUNT(*) FROM login_attempts WHERE username=? AND ip=? AND at_ms>?",now,username,ip)>=LOGIN_MAX_PER_PAIR
         ||loginFails("SELECT COUNT(*) FROM login_attempts WHERE username=? AND at_ms>?",now,username)>=LOGIN_MAX_PER_USER
         ||loginFails("SELECT COUNT(*) FROM login_attempts WHERE ip=? AND at_ms>?",now,ip)>=LOGIN_MAX_PER_IP){
            Db.log(null,"LOGIN_THROTTLED","Sign-in blocked for '"+username+"' from "+ip);
            throw new SecurityException(LOGIN_LOCKED);
        }
        int id=-1;
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT id,password_hash,salt FROM users WHERE username=?")){
            p.setString(1,username);
            try(ResultSet r=p.executeQuery()){
                if(r.next()){if(Security.verify(password,r.getString(3),r.getString(2)))id=r.getInt(1);}
                else Security.hash("equalise-timing",Security.newSalt()); // unknown user costs the same time as a wrong password
            }
        }
        if(id<0){
            try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("INSERT INTO login_attempts(username,ip,at_ms) VALUES(?,?,?)")){p.setString(1,username);p.setString(2,ip);p.setLong(3,now);p.executeUpdate();}
            Db.log(null,"LOGIN_FAILED","Failed sign-in for '"+username+"' from "+ip);
            throw new SecurityException(LOGIN_FAILED);
        }
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("DELETE FROM login_attempts WHERE username=? AND ip=?")){p.setString(1,username);p.setString(2,ip);p.executeUpdate();}
        String token=UUID.randomUUID().toString(),stamp=Instant.now().toString();
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("INSERT INTO sessions(id,user_id,token,ip_address,expires_at,created_at,last_seen) VALUES(?,?,?,?,?,?,?)")){
            p.setString(1,UUID.randomUUID().toString());p.setInt(2,id);p.setString(3,token);p.setString(4,ip);p.setString(5,Instant.now().plusSeconds(1800).toString());p.setString(6,stamp);p.setString(7,stamp);p.executeUpdate();
        }
        Db.log(id,"LOGIN","Session created");return token;
    }
    private int loginFails(String sql,long now,String... vals)throws Exception{ // sql is always one of three fixed literals above
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement(sql)){
            int i=1;for(String v:vals)p.setString(i++,v);p.setLong(i,now-ATTEMPT_WINDOW_MS);
            try(ResultSet r=p.executeQuery()){r.next();return r.getInt(1);}
        }
    }
    private void pruneLoginAttempts(long now)throws Exception{
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("DELETE FROM login_attempts WHERE at_ms<?")){p.setLong(1,now-24*3600_000L);p.executeUpdate();}
    }
    public int userForToken(String token)throws Exception{
        if(token==null)return -1;
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT user_id FROM sessions WHERE token=? AND active=1 AND expires_at>?")){
            p.setString(1,token);p.setString(2,Instant.now().toString());
            try(ResultSet r=p.executeQuery()){if(!r.next())return -1;int id=r.getInt(1);
                try(PreparedStatement u=c.prepareStatement("UPDATE sessions SET last_seen=?,expires_at=? WHERE token=?")){
                    u.setString(1,Instant.now().toString());u.setString(2,Instant.now().plusSeconds(1800).toString());u.setString(3,token);u.executeUpdate();
                }return id;
            }
        }
    }
    public void logout(String token,int uid)throws Exception{
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("UPDATE sessions SET active=0 WHERE token=? AND user_id=?")){p.setString(1,token);p.setInt(2,uid);p.executeUpdate();}
        locks.releaseUser(uid);Db.log(uid,"LOGOUT","Session ended");
    }
    public String role(int uid)throws Exception{
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT role FROM users WHERE id=?")){
            p.setInt(1,uid);try(ResultSet r=p.executeQuery()){return r.next()?r.getString(1):"USER";}
        }
    }
    public boolean mustChangePassword(int uid)throws Exception{
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT must_change_password FROM users WHERE id=?")){
            p.setInt(1,uid);try(ResultSet r=p.executeQuery()){return r.next()&&r.getInt(1)==1;}
        }
    }
    // ===================== Account recovery (forgot password) =====================
    // Rule: nobody except the account owner ever chooses or sees a password. An administrator can only hand out a
    // one-time ticket that lets the OWNER pick a new password, and an administrator has no way to read workspaces.

    /** Replaces all recovery codes of a user with a fresh set (caller controls the transaction). */
    private List<String> newRecoveryCodes(Connection c,int uid)throws Exception{
        try(PreparedStatement d=c.prepareStatement("DELETE FROM recovery_codes WHERE user_id=?")){d.setInt(1,uid);d.executeUpdate();}
        List<String> out=new ArrayList<>();
        try(PreparedStatement p=c.prepareStatement("INSERT INTO recovery_codes(user_id,code_hash,created_at) VALUES(?,?,?)")){
            for(int i=0;i<RECOVERY_CODE_COUNT;i++){
                String code=Security.newRecoveryCode();
                p.setInt(1,uid);p.setString(2,Security.sha256("C:"+Security.normalizeCode(code)));p.setString(3,Instant.now().toString());p.executeUpdate();
                out.add(code);
            }
        }
        return out;
    }
    /** Logged-in user asks for a new set (needs the current password). Old codes stop working immediately. */
    public List<String> regenerateRecoveryCodes(int uid,String currentPassword)throws Exception{
        if(currentPassword==null||currentPassword.isEmpty())throw new IllegalArgumentException("Enter your current password to generate new codes.");
        List<String> codes;
        try(Connection c=Db.open()){
            String salt=null,hash=null;
            try(PreparedStatement p=c.prepareStatement("SELECT password_hash,salt FROM users WHERE id=?")){p.setInt(1,uid);try(ResultSet r=p.executeQuery()){if(r.next()){hash=r.getString(1);salt=r.getString(2);}}}
            if(hash==null||!Security.verify(currentPassword,salt,hash))throw new SecurityException("Current password is incorrect.");
            c.setAutoCommit(false);codes=newRecoveryCodes(c,uid);c.commit();
        }
        Db.log(uid,"RECOVERY_CODES_REGENERATED","New recovery codes issued; the old ones no longer work");
        return codes;
    }
    public int recoveryCodesLeft(int uid)throws Exception{
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NULL")){
            p.setInt(1,uid);try(ResultSet r=p.executeQuery()){r.next();return r.getInt(1);}
        }
    }

    /**
     * Administrator hands out a ONE-TIME ticket (128 random bits, valid 15 min, stored only as a hash).
     * The admin never sets or sees a password; the owner uses the ticket on the Forgot-password page to pick one.
     */
    public String issueResetTicket(int adminId,String username)throws Exception{
        if(!"ADMIN".equals(role(adminId)))throw new SecurityException("Administrator access required.");
        username=username==null?"":username.trim();
        int target;String targetRole;
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT id,role FROM users WHERE username=?")){
            p.setString(1,username);try(ResultSet r=p.executeQuery()){if(!r.next())throw new IllegalArgumentException("No account found with that username.");target=r.getInt(1);targetRole=r.getString(2);}
        }
        if(target==adminId)throw new IllegalArgumentException("You cannot issue a ticket for your own account. Use your recovery codes.");
        if("ADMIN".equals(targetRole))throw new IllegalArgumentException("Administrator accounts cannot be reset by ticket. They must use their recovery codes.");
        long now=System.currentTimeMillis();String ticket=Security.newTicket();
        try(Connection c=Db.open()){
            c.setAutoCommit(false);
            try(PreparedStatement p=c.prepareStatement("SELECT COUNT(*) FROM reset_tickets WHERE user_id=? AND created_ms>?")){p.setInt(1,target);p.setLong(2,now-3600_000L);try(ResultSet r=p.executeQuery()){r.next();if(r.getInt(1)>=3)throw new IllegalStateException("Three tickets were already issued for this user in the last hour. Try again later.");}}
            try(PreparedStatement p=c.prepareStatement("UPDATE reset_tickets SET expires_ms=0 WHERE user_id=? AND used_at IS NULL")){p.setInt(1,target);p.executeUpdate();} // only the newest ticket works
            try(PreparedStatement p=c.prepareStatement("INSERT INTO reset_tickets(user_id,token_hash,created_by,created_ms,expires_ms) VALUES(?,?,?,?,?)")){p.setInt(1,target);p.setString(2,Security.sha256("T:"+Security.normalizeTicket(ticket)));p.setInt(3,adminId);p.setLong(4,now);p.setLong(5,now+TICKET_TTL_MS);p.executeUpdate();}
            c.commit();
        }
        Db.log(adminId,"RESET_TICKET_ISSUED","Reset ticket issued for "+username+" (single use, 15 minutes). Admin does not see or set the password.");
        return ticket;
    }

    /**
     * Forgot-password: username + (recovery code OR admin ticket) + new password chosen by the owner.
     * Security properties: secrets stored hashed, single use (enforced inside the DB transaction), 15-minute ticket
     * expiry, rate limited per username and per IP, same error for every failure (no username enumeration), the
     * new password must differ from the old one, and ALL existing sessions of the account are signed out.
     */
    public ResetResult resetPassword(String username,String secret,String newPassword,String confirm,String ip)throws Exception{
        username=username==null?"":username.trim();
        if(username.length()>100)username=username.substring(0,100);
        if(newPassword==null||newPassword.length()<8||newPassword.length()>128)throw new IllegalArgumentException("New password must be 8 to 128 characters.");
        if(!newPassword.equals(confirm))throw new IllegalArgumentException("The two new passwords do not match.");
        long now=System.currentTimeMillis();
        pruneAttempts(now);
        if(attempts("username",username,now)>=MAX_ATTEMPTS_PER_USER||attempts("ip",ip,now)>=MAX_ATTEMPTS_PER_IP)
            throw new SecurityException("Too many attempts. Please wait 15 minutes and try again.");

        int uid=-1;String salt=null,hash=null;
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT id,password_hash,salt FROM users WHERE username=?")){
            p.setString(1,username);try(ResultSet r=p.executeQuery()){if(r.next()){uid=r.getInt(1);hash=r.getString(2);salt=r.getString(3);}}
        }
        String code=Security.normalizeCode(secret),ticket=Security.normalizeTicket(secret);
        String via=code.length()==16?"RECOVERY_CODE":ticket.length()==32?"ADMIN_TICKET":null;
        long secretRow=-1;
        if(uid>=0&&via!=null)secretRow=findSecret(uid,via,Security.sha256(("RECOVERY_CODE".equals(via)?"C:"+code:"T:"+ticket)),now);
        if(secretRow<0){
            Security.hash("equalise-timing",Security.newSalt()); // failures cost the same whether or not the user exists
            recordAttempt(username,ip,now);
            Db.log(uid<0?null:uid,"PASSWORD_RESET_FAILED","Failed password-reset attempt");
            throw new SecurityException(RESET_FAILED);
        }
        if(Security.verify(newPassword,salt,hash))throw new IllegalArgumentException("Choose a password that is different from your current one.");

        String newSalt=Security.newSalt(),newHash=Security.hash(newPassword,newSalt);
        try(Connection c=Db.open()){
            c.setAutoCommit(false);
            String mark="RECOVERY_CODE".equals(via)?"UPDATE recovery_codes SET used_at=? WHERE id=? AND used_at IS NULL":"UPDATE reset_tickets SET used_at=? WHERE id=? AND used_at IS NULL";
            try(PreparedStatement p=c.prepareStatement(mark)){p.setString(1,Instant.now().toString());p.setLong(2,secretRow);if(p.executeUpdate()!=1)throw new SecurityException(RESET_FAILED);} // lost a race: someone used it first
            try(PreparedStatement p=c.prepareStatement("UPDATE users SET password_hash=?,salt=?,must_change_password=0,reset_notice=? WHERE id=?")){p.setString(1,newHash);p.setString(2,newSalt);p.setString(3,via+"|"+Instant.now());p.setInt(4,uid);p.executeUpdate();}
            try(PreparedStatement p=c.prepareStatement("UPDATE sessions SET active=0 WHERE user_id=?")){p.setInt(1,uid);p.executeUpdate();}
            try(PreparedStatement p=c.prepareStatement("UPDATE reset_tickets SET expires_ms=0 WHERE user_id=? AND used_at IS NULL")){p.setInt(1,uid);p.executeUpdate();}
            c.commit();
        }
        locks.releaseUser(uid);
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("DELETE FROM reset_attempts WHERE username=?")){p.setString(1,username);p.executeUpdate();}
        Db.log(uid,"PASSWORD_RESET","Password reset via "+("RECOVERY_CODE".equals(via)?"recovery code":"administrator ticket")+"; all sessions signed out");
        return new ResetResult(via,recoveryCodesLeft(uid));
    }
    private long findSecret(int uid,String via,String h,long now)throws Exception{
        boolean ticket="ADMIN_TICKET".equals(via);
        String sql=ticket?"SELECT id FROM reset_tickets WHERE user_id=? AND token_hash=? AND used_at IS NULL AND expires_ms>?":"SELECT id FROM recovery_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL";
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement(sql)){
            p.setInt(1,uid);p.setString(2,h);if(ticket)p.setLong(3,now);
            try(ResultSet r=p.executeQuery()){return r.next()?r.getLong(1):-1;}
        }
    }
    private int attempts(String column,String value,long now)throws Exception{ // column is always one of two constants, never user input
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT COUNT(*) FROM reset_attempts WHERE "+column+"=? AND at_ms>?")){
            p.setString(1,value==null?"":value);p.setLong(2,now-ATTEMPT_WINDOW_MS);try(ResultSet r=p.executeQuery()){r.next();return r.getInt(1);}
        }
    }
    private void recordAttempt(String username,String ip,long now)throws Exception{
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("INSERT INTO reset_attempts(username,ip,at_ms) VALUES(?,?,?)")){p.setString(1,username);p.setString(2,ip==null?"":ip);p.setLong(3,now);p.executeUpdate();}
    }
    private void pruneAttempts(long now)throws Exception{
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("DELETE FROM reset_attempts WHERE at_ms<?")){p.setLong(1,now-24*3600_000L);p.executeUpdate();}
    }
    /** Text for the dashboard banner after a reset (null when there is nothing to show). */
    public String resetNotice(int uid)throws Exception{
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT reset_notice FROM users WHERE id=?")){
            p.setInt(1,uid);try(ResultSet r=p.executeQuery()){
                if(!r.next()||r.getString(1)==null)return null;
                String[] a=r.getString(1).split("\\|",2);
                return "Your password was reset on "+(a.length>1?fmtTime(a[1]):"an earlier date")+" using "+("ADMIN_TICKET".equals(a[0])?"an administrator reset ticket":"a recovery code")+". If this was not you, generate new recovery codes now and tell your administrator.";
            }
        }
    }
    public void dismissResetNotice(int uid)throws Exception{
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("UPDATE users SET reset_notice=NULL WHERE id=?")){p.setInt(1,uid);p.executeUpdate();}
    }
    public void changeTemporaryPassword(int uid,String newPassword)throws Exception{
        if(!mustChangePassword(uid))throw new SecurityException("No temporary password change is pending for this account.");
        if(newPassword==null||newPassword.length()<8)throw new IllegalArgumentException("New password must be at least 8 characters.");
        String salt=Security.newSalt();
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("UPDATE users SET password_hash=?,salt=?,must_change_password=0 WHERE id=?")){
            p.setString(1,Security.hash(newPassword,salt));p.setString(2,salt);p.setInt(3,uid);p.executeUpdate();
        }
        Db.log(uid,"PASSWORD_CHANGED","Temporary password changed by account owner");
    }
    public List<Map<String,Object>> files(int uid)throws Exception{
        List<Map<String,Object>> out=new ArrayList<>();
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT f.id,f.filename,f.version,length(f.content),f.updated_at FROM files f JOIN workspaces w ON w.id=f.workspace_id WHERE w.user_id=? AND f.deleted_at IS NULL ORDER BY f.filename")){
            p.setInt(1,uid);try(ResultSet r=p.executeQuery()){while(r.next()){Map<String,Object> m=new LinkedHashMap<>();m.put("id",r.getInt(1));m.put("filename",r.getString(2));m.put("version",r.getInt(3));m.put("bytes",r.getInt(4));m.put("updated",r.getString(5));out.add(m);}}
        }return out;
    }
    public int saveFile(int uid,String name,String content,int expectedVersion)throws Exception{
        if(name==null||!name.matches("[A-Za-z0-9._ -]{1,100}")||name.contains(".."))throw new IllegalArgumentException("Invalid filename.");
        long size=content.getBytes(StandardCharsets.UTF_8).length;
        try(Connection c=Db.open()){
            c.setAutoCommit(false);
            int ws;long quota,used;
            try(PreparedStatement p=c.prepareStatement("SELECT id,quota_bytes,used_bytes FROM workspaces WHERE user_id=?")){p.setInt(1,uid);try(ResultSet r=p.executeQuery()){if(!r.next())throw new SQLException("Workspace missing");ws=r.getInt(1);quota=r.getLong(2);used=r.getLong(3);}}
            int fid=-1,version=0,oldBytes=0;
            try(PreparedStatement p=c.prepareStatement("SELECT id,version,length(content) FROM files WHERE workspace_id=? AND filename=?")){p.setInt(1,ws);p.setString(2,name);try(ResultSet r=p.executeQuery()){if(r.next()){fid=r.getInt(1);version=r.getInt(2);oldBytes=r.getInt(3);}}}
            if(fid>0&&expectedVersion!=version)throw new ConcurrentModificationException("Version conflict. Current version is "+version+".");
            if(fid>0&&locks.writeBlocked(fid,uid))throw new IllegalStateException("Another user holds a lock on this file. Try again when they release it.");
            if(used-oldBytes+size>quota)throw new IllegalStateException("Storage quota exceeded ("+formatBytes(quota)+" limit for this workspace).");
            if(fid<0){
                try(PreparedStatement p=c.prepareStatement("INSERT INTO files(workspace_id,filename,content,version,updated_at) VALUES(?,?,?,1,?)")){p.setInt(1,ws);p.setString(2,name);p.setString(3,content);p.setString(4,Instant.now().toString());p.executeUpdate();}
                try(PreparedStatement p=c.prepareStatement("SELECT id FROM files WHERE workspace_id=? AND filename=?")){p.setInt(1,ws);p.setString(2,name);try(ResultSet r=p.executeQuery()){r.next();snapshot(c,r.getInt(1),1,content,uid);}}
            }else{
                try(PreparedStatement p=c.prepareStatement("UPDATE files SET content=?,version=version+1,updated_at=? WHERE id=? AND version=?")){p.setString(1,content);p.setString(2,Instant.now().toString());p.setInt(3,fid);p.setInt(4,expectedVersion);if(p.executeUpdate()!=1)throw new ConcurrentModificationException("Concurrent save conflict.");}
                snapshot(c,fid,expectedVersion+1,content,uid);
            }
            try(PreparedStatement p=c.prepareStatement("UPDATE workspaces SET used_bytes=? WHERE id=?")){p.setLong(1,used-oldBytes+size);p.setInt(2,ws);p.executeUpdate();}
            c.commit();
        }
        Db.log(uid,"FILE_SAVED",name+" ("+size+" bytes)");return 1;
    }
    // ===================== File access, sharing, quota =====================
    public record FileView(int id,String name,String content,int version,String access,String owner,int ownerId,long bytes){}
    public record Share(String username,String permission){}
    public record Usage(long used,long quota){}

    /** OWNER, WRITE, READ or null. Single source of truth for "may this user touch this file". */
    public String access(int uid,int fileId)throws Exception{
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT w.user_id FROM files f JOIN workspaces w ON w.id=f.workspace_id WHERE f.id=? AND f.deleted_at IS NULL")){
            p.setInt(1,fileId);try(ResultSet r=p.executeQuery()){if(!r.next())return null;if(r.getInt(1)==uid)return "OWNER";}
        }
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT permission FROM shares WHERE file_id=? AND shared_with_user_id=?")){
            p.setInt(1,fileId);p.setInt(2,uid);try(ResultSet r=p.executeQuery()){return r.next()?r.getString(1):null;}
        }
    }
    public FileView openFile(int uid,int fileId)throws Exception{
        String acc=access(uid,fileId);if(acc==null)throw new SecurityException(NO_ACCESS);
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT f.filename,f.content,f.version,u.username,u.id FROM files f JOIN workspaces w ON w.id=f.workspace_id JOIN users u ON u.id=w.user_id WHERE f.id=?")){
            p.setInt(1,fileId);try(ResultSet r=p.executeQuery()){
                if(!r.next())throw new SecurityException(NO_ACCESS);
                String content=r.getString(2);
                return new FileView(fileId,r.getString(1),content,r.getInt(3),acc,r.getString(4),r.getInt(5),content.getBytes(StandardCharsets.UTF_8).length);
            }
        }
    }
    /** Files other users shared with this user. */
    public List<Map<String,Object>> sharedWithMe(int uid)throws Exception{
        List<Map<String,Object>> out=new ArrayList<>();
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT f.id,f.filename,f.version,s.permission,u.username FROM shares s JOIN files f ON f.id=s.file_id JOIN users u ON u.id=s.owner_id WHERE s.shared_with_user_id=? ORDER BY f.filename")){
            p.setInt(1,uid);try(ResultSet r=p.executeQuery()){while(r.next()){Map<String,Object> m=new LinkedHashMap<>();m.put("id",r.getInt(1));m.put("filename",r.getString(2));m.put("version",r.getInt(3));m.put("permission",r.getString(4));m.put("owner",r.getString(5));out.add(m);}}
        }return out;
    }
    public List<Share> sharesOf(int uid,int fileId)throws Exception{
        if(!"OWNER".equals(access(uid,fileId)))throw new SecurityException("Only the owner can see or change sharing.");
        List<Share> out=new ArrayList<>();
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT u.username,s.permission FROM shares s JOIN users u ON u.id=s.shared_with_user_id WHERE s.file_id=? ORDER BY u.username")){
            p.setInt(1,fileId);try(ResultSet r=p.executeQuery()){while(r.next())out.add(new Share(r.getString(1),r.getString(2)));}
        }return out;
    }
    private int userId(String username)throws Exception{
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT id FROM users WHERE username=?")){
            p.setString(1,username==null?"":username.trim());try(ResultSet r=p.executeQuery()){return r.next()?r.getInt(1):-1;}
        }
    }
    public String usernameOf(int uid)throws Exception{
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT username FROM users WHERE id=?")){
            p.setInt(1,uid);try(ResultSet r=p.executeQuery()){return r.next()?r.getString(1):"user "+uid;}
        }
    }
    /** Owner grants (or changes) READ/WRITE access for one other user. Locks that no longer match the permission are dropped. */
    public void shareFile(int uid,int fileId,String username,String permission)throws Exception{
        if(!"OWNER".equals(access(uid,fileId)))throw new SecurityException("Only the owner can share this file.");
        if(!"READ".equals(permission)&&!"WRITE".equals(permission))throw new IllegalArgumentException("Permission must be READ or WRITE.");
        int target=userId(username);
        if(target<0)throw new IllegalArgumentException("No account found with that username.");
        if(target==uid)throw new IllegalArgumentException("This file is already yours.");
        try(Connection c=Db.open()){
            c.setAutoCommit(false);
            int n;
            try(PreparedStatement p=c.prepareStatement("UPDATE shares SET permission=? WHERE file_id=? AND shared_with_user_id=?")){p.setString(1,permission);p.setInt(2,fileId);p.setInt(3,target);n=p.executeUpdate();}
            if(n==0)try(PreparedStatement p=c.prepareStatement("INSERT INTO shares(file_id,owner_id,shared_with_user_id,permission) VALUES(?,?,?,?)")){p.setInt(1,fileId);p.setInt(2,uid);p.setInt(3,target);p.setString(4,permission);p.executeUpdate();}
            c.commit();
        }
        if("READ".equals(permission))locks.forget(fileId,target); // downgrade: a WRITE lock/wait must not survive
        Db.log(uid,"FILE_SHARED","File "+fileId+" shared with "+username.trim()+" ("+permission+")");
    }
    public void unshareFile(int uid,int fileId,String username)throws Exception{
        if(!"OWNER".equals(access(uid,fileId)))throw new SecurityException("Only the owner can change sharing.");
        int target=userId(username);
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("DELETE FROM shares WHERE file_id=? AND shared_with_user_id=?")){p.setInt(1,fileId);p.setInt(2,target);p.executeUpdate();}
        locks.forget(fileId,target);
        Db.log(uid,"FILE_UNSHARED","File "+fileId+" no longer shared with "+(username==null?"":username.trim()));
    }
    /** Edit a file by id: owner, or a user with WRITE permission. Quota is charged to the OWNER's workspace. */
    public void saveFileById(int uid,int fileId,String content,int expectedVersion)throws Exception{
        String acc=access(uid,fileId);
        if(acc==null)throw new SecurityException(NO_ACCESS);
        if(!"OWNER".equals(acc)&&!"WRITE".equals(acc))throw new SecurityException("You only have read access to this file.");
        if(content==null)content="";
        long size=content.getBytes(StandardCharsets.UTF_8).length;String name;
        try(Connection c=Db.open()){
            c.setAutoCommit(false);
            int ws,version,oldBytes;long quota,used;
            try(PreparedStatement p=c.prepareStatement("SELECT f.filename,f.version,length(f.content),w.id,w.quota_bytes,w.used_bytes FROM files f JOIN workspaces w ON w.id=f.workspace_id WHERE f.id=?")){
                p.setInt(1,fileId);try(ResultSet r=p.executeQuery()){if(!r.next())throw new SecurityException(NO_ACCESS);name=r.getString(1);version=r.getInt(2);oldBytes=r.getInt(3);ws=r.getInt(4);quota=r.getLong(5);used=r.getLong(6);}
            }
            if(expectedVersion!=version)throw new ConcurrentModificationException("Version conflict. Current version is "+version+". Reload the file and apply your change again.");
            if(locks.writeBlocked(fileId,uid))throw new IllegalStateException("Another user holds a lock on this file. Try again when they release it.");
            if(used-oldBytes+size>quota)throw new IllegalStateException("Storage quota exceeded ("+formatBytes(quota)+" limit for this workspace).");
            try(PreparedStatement p=c.prepareStatement("UPDATE files SET content=?,version=version+1,updated_at=? WHERE id=? AND version=?")){p.setString(1,content);p.setString(2,Instant.now().toString());p.setInt(3,fileId);p.setInt(4,expectedVersion);if(p.executeUpdate()!=1)throw new ConcurrentModificationException("Concurrent save conflict.");}
            snapshot(c,fileId,expectedVersion+1,content,uid);
            try(PreparedStatement p=c.prepareStatement("UPDATE workspaces SET used_bytes=? WHERE id=?")){p.setLong(1,used-oldBytes+size);p.setInt(2,ws);p.executeUpdate();}
            c.commit();
        }
        Db.log(uid,"FILE_SAVED",name+" ("+size+" bytes)"+("OWNER".equals(acc)?"":" [edited via share]"));
    }
    /** Stored times are UTC ISO strings; people see them in the computer's own time zone, e.g. "14 Nov 2026, 13:28:00 IST". */
    public static String fmtTime(String iso){
        if(iso==null)return "";
        try{return java.time.format.DateTimeFormatter.ofPattern("dd MMM yyyy, HH:mm:ss z",Locale.ENGLISH).format(Instant.parse(iso).atZone(java.time.ZoneId.systemDefault()));}
        catch(Exception e){return iso;}
    }
    public static String formatBytes(long b){return b>=1048576?String.format(Locale.ROOT,"%.1f MB",b/1048576.0):b>=1024?String.format(Locale.ROOT,"%.1f KB",b/1024.0):b+" B";}
    public Usage usage(int uid)throws Exception{
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT used_bytes,quota_bytes FROM workspaces WHERE user_id=?")){
            p.setInt(1,uid);try(ResultSet r=p.executeQuery()){return r.next()?new Usage(r.getLong(1),r.getLong(2)):new Usage(0,0);}
        }
    }
    /** Admin-only: change a user's storage quota. Cannot go below what the user already stores; bounds 10 KB..100 MB. */
    public void setQuota(int adminId,String username,long quotaKb)throws Exception{
        if(!"ADMIN".equals(role(adminId)))throw new SecurityException("Administrator access required.");
        int target=userId(username);if(target<0)throw new IllegalArgumentException("No account found with that username.");
        if(quotaKb<10||quotaKb>102400)throw new IllegalArgumentException("Quota must be between 10 KB and 102400 KB (100 MB).");
        long bytes=quotaKb*1024;
        try(Connection c=Db.open()){
            c.setAutoCommit(false);long used;
            try(PreparedStatement p=c.prepareStatement("SELECT used_bytes FROM workspaces WHERE user_id=?")){p.setInt(1,target);try(ResultSet r=p.executeQuery()){if(!r.next())throw new IllegalArgumentException("Workspace missing.");used=r.getLong(1);}}
            if(bytes<used)throw new IllegalArgumentException("That user already stores "+formatBytes(used)+". Choose a larger quota.");
            try(PreparedStatement p=c.prepareStatement("UPDATE workspaces SET quota_bytes=? WHERE user_id=?")){p.setLong(1,bytes);p.setInt(2,target);p.executeUpdate();}
            c.commit();
        }
        Db.log(adminId,"QUOTA_CHANGED","Quota of "+username.trim()+" set to "+formatBytes(bytes));
    }
    /** Admin overview: every user's storage use (sizes only, never file names or contents). */
    public List<Map<String,Object>> usageAll(int adminId)throws Exception{
        if(!"ADMIN".equals(role(adminId)))throw new SecurityException("Administrator access required.");
        List<Map<String,Object>> out=new ArrayList<>();
        try(Connection c=Db.open();Statement st=c.createStatement();ResultSet r=st.executeQuery("SELECT u.username,w.used_bytes,w.quota_bytes FROM workspaces w JOIN users u ON u.id=w.user_id ORDER BY u.username")){
            while(r.next()){Map<String,Object> m=new LinkedHashMap<>();m.put("username",r.getString(1));m.put("used",r.getLong(2));m.put("quota",r.getLong(3));out.add(m);}
        }return out;
    }
    // ===================== Version history =====================
    private static final int MAX_VERSIONS=20;
    public record Version(int version,String savedAt,String savedBy,int bytes){}
    private void snapshot(Connection c,int fileId,int version,String content,int uid)throws SQLException{
        try(PreparedStatement p=c.prepareStatement("INSERT INTO file_versions(file_id,version,content,saved_by,saved_at) VALUES(?,?,?,?,?)")){p.setInt(1,fileId);p.setInt(2,version);p.setString(3,content);p.setInt(4,uid);p.setString(5,Instant.now().toString());p.executeUpdate();}
        try(PreparedStatement p=c.prepareStatement("DELETE FROM file_versions WHERE file_id=? AND version<=?")){p.setInt(1,fileId);p.setInt(2,version-MAX_VERSIONS);p.executeUpdate();} // keep the newest 20
    }
    /** Newest first. Anyone with access to the file may read its history. */
    public List<Version> history(int uid,int fileId)throws Exception{
        if(access(uid,fileId)==null)throw new SecurityException(NO_ACCESS);
        List<Version> out=new ArrayList<>();
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT v.version,v.saved_at,COALESCE(u.username,'-'),length(v.content) FROM file_versions v LEFT JOIN users u ON u.id=v.saved_by WHERE v.file_id=? ORDER BY v.version DESC LIMIT ?")){
            p.setInt(1,fileId);p.setInt(2,MAX_VERSIONS);try(ResultSet r=p.executeQuery()){while(r.next())out.add(new Version(r.getInt(1),r.getString(2),r.getString(3),r.getInt(4)));}
        }return out;
    }
    public String versionContent(int uid,int fileId,int version)throws Exception{
        if(access(uid,fileId)==null)throw new SecurityException(NO_ACCESS);
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT content FROM file_versions WHERE file_id=? AND version=?")){
            p.setInt(1,fileId);p.setInt(2,version);try(ResultSet r=p.executeQuery()){if(!r.next())throw new IllegalArgumentException("That version no longer exists (only the newest "+MAX_VERSIONS+" are kept).");return r.getString(1);}
        }
    }
    /** Restoring never rewrites history: the old text is saved as a NEW version (same rules as a normal edit: needs WRITE, version check, locks, quota). */
    public void restoreVersion(int uid,int fileId,int version,int currentVersion)throws Exception{
        String old=versionContent(uid,fileId,version);
        saveFileById(uid,fileId,old,currentVersion);
        Db.log(uid,"FILE_VERSION_RESTORED","File "+fileId+": restored text of version "+version);
    }
    /** Line diff old -> new using LCS. ops: "=" same, "-" only in old, "+" only in new. Returns null when the files are too large to diff. */
    public static List<String[]> diff(String a,String b){
        String[] x=a.split("\n",-1),y=b.split("\n",-1);
        if(x.length>400||y.length>400)return null;
        int[][] l=new int[x.length+1][y.length+1];
        for(int i=x.length-1;i>=0;i--)for(int j=y.length-1;j>=0;j--)l[i][j]=x[i].equals(y[j])?l[i+1][j+1]+1:Math.max(l[i+1][j],l[i][j+1]);
        List<String[]> out=new ArrayList<>();int i=0,j=0;
        while(i<x.length&&j<y.length){
            if(x[i].equals(y[j])){out.add(new String[]{"=",x[i]});i++;j++;}
            else if(l[i+1][j]>=l[i][j+1]){out.add(new String[]{"-",x[i++]});}
            else{out.add(new String[]{"+",y[j++]});}
        }
        while(i<x.length)out.add(new String[]{"-",x[i++]});
        while(j<y.length)out.add(new String[]{"+",y[j++]});
        return out;
    }

    // ===================== Trash (soft delete) =====================
    /** Owner moves a file to the trash: it disappears for everyone else (shares and locks are removed) and stops using quota. */
    public void trashFile(int uid,int fileId)throws Exception{
        if(!"OWNER".equals(access(uid,fileId)))throw new SecurityException("Only the owner can delete this file.");
        if(locks.writeBlocked(fileId,uid))throw new IllegalStateException("Another user holds a lock on this file. Try again when they release it.");
        String name;
        try(Connection c=Db.open()){
            c.setAutoCommit(false);
            int ws;long used;int bytes;
            try(PreparedStatement p=c.prepareStatement("SELECT f.filename,length(f.content),w.id,w.used_bytes FROM files f JOIN workspaces w ON w.id=f.workspace_id WHERE f.id=? AND f.deleted_at IS NULL")){
                p.setInt(1,fileId);try(ResultSet r=p.executeQuery()){if(!r.next())throw new SecurityException(NO_ACCESS);name=r.getString(1);bytes=r.getInt(2);ws=r.getInt(3);used=r.getLong(4);}
            }
            // the visible name is parked so the same name can be created again; the original is kept in orig_name
            try(PreparedStatement p=c.prepareStatement("UPDATE files SET deleted_at=?,orig_name=filename,filename=filename||'~trash'||id WHERE id=?")){p.setString(1,Instant.now().toString());p.setInt(2,fileId);p.executeUpdate();}
            try(PreparedStatement p=c.prepareStatement("DELETE FROM shares WHERE file_id=?")){p.setInt(1,fileId);p.executeUpdate();}
            try(PreparedStatement p=c.prepareStatement("UPDATE workspaces SET used_bytes=? WHERE id=?")){p.setLong(1,Math.max(0,used-bytes));p.setInt(2,ws);p.executeUpdate();}
            c.commit();
        }
        locks.dropFile(fileId);
        Db.log(uid,"FILE_TRASHED",name+" moved to trash (sharing removed)");
    }
    public List<Map<String,Object>> trash(int uid)throws Exception{
        List<Map<String,Object>> out=new ArrayList<>();
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT f.id,f.orig_name,f.deleted_at,length(f.content),f.version FROM files f JOIN workspaces w ON w.id=f.workspace_id WHERE w.user_id=? AND f.deleted_at IS NOT NULL ORDER BY f.deleted_at DESC")){
            p.setInt(1,uid);try(ResultSet r=p.executeQuery()){while(r.next()){Map<String,Object> m=new LinkedHashMap<>();m.put("id",r.getInt(1));m.put("filename",r.getString(2));m.put("deleted",r.getString(3));m.put("bytes",r.getInt(4));m.put("version",r.getInt(5));out.add(m);}}
        }return out;
    }
    public void restoreFile(int uid,int fileId)throws Exception{
        String name;
        try(Connection c=Db.open()){
            c.setAutoCommit(false);
            int ws;long used,quota;int bytes;
            try(PreparedStatement p=c.prepareStatement("SELECT f.orig_name,length(f.content),w.id,w.used_bytes,w.quota_bytes FROM files f JOIN workspaces w ON w.id=f.workspace_id WHERE f.id=? AND w.user_id=? AND f.deleted_at IS NOT NULL")){
                p.setInt(1,fileId);p.setInt(2,uid);try(ResultSet r=p.executeQuery()){if(!r.next())throw new SecurityException(NO_ACCESS);name=r.getString(1);bytes=r.getInt(2);ws=r.getInt(3);used=r.getLong(4);quota=r.getLong(5);}
            }
            try(PreparedStatement p=c.prepareStatement("SELECT id FROM files WHERE workspace_id=? AND filename=? AND deleted_at IS NULL")){p.setInt(1,ws);p.setString(2,name);try(ResultSet r=p.executeQuery()){if(r.next())throw new IllegalStateException("You already have a file named "+name+". Rename or delete that one first.");}}
            if(used+bytes>quota)throw new IllegalStateException("Restoring needs "+formatBytes(bytes)+" but your quota is full. Free some space first.");
            try(PreparedStatement p=c.prepareStatement("UPDATE files SET filename=?,deleted_at=NULL,orig_name=NULL WHERE id=?")){p.setString(1,name);p.setInt(2,fileId);p.executeUpdate();}
            try(PreparedStatement p=c.prepareStatement("UPDATE workspaces SET used_bytes=? WHERE id=?")){p.setLong(1,used+bytes);p.setInt(2,ws);p.executeUpdate();}
            c.commit();
        }
        Db.log(uid,"FILE_RESTORED",name+" restored from trash (it is private again; share it again if needed)");
    }
    /** Delete forever (also removes its version history). Only works for files already in the trash. */
    public void purgeFile(int uid,int fileId)throws Exception{
        String name;
        try(Connection c=Db.open()){
            c.setAutoCommit(false);
            try(PreparedStatement p=c.prepareStatement("SELECT f.orig_name FROM files f JOIN workspaces w ON w.id=f.workspace_id WHERE f.id=? AND w.user_id=? AND f.deleted_at IS NOT NULL")){
                p.setInt(1,fileId);p.setInt(2,uid);try(ResultSet r=p.executeQuery()){if(!r.next())throw new SecurityException(NO_ACCESS);name=r.getString(1);}
            }
            try(PreparedStatement p=c.prepareStatement("DELETE FROM file_versions WHERE file_id=?")){p.setInt(1,fileId);p.executeUpdate();}
            try(PreparedStatement p=c.prepareStatement("DELETE FROM files WHERE id=? AND deleted_at IS NOT NULL")){p.setInt(1,fileId);p.executeUpdate();}
            c.commit();
        }
        Db.log(uid,"FILE_PURGED",name+" deleted permanently");
    }

    // ===================== Session management =====================
    public record SessionRow(String id,String username,String ip,String created,String lastSeen,String expires,boolean active,boolean current){}
    /** The user's own sessions, active ones first. */
    public List<SessionRow> mySessions(int uid,String currentToken)throws Exception{
        List<SessionRow> out=new ArrayList<>();String now=Instant.now().toString();
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT id,COALESCE(ip_address,''),created_at,last_seen,expires_at,active,token FROM sessions WHERE user_id=? ORDER BY active DESC,last_seen DESC LIMIT ?")){
            p.setInt(1,uid);p.setInt(2,25);
            try(ResultSet r=p.executeQuery()){while(r.next()){boolean act=r.getInt(6)==1&&r.getString(5).compareTo(now)>0;out.add(new SessionRow(r.getString(1),null,r.getString(2),r.getString(3),r.getString(4),r.getString(5),act,r.getString(7).equals(currentToken)));}}
        }return out;
    }
    public void revokeSession(int uid,String sessionId,String currentToken)throws Exception{
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT token FROM sessions WHERE id=? AND user_id=?")){
            p.setString(1,sessionId==null?"":sessionId);p.setInt(2,uid);
            try(ResultSet r=p.executeQuery()){if(!r.next())throw new SecurityException("Session not found.");if(r.getString(1).equals(currentToken))throw new IllegalArgumentException("That is the session you are using now. Use Logout instead.");}
        }
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("UPDATE sessions SET active=0 WHERE id=? AND user_id=?")){p.setString(1,sessionId);p.setInt(2,uid);p.executeUpdate();}
        Db.log(uid,"SESSION_REVOKED","Session signed out from the sessions page");
    }
    /** "Sign out everywhere else": every active session except the current one. */
    public int revokeOtherSessions(int uid,String currentToken)throws Exception{
        int n;
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("UPDATE sessions SET active=0 WHERE user_id=? AND active=1 AND token<>?")){p.setInt(1,uid);p.setString(2,currentToken==null?"":currentToken);n=p.executeUpdate();}
        Db.log(uid,"SESSIONS_REVOKED",n+" other session(s) signed out");return n;
    }
    /** Admin overview of every active session (metadata only: who, from where, since when). */
    public List<SessionRow> activeSessions(int adminId)throws Exception{
        if(!"ADMIN".equals(role(adminId)))throw new SecurityException("Administrator access required.");
        List<SessionRow> out=new ArrayList<>();
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT s.id,u.username,COALESCE(s.ip_address,''),s.created_at,s.last_seen,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.active=1 AND s.expires_at>? ORDER BY s.last_seen DESC LIMIT ?")){
            p.setString(1,Instant.now().toString());p.setInt(2,100);
            try(ResultSet r=p.executeQuery()){while(r.next())out.add(new SessionRow(r.getString(1),r.getString(2),r.getString(3),r.getString(4),r.getString(5),r.getString(6),true,false));}
        }return out;
    }
    public void adminTerminateSession(int adminId,String sessionId)throws Exception{
        if(!"ADMIN".equals(role(adminId)))throw new SecurityException("Administrator access required.");
        int target=-1;String name="";
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT s.user_id,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=?")){
            p.setString(1,sessionId==null?"":sessionId);try(ResultSet r=p.executeQuery()){if(r.next()){target=r.getInt(1);name=r.getString(2);}}
        }
        if(target<0)throw new IllegalArgumentException("Session not found.");
        try(Connection c=Db.open()){
            try(PreparedStatement p=c.prepareStatement("UPDATE sessions SET active=0 WHERE id=?")){p.setString(1,sessionId);p.executeUpdate();}
            try(PreparedStatement p=c.prepareStatement("SELECT COUNT(*) FROM sessions WHERE user_id=? AND active=1 AND expires_at>?")){p.setInt(1,target);p.setString(2,Instant.now().toString());try(ResultSet r=p.executeQuery()){r.next();if(r.getInt(1)==0)locks.releaseUser(target);}} // last session gone -> its locks go too
        }
        Db.log(adminId,"SESSION_TERMINATED","Administrator ended a session of "+name);
        Db.log(target,"SESSION_TERMINATED_BY_ADMIN","An administrator ended one of your sessions");
    }

    // ===================== Admin analytics =====================
    public record Day(String date,int logins,int failed){}
    public record Analytics(int users,int activeSessions,int files,int trashed,long storageUsed,long storageQuota,int locksHeld,int locksWaiting,List<Day> days,List<Map.Entry<String,Integer>> events24h,String recentSecurity){}
    /** Counts and trends only. No file names and no file contents are ever read here. */
    public Analytics analytics(int adminId)throws Exception{
        if(!"ADMIN".equals(role(adminId)))throw new SecurityException("Administrator access required.");
        String nowIso=Instant.now().toString();
        int users,active,files,trashed;long used,quota;
        try(Connection c=Db.open();Statement st=c.createStatement()){
            try(ResultSet r=st.executeQuery("SELECT COUNT(*) FROM users")){r.next();users=r.getInt(1);}
            try(PreparedStatement p=c.prepareStatement("SELECT COUNT(*) FROM sessions WHERE active=1 AND expires_at>?")){p.setString(1,nowIso);try(ResultSet r=p.executeQuery()){r.next();active=r.getInt(1);}}
            try(ResultSet r=st.executeQuery("SELECT COUNT(*) FROM files WHERE deleted_at IS NULL")){r.next();files=r.getInt(1);}
            try(ResultSet r=st.executeQuery("SELECT COUNT(*) FROM files WHERE deleted_at IS NOT NULL")){r.next();trashed=r.getInt(1);}
            try(ResultSet r=st.executeQuery("SELECT COALESCE(SUM(used_bytes),0),COALESCE(SUM(quota_bytes),0) FROM workspaces")){r.next();used=r.getLong(1);quota=r.getLong(2);}
        }
        // last 7 days (UTC), oldest first
        java.time.LocalDate today=java.time.LocalDate.now(java.time.ZoneOffset.UTC);
        Map<String,int[]> byDay=new LinkedHashMap<>();for(int i=6;i>=0;i--)byDay.put(today.minusDays(i).toString(),new int[2]);
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT substr(timestamp,1,10),action_type,COUNT(*) FROM activity_logs WHERE timestamp>=? AND action_type IN ('LOGIN','LOGIN_FAILED','LOGIN_THROTTLED') GROUP BY substr(timestamp,1,10),action_type")){
            p.setString(1,today.minusDays(6).toString());
            try(ResultSet r=p.executeQuery()){while(r.next()){int[] a=byDay.get(r.getString(1));if(a==null)continue;if("LOGIN".equals(r.getString(2)))a[0]+=r.getInt(3);else a[1]+=r.getInt(3);}}
        }
        List<Day> days=new ArrayList<>();byDay.forEach((d,a)->days.add(new Day(d,a[0],a[1])));
        List<Map.Entry<String,Integer>> ev=new ArrayList<>();
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT action_type,COUNT(*) FROM activity_logs WHERE timestamp>=? GROUP BY action_type ORDER BY 2 DESC")){
            p.setString(1,Instant.now().minusSeconds(86400).toString());
            try(ResultSet r=p.executeQuery()){while(r.next()&&ev.size()<10)ev.add(Map.entry(r.getString(1),r.getInt(2)));}
        }
        StringBuilder sec=new StringBuilder();
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT l.timestamp,COALESCE(u.username,'-'),l.action_type,COALESCE(l.description,'') FROM activity_logs l LEFT JOIN users u ON u.id=l.user_id WHERE l.action_type IN ('LOGIN_FAILED','LOGIN_THROTTLED','PASSWORD_RESET','PASSWORD_RESET_FAILED','RESET_TICKET_ISSUED','DEADLOCK_RESOLVED','SESSION_TERMINATED','QUOTA_CHANGED') ORDER BY l.id DESC LIMIT ?")){
            p.setInt(1,15);try(ResultSet r=p.executeQuery()){while(r.next())sec.append(fmtTime(r.getString(1))).append(" | ").append(r.getString(2)).append(" | ").append(r.getString(3)).append(" | ").append(r.getString(4)).append("\n");}
        }
        return new Analytics(users,active,files,trashed,used,quota,locks.heldList().size(),locks.waitingList().size(),days,ev,sec.toString());
    }
    public String adminSummary()throws Exception{
        try(Connection c=Db.open();Statement s=c.createStatement();ResultSet r=s.executeQuery("SELECT (SELECT COUNT(*) FROM users),(SELECT COUNT(*) FROM sessions WHERE active=1),(SELECT COALESCE(SUM(used_bytes),0) FROM workspaces)")){
            r.next();return "Users: "+r.getInt(1)+"\nActive sessions: "+r.getInt(2)+"\nStorage used: "+r.getLong(3)+" bytes";
        }
    }
    public String logs(int uid,int limit)throws Exception{
        boolean admin="ADMIN".equals(role(uid));
        StringBuilder b=new StringBuilder();
        // A normal user only sees their own events (including failed reset attempts on their account); the administrator sees all.
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("SELECT l.timestamp,COALESCE(u.username,'SYSTEM'),l.action_type,COALESCE(l.description,'') FROM activity_logs l LEFT JOIN users u ON u.id=l.user_id "+(admin?"":"WHERE l.user_id=? ")+"ORDER BY l.id DESC LIMIT ?")){
            int i=1;if(!admin)p.setInt(i++,uid);p.setInt(i,limit);
            try(ResultSet r=p.executeQuery()){while(r.next())b.append(fmtTime(r.getString(1))).append(" | ").append(r.getString(2)).append(" | ").append(r.getString(3)).append(" | ").append(r.getString(4)).append("\n");}
        }return b.toString();
    }
    public void reapExpiredSessions()throws Exception{
        try(Connection c=Db.open();PreparedStatement p=c.prepareStatement("UPDATE sessions SET active=0 WHERE active=1 AND expires_at<?")){p.setString(1,Instant.now().toString());int n=p.executeUpdate();if(n>0)Db.log(null,"SESSION_REAPER","Expired sessions: "+n);}
    }
    /** A user may only lock files they own or that were shared with them (READ lock needs read access, WRITE lock needs write access). */
    public String acquireLock(int file,int user,String type)throws Exception{
        String acc=access(user,file);
        if(acc==null)throw new SecurityException(NO_ACCESS);
        if("WRITE".equalsIgnoreCase(type)&&"READ".equals(acc))throw new SecurityException("You only have read access to this file, so you cannot take a write lock.");
        return locks.acquire(file,user,type);
    }
    public void releaseLock(int file,int user){locks.release(file,user);}
    /** Admin sees every lock with user NAMES (file ids only, never file names); normal users see only their own. */
    public String lockSnapshot(int uid)throws Exception{
        if(!"ADMIN".equals(role(uid)))return locks.snapshotFor(uid);
        StringBuilder b=new StringBuilder();
        for(LockManager.Held h:locks.heldList())b.append("HOLD  file ").append(h.fileId()).append(" · ").append(usernameOf(h.userId())).append(" · ").append(h.type()).append("\n");
        for(LockManager.Waiting w:locks.waitingList())b.append("WAIT  file ").append(w.fileId()).append(" · ").append(usernameOf(w.userId())).append(" · ").append(w.type()).append("\n");
        return b.length()==0?"No locks held.\n":b.toString();
    }
    public LockManager locks(){return locks;}
    /** Detector status for the admin screen: UTC timestamps become local time and user ids become user names. */
    public String detectorStatus()throws Exception{
        String t=locks.lastDetection();
        java.util.regex.Matcher m=java.util.regex.Pattern.compile("\\d{4}-\\d\\d-\\d\\dT[\\d:.]+Z").matcher(t);
        StringBuilder out=new StringBuilder();
        while(m.find())m.appendReplacement(out,java.util.regex.Matcher.quoteReplacement(fmtTime(m.group())));
        m.appendTail(out);t=out.toString();
        m=java.util.regex.Pattern.compile("cycle \\[([\\d, ]+)\\]").matcher(t);
        if(m.find()){List<String> names=new ArrayList<>();for(String id:m.group(1).split(",\\s*"))names.add(usernameOf(Integer.parseInt(id.trim())));t=t.substring(0,m.start())+"cycle "+String.join(" <-> ",names)+t.substring(m.end());}
        m=java.util.regex.Pattern.compile("victim user (\\d+)").matcher(t);
        if(m.find())t=t.substring(0,m.start())+"victim "+usernameOf(Integer.parseInt(m.group(1)))+t.substring(m.end());
        return t;
    }
}
