
package com.secureworkspace;
import java.sql.*;
import java.nio.file.*;

public final class Db {
    private static final String URL = "jdbc:sqlite:data/secure_workspace.db";
    private Db() {}
    public static Connection open() throws SQLException {
        Connection c = DriverManager.getConnection(URL);
        try (Statement s = c.createStatement()) {
            s.execute("PRAGMA foreign_keys=ON");
            s.execute("PRAGMA busy_timeout=5000");
        }
        return c;
    }
    public static void init() throws Exception {
        Files.createDirectories(Path.of("data"));
        Files.createDirectories(Path.of("workspaces"));
        Class.forName("org.sqlite.JDBC");
        try (Connection c = open(); Statement s = c.createStatement()) {
            s.execute("PRAGMA journal_mode=WAL");
            s.executeUpdate("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'USER', must_change_password INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)");
            // Backward-compatible migration for databases created by earlier project versions.
            try { s.executeUpdate("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"); } catch (SQLException ignored) {}
            // Password-reset feature: remembers "VIA|timestamp" of the last reset so the user is told about it at next login.
            try { s.executeUpdate("ALTER TABLE users ADD COLUMN reset_notice TEXT"); } catch (SQLException ignored) {}
            try (ResultSet admins = s.executeQuery("SELECT COUNT(*) FROM users WHERE role='ADMIN'")) {
                if (admins.next() && admins.getInt(1) == 0) {
                    s.executeUpdate("UPDATE users SET role='ADMIN' WHERE id=(SELECT MIN(id) FROM users)");
                }
            }
            s.executeUpdate("CREATE TABLE IF NOT EXISTS workspaces(id INTEGER PRIMARY KEY, user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE, quota_bytes INTEGER NOT NULL DEFAULT 5242880, used_bytes INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)");
            s.executeUpdate("CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE, filename TEXT NOT NULL, content TEXT NOT NULL DEFAULT '', version INTEGER NOT NULL DEFAULT 1, locked_by_user_id INTEGER REFERENCES users(id), updated_at TEXT NOT NULL, UNIQUE(workspace_id,filename))");
            s.executeUpdate("CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, token TEXT UNIQUE NOT NULL, ip_address TEXT, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, last_seen TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1)");
            s.executeUpdate("CREATE TABLE IF NOT EXISTS file_locks(id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, lock_type TEXT NOT NULL CHECK(lock_type IN ('READ','WRITE')), acquired_at TEXT NOT NULL, UNIQUE(file_id,user_id))");
            // Trash (soft delete) + version history. Columns are added by ALTER so databases from older versions upgrade in place.
            try { s.executeUpdate("ALTER TABLE files ADD COLUMN deleted_at TEXT"); } catch (SQLException ignored) {}
            try { s.executeUpdate("ALTER TABLE files ADD COLUMN orig_name TEXT"); } catch (SQLException ignored) {}
            s.executeUpdate("CREATE TABLE IF NOT EXISTS file_versions(id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE, version INTEGER NOT NULL, content TEXT NOT NULL, saved_by INTEGER REFERENCES users(id), saved_at TEXT NOT NULL, UNIQUE(file_id,version))");
            s.executeUpdate("CREATE TABLE IF NOT EXISTS activity_logs(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), action_type TEXT NOT NULL, description TEXT, timestamp TEXT NOT NULL)");
            s.executeUpdate("CREATE TABLE IF NOT EXISTS shares(id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE, owner_id INTEGER NOT NULL REFERENCES users(id), shared_with_user_id INTEGER NOT NULL REFERENCES users(id), permission TEXT NOT NULL CHECK(permission IN ('READ','WRITE')), UNIQUE(file_id,shared_with_user_id))");
            s.executeUpdate("CREATE INDEX IF NOT EXISTS ix_sessions_active ON sessions(active,expires_at)");
            s.executeUpdate("CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions(user_id,active)");
            s.executeUpdate("CREATE INDEX IF NOT EXISTS ix_logs_time ON activity_logs(timestamp)");
            // Account recovery. Only SHA-256 hashes of the secrets are stored, never the codes/tickets themselves.
            s.executeUpdate("CREATE TABLE IF NOT EXISTS recovery_codes(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, code_hash TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, used_at TEXT)");
            s.executeUpdate("CREATE TABLE IF NOT EXISTS reset_tickets(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash TEXT UNIQUE NOT NULL, created_by INTEGER NOT NULL REFERENCES users(id), created_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL, used_at TEXT)");
            s.executeUpdate("CREATE TABLE IF NOT EXISTS reset_attempts(id INTEGER PRIMARY KEY, username TEXT NOT NULL, ip TEXT, at_ms INTEGER NOT NULL)");
            s.executeUpdate("CREATE INDEX IF NOT EXISTS ix_reset_attempts_user ON reset_attempts(username,at_ms)");
            s.executeUpdate("CREATE INDEX IF NOT EXISTS ix_reset_attempts_ip ON reset_attempts(ip,at_ms)");
            // Login brute-force throttling (same shape as reset_attempts; failed sign-ins only).
            s.executeUpdate("CREATE TABLE IF NOT EXISTS login_attempts(id INTEGER PRIMARY KEY, username TEXT NOT NULL, ip TEXT, at_ms INTEGER NOT NULL)");
            s.executeUpdate("CREATE INDEX IF NOT EXISTS ix_login_attempts_user ON login_attempts(username,at_ms)");
            s.executeUpdate("CREATE INDEX IF NOT EXISTS ix_login_attempts_ip ON login_attempts(ip,at_ms)");
        }
    }
    public static void log(Integer uid, String action, String description) {
        try (Connection c=open(); PreparedStatement p=c.prepareStatement("INSERT INTO activity_logs(user_id,action_type,description,timestamp) VALUES(?,?,?,?)")) {
            if (uid == null) p.setNull(1, Types.INTEGER); else p.setInt(1, uid);
            p.setString(2, action); p.setString(3, description); p.setString(4, java.time.Instant.now().toString()); p.executeUpdate();
        } catch (Exception e) { e.printStackTrace(); }
    }
}
