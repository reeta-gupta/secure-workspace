# Secure Workspace - what is new in this version

## 1. Forgot password (admin never sees or sets a password)
- 8 one-time recovery codes at registration (shown once). "Forgot password?" on the login page.
- No codes left: admin issues a one-time reset ticket (15 min, single use); the USER chooses the new password.
- Rate limited, hashed secrets, all sessions killed after reset, notice banner at next login, full audit trail.
- Existing users have no codes: dashboard -> "Generate new recovery codes" once.

## 2. Security fixes
- Login brute-force throttling: 5 failed tries per user+IP, 25 per user, 30 per IP in 15 minutes (then blocked, even with the right password).
- /lock now checks ownership: you can only lock files you own or that were shared with you (READ lock needs read access, WRITE lock needs write access).
- Saving a file is blocked while another user holds a lock on it.
- Fixed literal "\n" bug in lock snapshot / admin summary.
- Normal users only see their own lock activity; only the admin sees the global graph.

## 3. Deadlock wait-for graph (admin dashboard)
- Live graph: arrow A -> B = A waits for a lock B holds. Last resolved deadlock is drawn with the cycle in red + victim name.
- Fixed a detector bug: a user who only waits on a cycle (but is not in it) could be picked as victim. Now the victim is always inside the cycle.
- Demo: alice locks a.txt, bob locks b.txt (each shared with the other as "Can edit"), then each requests the other's file -> within 3 s the detector resolves it.

## 4. File sharing with permissions
- Open any file -> share with a user as "Read only" or "Can edit". Owner can change/remove access any time.
- "Shared with me" table. Lock buttons + editor on the file page. Version check (optimistic concurrency) on every save.
- Admin has NO access to other users' files (only sizes in the quota table).

## 5. Resource allocation: storage quota
- Real usage bar on the dashboard. Admin can set a quota per user (10 KB - 100 MB, never below what is already stored).
- Edits by a shared writer are charged to the file OWNER's quota.

## 6. Sessions page (/sessions)
- See every session (IP, sign-in time, last activity), sign out one, or "Sign out all other sessions".
- Admin: Analytics page lists all active sessions (metadata only) and can end one; the user sees that in their own log.

## 7. Trash + restore
- Owner deletes a file -> trash. Sharing and locks are removed, it stops using quota, the name can be reused.
- Restore (checks name clash + quota; file comes back private) or Delete forever.

## 8. Version history (/history)
- Every save keeps a version (who, when, size). Newest 20 are kept. Line-by-line diff against the current text.
- Restore saves the old text as a NEW version (history is never rewritten). Needs write access.

## 9. Admin analytics (/admin)
- KPIs, 7-day sign-in vs failed-login chart, top events in 24 h, storage per user, active sessions, recent security events.
- Counts only: no file names or contents.

## Testing done (honest summary)
- 53 + 59 + 60 end-to-end HTTP checks and 13 LockManager unit checks pass; all 83 SQL statements validated on real SQLite.
- The end-to-end runs used a Derby stand-in database, NOT sqlite-jdbc (not available in my environment).
  Please do one quick manual run on your machine (register, share a file, try a deadlock).

## Not done (ideas for later)
- CSRF tokens, normal change-password page, audit-log search/CSV export, live (auto-refresh) graph.
