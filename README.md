Secure Workspace

Secure Workspace with File Isolation, Resource Allocation & Session Tracking

A multi-user workspace system written in Java for Windows. Every user gets a private workspace, and the operating-system ideas behind safely sharing one computer (access control, locking, deadlock detection, resource limits, session handling) are implemented in a real, working application. This is not a simulation.

Team techRAAH · Graphic Era Hill University · B.Tech CSE (OS + DBMS project)

Features

File isolation and sharing

Private workspace per user; one permission check (OWNER / WRITE / READ) guards every file action
Share a file as Read only or Can edit; the owner can change or remove access at any time
The administrator cannot open other users' files (the admin sees only sizes and counts)

Concurrency and resource allocation

READ (shared) and WRITE (exclusive) locks with a wait queue
Deadlock detection: wait-for graph + DFS cycle detection every 3 seconds, one victim is released, live graph on the admin dashboard
Version-checked saves inside transactions, so two users cannot silently overwrite each other
Admin-controlled storage quota per user with a usage bar
OS worker process launched with ProcessBuilder

Sessions, logs and analytics

30-minute session timeout, background cleanup thread, sessions page with sign-out-everywhere, admin can end sessions
Audit log of every action (users see their own, the admin sees all)
Admin analytics: counts, sign-in vs failed-login chart, storage per user (never file names or contents)

Accounts and recovery

PBKDF2-HMAC-SHA256 password hashing (150,000 iterations), login brute-force throttling
Forgot password with one-time recovery codes, or an admin-issued one-time reset ticket; the user always chooses the new password, so the admin never sees or sets one

Files

Version history with line-by-line diff and restore
Trash with restore and delete-forever
Tech stack

Java 17 · built-in JDK HttpServer · server-rendered HTML · SQLite via sqlite-jdbc (with slf4j). No other framework.

How to run (Windows)
Install JDK 17 or newer (java -version should show 17+).
Download or clone this repository (the lib folder already contains the three required jars).
Open a Command Prompt in the project folder and run build.bat.
Run run.bat, then open http://localhost:8090.
The first account you register becomes the administrator. Save the recovery codes shown at registration.

The database (data/) and user workspaces (workspaces/) are created automatically on first run.

Project structure
src/com/secureworkspace/
  Main.java         start-up, background threads
  WebServer.java    HTTP routes and pages
  Services.java     business rules and SQL transactions
  LockManager.java  locks and deadlock detector
  Security.java     password hashing and one-time secrets
  Db.java           schema and migrations
lib/                sqlite-jdbc, slf4j-api, slf4j-nop
CHANGES.md          detailed feature notes
