@echo off
REM Needs JDK 17+ and a sqlite-jdbc jar in the lib folder.
if not exist lib\sqlite-jdbc*.jar (
  echo ERROR: lib\sqlite-jdbc-*.jar not found. Read lib\PUT_SQLITE_JAR_HERE.txt
  exit /b 1
)
if not exist out mkdir out
dir /s /b src\*.java > sources.txt
javac --release 17 -cp "lib\*" -d out @sources.txt
del sources.txt
echo Build finished.
