@echo off
java -cp "h2-*.jar;%H2DRIVERS%;%CLASSPATH%" org.h2.tools.Server -pg -pgAllowOthers -key %1 "./%1;CIPHER=AES;MODE=PostgreSQL;" & echo %! > h2db.pid