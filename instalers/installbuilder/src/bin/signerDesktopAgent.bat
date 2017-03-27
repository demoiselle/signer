@echo off


set SIGNER_DESKTOP_HOME=%~dp0
if exist "%SIGNER_DESKTOP_HOME%..\java\bin" goto SET_BUNDLED_JAVA

rem  %SIGNER_DESKTOP_HOME%
if exist "%JAVA_HOME%" goto SET_SYSTEM_JAVA

echo JAVA_HOME nao esta setado, erros inexperados podem ocorrer.
echo Set JAVA_HOME corretamente para evitar erros.
goto SET_SYSTEM_JAVA

:SET_BUNDLED_JAVA
rem bundle
set JAVA=%SIGNER_DESKTOP_HOME%..\java\bin\java
goto END_SETTING_JAVA

:SET_SYSTEM_JAVA
set JAVA=java

:END_SETTING_JAVA


rem parametros da JVM 

set JAVA_OPTS=-Xms128m -Xmx1024m -XX:MinHeapFreeRatio=20 -XX:MaxHeapFreeRatio=40

rem ********* executando signer desktop ***********

"%JAVA%" %JAVA_OPTS% -jar "%SIGNER_DESKTOP_HOME%lib\agent-desktop-3.0.0-SNAPSHOT.jar"
