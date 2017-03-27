Set oShell = CreateObject ("Wscript.Shell") 
Dim strArgs
strArgs = "cmd /c signerDesktopAgent.bat"
oShell.Run strArgs, 0, false
