@echo off 
echo Installation AV-Shield Windows... 
pip install flask flask-cors google-genai watchdog requests 
echo Telechargement signatures ClamAV... 
"C:\Program Files\ClamAV\freshclam.exe" 
echo Copie signatures dans le projet... 
xcopy "C:\Program Files\ClamAV\database" "%~dp0database\" /E /I /Y 
xcopy "C:\Program Files\ClamAV\certs" "%~dp0certs\" /E /I /Y 
echo Installation terminee ! 
pause 
