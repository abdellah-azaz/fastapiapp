@echo off 
echo Demarrage AV-Shield... 
start "Monitor" python web\realtime_monitor.py 
timeout /t 2 
start "Flask" python web\app.py 
timeout /t 3 
start http://localhost:5000 
echo AV-Shield demarre ! Ouvrez http://localhost:5000 
pause 
