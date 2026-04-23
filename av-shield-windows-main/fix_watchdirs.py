import os

path = 'web/realtime_monitor.py'
content = open(path, 'r', encoding='utf-8').read()

old = """if platform.system() == "Windows":
    WATCH_DIRS   = [
        os.path.join(os.path.expanduser("~"), "Downloads"),
        os.path.join(os.path.expanduser("~"), "Desktop"),
        "C:\\\\Temp"
    ]"""

new = """if platform.system() == "Windows":
    WATCH_DIRS   = [
        os.path.join(os.path.expanduser("~"), "Downloads"),
        os.path.join(os.path.expanduser("~"), "Desktop"),
        os.path.join(os.path.expanduser("~"), "Documents"),
        os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp"),
        "C:\\\\Temp"
    ]"""

if old in content:
    content = content.replace(old, new)
    print("realtime_monitor.py corrige !")
else:
    print("Pattern non trouve!")
    idx = content.find('WATCH_DIRS')
    print(repr(content[idx:idx+300]))

open(path, 'w', encoding='utf-8').write(content)
