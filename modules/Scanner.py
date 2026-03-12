import os
import json
import datetime
import platform
import ctypes
import winreg
import subprocess
import socket
import concurrent.futures
import urllib.request

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

try:
    import wmi
    WMI_OK = True
except ImportError:
    WMI_OK = False


def powershell(commande):
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", commande],
            capture_output=True, text=True, timeout=20
        )
        return r.stdout.strip()
    except Exception:
        return ""


def registre_lire(hive, chemin, cle):
    try:
        k = winreg.OpenKey(hive, chemin)
        valeur, _ = winreg.QueryValueEx(k, cle)
        winreg.CloseKey(k)
        return valeur
    except Exception:
        return None


def est_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def collecter_systeme():
    print("  -> [1/8] Informations systeme...")
    hostname        = os.environ.get("COMPUTERNAME", "inconnu")
    username        = os.environ.get("USERNAME", "inconnu")
    windows_version = platform.release()
    windows_build   = platform.version()
    architecture    = platform.machine()

    patches_raw = powershell(
        "Get-HotFix | Select-Object -ExpandProperty InstalledOn | Sort-Object"
    )
    patches = [p.strip() for p in patches_raw.splitlines() if p.strip()]

    ram_total = 0
    cpu_count = 0
    if PSUTIL_OK:
        ram_total = round(psutil.virtual_memory().total / (1024**3), 1)
        cpu_count = psutil.cpu_count()

    print(f"     OK {hostname} - Windows {windows_version}")
    return {
        "hostname":         hostname,
        "username":         username,
        "windows_version":  windows_version,
        "windows_build":    windows_build,
        "architecture":     architecture,
        "ram_gb":           ram_total,
        "cpu_cores":        cpu_count,
        "nombre_patches":   len(patches),
        "derniers_patches": patches[-3:],
        "est_admin":        est_admin(),
    }


def collecter_comptes():
    print("  -> [2/8] Comptes utilisateurs...")

    users_json = powershell(
        "Get-LocalUser | Select-Object Name, Enabled, PasswordExpires | ConvertTo-Json -Compress"
    )
    utilisateurs = []
    try:
        data = json.loads(users_json)
        if isinstance(data, dict):
            data = [data]
        for u in data:
            utilisateurs.append({
                "nom":               u.get("Name", ""),
                "actif":             u.get("Enabled", False),
                "mdp_expire_jamais": u.get("PasswordExpires") is None,
            })
    except Exception:
        pass

    admins_raw = powershell(
        "Get-LocalGroupMember -SID 'S-1-5-32-544' | Select-Object -ExpandProperty Name"
    )
    admins = [a.strip() for a in admins_raw.splitlines() if a.strip()]

    longueur_min = registre_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "MinimumPasswordLength"
    ) or 0

    print(f"     OK {len(utilisateurs)} user(s) - {len(admins)} admin(s)")
    return {
        "nombre_utilisateurs": len(utilisateurs),
        "utilisateurs":        utilisateurs,
        "administrateurs":     admins,
        "nombre_admins":       len(admins),
        "politique_mdp": {
            "longueur_minimale": longueur_min
        },
    }


def collecter_reseau():
    print("  -> [3/8] Reseau interne...")

    ports_ouverts = []
    if PSUTIL_OK:
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status == "LISTEN":
                    port = conn.laddr.port
                    if port not in ports_ouverts:
                        ports_ouverts.append(port)
        except Exception:
            pass

    smb1 = registre_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "SMB1"
    )
    rdp = registre_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections"
    )

    fw_raw = powershell(
        "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress"
    )
    parefeu_desactive = "false" in fw_raw.lower()

    partages_raw = powershell(
        "Get-SmbShare | Select-Object Name, Path | ConvertTo-Json -Compress"
    )
    partages = []
    try:
        data = json.loads(partages_raw)
        if isinstance(data, dict):
            data = [data]
        for p in data:
            partages.append({
                "nom":    p.get("Name", ""),
                "chemin": p.get("Path", "")
            })
    except Exception:
        pass

    ports_ouverts_obj = []
    for p in sorted(ports_ouverts):
        try:
            service = socket.getservbyport(p)
        except Exception:
            service = "inconnu"
        ports_ouverts_obj.append({"port": p, "service": service})

    print(f"     OK {len(ports_ouverts_obj)} port(s) ouverts")
    return {
        "ports_ouverts":     ports_ouverts_obj,
        "nombre_ports":      len(ports_ouverts_obj),
        "smb1_active":       smb1 == 1,
        "rdp_active":        rdp == 0,
        "parefeu_desactive": parefeu_desactive,
        "partages_reseau":   partages,
    }


def collecter_ports_externes():
    print("  -> [4/8] Ports exposes a internet...")

    ip_publique = None
    for service in ["https://api.ipify.org", "https://ipv4.icanhazip.com"]:
        try:
            ip_publique = urllib.request.urlopen(
                service, timeout=5
            ).read().decode("utf-8").strip()
            socket.inet_aton(ip_publique)
            break
        except Exception:
            continue

    if not ip_publique:
        print("     ERREUR - IP publique non recuperee")
        return {"ip_publique": "inconnu", "ports_exposes": [], "nombre_exposes": 0}

    print(f"     IP publique : {ip_publique}")

    PORTS_A_TESTER = {
        21:    ("FTP",              "CRITIQUE"),
        22:    ("SSH",              "ELEVE"),
        23:    ("Telnet",           "CRITIQUE"),
        25:    ("SMTP",             "ELEVE"),
        53:    ("DNS",              "MOYEN"),
        80:    ("HTTP",             "MOYEN"),
        110:   ("POP3",             "ELEVE"),
        135:   ("RPC",              "CRITIQUE"),
        139:   ("NetBIOS",          "CRITIQUE"),
        143:   ("IMAP",             "ELEVE"),
        443:   ("HTTPS",            "MOYEN"),
        445:   ("SMB",              "CRITIQUE"),
        1433:  ("MSSQL",            "ELEVE"),
        1723:  ("PPTP VPN",         "MOYEN"),
        3306:  ("MySQL",            "ELEVE"),
        3389:  ("RDP",              "CRITIQUE"),
        5432:  ("PostgreSQL",       "ELEVE"),
        5900:  ("VNC",              "ELEVE"),
        5985:  ("WinRM HTTP",       "ELEVE"),
        5986:  ("WinRM HTTPS",      "ELEVE"),
        8080:  ("HTTP alternatif",  "MOYEN"),
        8443:  ("HTTPS alternatif", "MOYEN"),
        27017: ("MongoDB",          "ELEVE"),
    }

    def tester_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            resultat = sock.connect_ex((ip_publique, port))
            sock.close()
            return resultat == 0
        except Exception:
            return False

    ports_exposes = []
    print(f"     Test de {len(PORTS_A_TESTER)} ports", end="", flush=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futurs = {ex.submit(tester_port, port): port for port in PORTS_A_TESTER}
        for futur in concurrent.futures.as_completed(futurs):
            port   = futurs[futur]
            ouvert = futur.result()
            print(".", end="", flush=True)
            if ouvert:
                service, risque = PORTS_A_TESTER[port]
                ports_exposes.append({"port": port, "service": service, "risque": risque})

    print()
    ports_exposes.sort(key=lambda x: x["port"])
    print(f"     OK {len(ports_exposes)} port(s) exposes sur {len(PORTS_A_TESTER)} testes")
    return {
        "ip_publique":    ip_publique,
        "ports_testes":   len(PORTS_A_TESTER),
        "ports_exposes":  ports_exposes,
        "nombre_exposes": len(ports_exposes),
    }


def collecter_securite():
    print("  -> [5/8] Configuration securite...")

    uac = registre_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA"
    )
    lsass = registre_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "RunAsPPL"
    )
    ps_policy = powershell("Get-ExecutionPolicy")

    defender_json = powershell(
        "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,"
        "AntivirusEnabled,AntivirusSignatureAge | ConvertTo-Json -Compress"
    )
    defender = {
        "protection_temps_reel": False,
        "antivirus_actif":       False,
        "age_signatures_jours":  0,
    }
    try:
        d = json.loads(defender_json)
        defender = {
            "protection_temps_reel": d.get("RealTimeProtectionEnabled", False),
            "antivirus_actif":       d.get("AntivirusEnabled", False),
            "age_signatures_jours":  d.get("AntivirusSignatureAge", 0),
        }
    except Exception:
        pass

    bl_raw = powershell(
        "try { (Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus } catch { 'Off' }"
    )
    wu = powershell("(Get-Service wuauserv).Status")

    print("     OK securite collectee")
    return {
        "uac_active":           uac == 1,
        "lsass_protege":        lsass == 1,
        "ps_execution_policy":  ps_policy.strip(),
        "defender":             defender,
        "bitlocker_actif":      "On" in bl_raw,
        "windows_update_actif": "Running" in wu,
    }


def collecter_logiciels():
    print("  -> [6/8] Logiciels installes...")

    logiciels = []
    deja_vus  = set()
    cles = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, chemin in cles:
        try:
            cle = winreg.OpenKey(hive, chemin)
            i = 0
            while True:
                try:
                    sous_nom = winreg.EnumKey(cle, i)
                    sous_cle = winreg.OpenKey(cle, sous_nom)
                    try:
                        nom     = winreg.QueryValueEx(sous_cle, "DisplayName")[0]
                        version = winreg.QueryValueEx(sous_cle, "DisplayVersion")[0]
                        if nom and nom not in deja_vus:
                            deja_vus.add(nom)
                            logiciels.append({"nom": nom.strip(), "version": version.strip()})
                    except Exception:
                        pass
                    winreg.CloseKey(sous_cle)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(cle)
        except Exception:
            pass

    print(f"     OK {len(logiciels)} logiciel(s) trouves")
    return sorted(logiciels, key=lambda x: x["nom"].lower())


def collecter_politique_mdp():
    print("  -> [7/8] Politique mots de passe...")

    politique_raw = powershell("net accounts")
    politique = {
        "longueur_minimale":  0,
        "age_maximum":        "inconnu",
        "age_minimum":        "inconnu",
        "seuil_verrouillage": "inconnu",
        "complexite":         False,
    }
    for ligne in politique_raw.splitlines():
        l = ligne.lower()
        if "longueur" in l or "length" in l:
            val = ligne.split(":")[-1].strip()
            if val.isdigit():
                politique["longueur_minimale"] = int(val)
        if "maximum" in l and ("age" in l or "dur" in l):
            politique["age_maximum"] = ligne.split(":")[-1].strip()
        if "minimum" in l and ("age" in l or "dur" in l):
            politique["age_minimum"] = ligne.split(":")[-1].strip()
        if "verrouillage" in l or "lockout" in l:
            politique["seuil_verrouillage"] = ligne.split(":")[-1].strip()

    complexite = registre_lire(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "PasswordComplexity"
    )
    politique["complexite"] = complexite == 1

    print("     OK politique collectee")
    return politique


def collecter_persistence():
    print("  -> [8/8] Persistence et Autorun...")

    EXT_SUSPECTES = [".vbs", ".bat", ".ps1", ".cmd"]
    CHEM_SUSPECTS = ["temp", "tmp", "appdata", "public"]

    def est_suspect(valeur):
        v = valeur.lower()
        return any(e in v for e in EXT_SUSPECTES) and any(c in v for c in CHEM_SUSPECTS)

    tous_autoruns    = []
    autorun_suspects = []
    cles_autorun = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ]
    for hive, chemin in cles_autorun:
        try:
            cle = winreg.OpenKey(hive, chemin)
            i = 0
            while True:
                try:
                    nom, valeur, _ = winreg.EnumValue(cle, i)
                    entree = {"nom": nom, "valeur": valeur[:100], "suspect": est_suspect(valeur)}
                    tous_autoruns.append(entree)
                    if est_suspect(valeur):
                        autorun_suspects.append(entree)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(cle)
        except Exception:
            pass

    services_raw = powershell(
        "Get-WmiObject Win32_Service | Select-Object Name, PathName | ConvertTo-Json -Compress"
    )
    unquoted = []
    try:
        services = json.loads(services_raw)
        if isinstance(services, dict):
            services = [services]
        for svc in services:
            path = svc.get("PathName", "") or ""
            if path and " " in path and not path.startswith('"') and "windows" not in path.lower():
                unquoted.append({"service": svc.get("Name", ""), "chemin": path[:100]})
    except Exception:
        pass

    taches_raw = powershell(
        "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | "
        "Select-Object TaskName | ConvertTo-Json -Compress"
    )
    taches_suspectes = []
    try:
        taches = json.loads(taches_raw)
        if isinstance(taches, dict):
            taches = [taches]
        for t in taches:
            nom = t.get("TaskName", "") or ""
            if est_suspect(nom):
                taches_suspectes.append(nom)
    except Exception:
        pass

    print(f"     OK {len(tous_autoruns)} autorun(s) - {len(autorun_suspects)} suspect(s) - {len(unquoted)} unquoted")
    return {
        "tous_autoruns":     tous_autoruns,
        "autorun_suspects":  autorun_suspects,
        "unquoted_services": unquoted,
        "taches_suspectes":  taches_suspectes,
    }


def collecter_logs():
    print("  -> [8/8] Logs Windows...")

    def compter_evenement(event_id):
        resultat = powershell(
            f"(Get-WinEvent -FilterHashtable @{{LogName='Security'; Id={event_id}}} "
            f"-MaxEvents 500 -ErrorAction SilentlyContinue | Measure-Object).Count"
        )
        return int(resultat) if resultat.isdigit() else 0

    echecs_connexion       = compter_evenement(4625)
    nouveaux_comptes       = compter_evenement(4720)
    utilisation_privileges = compter_evenement(4672)
    changements_politique  = compter_evenement(4719)

    print(f"     OK {echecs_connexion} echec(s) - {nouveaux_comptes} nouveau(x) compte(s)")
    return {
        "echecs_connexion":       echecs_connexion,
        "nouveaux_comptes":       nouveaux_comptes,
        "utilisation_privileges": utilisation_privileges,
        "changements_politique":  changements_politique,
    }


if __name__ == "__main__":

    print("=" * 50)
    print("  AuditAI - Scanner Windows")
    print("=" * 50 + "\n")

    scan = {
        "date_scan":      datetime.datetime.now().isoformat(),
        "systeme":        collecter_systeme(),
        "comptes":        collecter_comptes(),
        "reseau":         collecter_reseau(),
        "ports_externes": collecter_ports_externes(),
        "securite":       collecter_securite(),
        "logiciels":      collecter_logiciels(),
        "politique_mdp":  collecter_politique_mdp(),
        "persistence":    collecter_persistence(),
        "logs":           collecter_logs(),
    }

    os.makedirs("C:\\AuditAI\\data", exist_ok=True)
    chemin = "C:\\AuditAI\\data\\scan_complet.json"

    s   = scan["systeme"]
    c   = scan["comptes"]
    r   = scan["reseau"]
    pe  = scan["ports_externes"]
    sec = scan["securite"]
    p   = scan["politique_mdp"]
    per = scan["persistence"]
    lg  = scan["logs"]
    d   = sec["defender"]

    risques = []

    if c["nombre_admins"] > 2:
        risques.append(("ELEVE", f"Trop d'administrateurs : {c['nombre_admins']}"))

    for u in c["utilisateurs"]:
        if u.get("mdp_expire_jamais") and u.get("actif"):
            risques.append(("ELEVE", f"Mot de passe sans expiration : {u['nom']}"))

    if p["longueur_minimale"] < 8:
        risques.append(("ELEVE", f"Longueur minimale mdp : {p['longueur_minimale']} caracteres"))

    if "jamais" in str(p["seuil_verrouillage"]).lower() or "never" in str(p["seuil_verrouillage"]).lower():
        risques.append(("ELEVE", "Aucun verrouillage de compte configure"))

    if not p["complexite"]:
        risques.append(("MOYEN", "Complexite mot de passe non requise"))

    if r["smb1_active"]:
        risques.append(("CRITIQUE", "SMBv1 active - Risque WannaCry"))

    if r["rdp_active"]:
        risques.append(("ELEVE", "RDP active - Risque acces distant"))

    if r["parefeu_desactive"]:
        risques.append(("CRITIQUE", "Pare-feu desactive"))

    PORTS_DANGEREUX = {
        21: "FTP", 23: "Telnet", 135: "RPC",
        139: "NetBIOS", 445: "SMB", 3389: "RDP", 5985: "WinRM"
    }
    for port in r["ports_ouverts"]:
        if port in PORTS_DANGEREUX:
            risques.append(("CRITIQUE", f"Port dangereux ouvert : {port} ({PORTS_DANGEREUX[port]})"))

    for partage in r["partages_reseau"]:
        if partage["nom"] in ["C$", "ADMIN$", "D$"]:
            risques.append(("MOYEN", f"Partage administratif actif : {partage['nom']}"))

    for port_exp in pe["ports_exposes"]:
        risques.append((port_exp["risque"], f"Port expose sur internet : {port_exp['port']} ({port_exp['service']})"))

    if not sec["uac_active"]:
        risques.append(("CRITIQUE", "UAC desactive"))

    if not sec["lsass_protege"]:
        risques.append(("CRITIQUE", "LSASS non protege - Risque Mimikatz"))

    if sec["ps_execution_policy"].lower() == "unrestricted":
        risques.append(("ELEVE", "PowerShell en mode Unrestricted"))

    if not sec["bitlocker_actif"]:
        risques.append(("MOYEN", "BitLocker non active sur C:"))

    if not sec["windows_update_actif"]:
        risques.append(("CRITIQUE", "Windows Update arrete"))

    if not d["protection_temps_reel"]:
        risques.append(("CRITIQUE", "Windows Defender desactive"))

    if d["age_signatures_jours"] > 7:
        risques.append(("ELEVE", f"Signatures antivirus obsoletes : {d['age_signatures_jours']} jours"))

    for entry in per["autorun_suspects"]:
        risques.append(("ELEVE", f"Autorun suspect : {entry['nom']}"))

    for svc in per["unquoted_services"]:
        risques.append(("ELEVE", f"Unquoted service path : {svc['service']}"))

    for tache in per["taches_suspectes"]:
        risques.append(("ELEVE", f"Tache planifiee suspecte : {tache}"))

    if lg["echecs_connexion"] > 20:
        risques.append(("ELEVE", f"Echecs de connexion suspects : {lg['echecs_connexion']}"))

    if lg["nouveaux_comptes"] > 0:
        risques.append(("MOYEN", f"Nouveaux comptes crees : {lg['nouveaux_comptes']}"))

    scan["risques"] = [{"niveau": r[0], "message": r[1]} for r in risques]

    with open(chemin, "w", encoding="utf-8") as f:
        json.dump(scan, f, indent=4, ensure_ascii=False)

    ordre = {"CRITIQUE": 0, "ELEVE": 1, "MOYEN": 2, "FAIBLE": 3}
    risques.sort(key=lambda x: ordre.get(x[0], 4))

    nb_critique = len([x for x in risques if x[0] == "CRITIQUE"])
    nb_eleve    = len([x for x in risques if x[0] == "ELEVE"])
    nb_moyen    = len([x for x in risques if x[0] == "MOYEN"])

    print("\n" + "-" * 50)
    print(f"  AUDIT DE SECURITE - {s['hostname']} - {scan['date_scan'][:10]}")
    print("-" * 50)

    if risques:
        print("\n  RISQUES DETECTES :\n")
        for niveau, message in risques:
            print(f"  {niveau:10} - {message}")
    else:
        print("\n  Aucun risque detecte.")

    print(f"\n  RESUME :")
    print(f"  Total    : {len(risques)} risque(s)")
    print(f"  Critique : {nb_critique}  |  Eleve : {nb_eleve}  |  Moyen : {nb_moyen}")
    print("\n" + "-" * 50)
    print(f"  Rapport  : {chemin}")
    print("-" * 50)