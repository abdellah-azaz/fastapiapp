from google import genai

try:
    from config_local import GEMINI_API_KEY
except:
    GEMINI_API_KEY = ""

def analyze_threat(filename, result, threat_name, heuristic_score, entropy):
    client = genai.Client(api_key=GEMINI_API_KEY)

    prompt = f"""Tu es un expert en cybersécurité. Analyse ce fichier détecté par un antivirus et réponds en français.

Fichier : {filename}
Résultat : {result}
Menace détectée : {threat_name if threat_name else 'Inconnue'}
Score heuristique : {heuristic_score}/100
Entropie : {entropy}

Donne une analyse structurée avec exactement ces 5 sections. IMPORTANT: N'utilise pas ** pour le gras, écris le texte normalement sans formatage markdown :

🏷️ CLASSIFICATION
[Choisis parmi : Trojan / Backdoor / Ransomware / Keylogger / Cryptominer / Script malveillant / Spyware / Worm / Adware / Code obfusqué / Inconnu]
[Justifie en 1 phrase]

🎯 TYPE DE MENACE
[Explique le type de malware/menace en 2-3 phrases]

⚠️ POURQUOI C'EST DANGEREUX
[Explique les risques concrets en 2-3 phrases]

🛡️ RECOMMANDATIONS
[3 actions concrètes à faire]

🔴 NIVEAU DE RISQUE : [FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE]
[Justification en 1 phrase]"""

    response = client.models.generate_content(
        model="gemini-3.1-flash-lite-preview",
        contents=prompt
    )
    return response.text
