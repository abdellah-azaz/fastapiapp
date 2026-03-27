import os
from groq import Groq
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

def analyze_threat(filename, result, threat_name, heuristic_score, entropy):
    """
    Utilise Groq (LLAMA 3.3) pour expliquer une détection de menace.
    """
    if not GROQ_API_KEY:
        return "Erreur : Clé API Groq non configurée."

    client = Groq(api_key=GROQ_API_KEY)
    
    prompt = f"""Tu es un expert en cybersécurité. Analyse ce fichier détecté par un antivirus et réponds en français.

Fichier : {filename}
Résultat : {result}
Menace détectée : {threat_name if threat_name else 'Inconnue'}
Score heuristique : {heuristic_score}/100
Entropie : {entropy}

Donne une analyse structurée avec exactement ces 5 sections :

🏷️ CLASSIFICATION
[Choisis parmi : Trojan / Backdoor / Ransomware / Keylogger / Cryptominer / Script malveillant / Spyware / Worm / Adware / Code obfusqué / Inconnu]
[Justifie en 1 sentence]

🎯 TYPE DE MENACE
[Explique le type de malware/menace en 2-3 sentences]

⚠️ POURQUOI C'EST DANGEREUX
[Explique les risques concrets en 2-3 sentences]

🛡️ RECOMMANDATIONS
[3 actions concrètes à faire]

🔴 NIVEAU DE RISQUE : [FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE]
[Justification en 1 sentence]"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
            temperature=0.3
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Erreur lors de l'analyse AI : {str(e)}"
