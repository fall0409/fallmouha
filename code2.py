import csv
import webbrowser
import matplotlib.pyplot as plt

# 1. Ouverture du fichier de capture de paquets
try:
    fichier = open("DumpFile.txt", "r")
except FileNotFoundError:
    print("Erreur : Le fichier 'Dumpfile.txt' est introuvable.")
    exit()

# 2. Initialisation des listes et compteurs
ipsr, ipde, ports, flags, seq, ack, win, options, length, heure = [], [], [], [], [], [], [], [], [], []
flagcounterP, flagcounterS, flagcounter, framecounter, requestcounter, replycounter = 0, 0, 0, 0, 0, 0

# 3. Analyse des 10 premières lignes du fichier
for i, line in enumerate(fichier):
    if i >= 10:
        break  # Limiter à 10 premières lignes
    elements = line.split()

    if "IP" in elements:
        ipsr.append(elements[2])
        ipde.append(elements[4])
        ports.append(elements[2].split(":")[-1] if ":" in elements[2] else "")
        
        # Détection des drapeaux
        flag = "P" if "[P]" in line else "S" if "[S]" in line else "." if "[.]" in line else ""
        flags.append(flag)
        
        if flag == "P":
            flagcounterP += 1
        elif flag == "S":
            flagcounterS += 1
        elif flag == ".":
            flagcounter += 1
        
        seq.append(elements[elements.index("seq") + 1] if "seq" in elements else "")
        ack.append(elements[elements.index("ack") + 1] if "ack" in elements else "")
        win.append(elements[elements.index("win") + 1] if "win" in elements else "")
        options.append("nop,nop,TS" if "nop,nop,TS" in line else "")
        length.append(elements[-1])
        heure.append(elements[0])
        framecounter += 1
    
    if "ICMP" in elements:
        if "request" in elements:
            requestcounter += 1
        elif "reply" in elements:
            replycounter += 1

fichier.close()

# 4. Création des graphiques (toujours générés, même si les données sont nulles)
plt.figure(figsize=(6, 6))
if framecounter > 0:
    plt.pie([flagcounterP, flagcounterS, flagcounter], labels=["PUSH", "SYN", "ACK"], autopct='%1.1f%%')
    plt.title("Répartition des drapeaux")
else:
    plt.text(0.5, 0.5, "Aucun drapeau détecté", ha="center", va="center", fontsize=12)
    plt.title("Répartition des drapeaux (Aucune donnée)")
plt.savefig("graphe1.png")
plt.close()

plt.figure(figsize=(6, 6))
if requestcounter + replycounter > 0:
    plt.pie([requestcounter, replycounter], labels=["Requêtes", "Réponses"], autopct='%1.1f%%')
    plt.title("Répartition des requêtes et réponses ICMP")
else:
    plt.text(0.5, 0.5, "Aucune requête/réponse ICMP détectée", ha="center", va="center", fontsize=12)
    plt.title("Répartition des requêtes et réponses ICMP (Aucune donnée)")
plt.savefig("graphe2.png")
plt.close()

# 5. Écriture des données dans un fichier CSV
with open('sae.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["DATE", "SOURCE", "PORT", "DESTINATION", "FLAG", "SEQ", "ACK", "WIN", "OPTIONS", "LENGTH"])
    for i in range(len(ipsr)):
        writer.writerow([heure[i], ipsr[i], ports[i], ipde[i], flags[i], seq[i], ack[i], win[i], options[i], length[i]])

with open('ds.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Flag[P] (PUSH)", "Flag[S] (SYN)", "Flag[.] (ACK)", "Nombre total de trames", "nombre de request", "nombre de reply"])
    writer.writerow([flagcounterP, flagcounterS, flagcounter, framecounter, requestcounter, replycounter])

# 6. Création de la page HTML pour afficher les graphiques
html_content = """
<html>
<head><title>Statistiques des paquets</title></head>
<body>
    <h1>Statistiques des Paquets</h1>
    <h2>Graphiques des Drapeaux</h2>
    <img src="graphe1.png" alt="Graphique des drapeaux">
    <p>Ce graphique montre la répartition des types de drapeaux utilisés dans les paquets capturés.</p>
    <h2>Graphiques des Requêtes et Réponses ICMP</h2>
    <img src="graphe2.png" alt="Graphique des requêtes et réponses">
    <p>Ce graphique montre la répartition des requêtes et des réponses ICMP capturées.</p>
    <h2>Détails des Paquets</h2>
    <table border="1">
        <tr>
            <th>DATE</th>
            <th>SOURCE</th>
            <th>PORT</th>
            <th>DESTINATION</th>
            <th>FLAG</th>
            <th>SEQ</th>
            <th>ACK</th>
            <th>WIN</th>
            <th>OPTIONS</th>
            <th>LENGTH</th>
        </tr>
"""
for i in range(len(ipsr)):
    html_content += f"""
        <tr>
            <td>{heure[i]}</td>
            <td>{ipsr[i]}</td>
            <td>{ports[i]}</td>
            <td>{ipde[i]}</td>
            <td>{flags[i]}</td>
            <td>{seq[i]}</td>
            <td>{ack[i]}</td>
            <td>{win[i]}</td>
            <td>{options[i]}</td>
            <td>{length[i]}</td>
        </tr>
    """
html_content += """
    </table>
    <h2>Résumé des Drapeaux</h2>
    <p>Nombre de paquets avec le flag PUSH (P) : {flagcounterP}</p>
    <p>Nombre de paquets avec le flag SYN (S) : {flagcounterS}</p>
    <p>Nombre de paquets avec le flag ACK (.) : {flagcounter}</p>
    <p>Nombre total de paquets analysés : {framecounter}</p>
    <h2>Résumé des ICMP</h2>
    <p>Nombre de requêtes ICMP : {requestcounter}</p>
    <p>Nombre de réponses ICMP : {replycounter}</p>
</body>
</html>
"""

with open("statistics.html", "w") as file:
    file.write(html_content)

# 7. Ouverture de la page HTML dans le navigateur
webbrowser.open("statistics.html")

print("\nAnalyse terminée. Les fichiers CSV et les graphiques ont été générés.")
