from scapy.all import *

def scan_ports(target_ip, ports_to_scan):
    print("Exploration des ports...")
    for port in ports_to_scan:
        response = sr1(IP(dst=target_ip)/TCP(dport=port, flags="S"), timeout=1, verbose=False)
        if response is not None:
            print(f"Port {port} is open")

def exploit_vulnerability(target_ip):
    print("Exploitation des vulnérabilités (à des fins éducatives uniquement)...")
    payload = "Commande malveillante"
    exploit_packet = IP(dst=target_ip)/TCP(dport=22)/Raw(load=payload)
    send(exploit_packet)

def post_exploitation(target_ip):
    print("Analyse post-exploitation...")
    packets = sniff(filter=f"host {target_ip}", count=10)
    for pkt in packets:
        print(pkt.summary())

def generate_report(target_ip, ports_to_scan):
    print("Génération de rapport...")
    report = f"Rapport de test d'intrusion sur {target_ip}:\n"
    report += "Ports ouverts:\n"
    for port in ports_to_scan:
        response = sr1(IP(dst=target_ip)/TCP(dport=port, flags="S"), timeout=1, verbose=False)
        if response is not None:
            report += f"- Port {port}: Open\n"
    with open("intrusion_test_report.txt", "w") as file:
        file.write(report)
    print("Rapport généré avec succès!")

# Menu principal
while True:
    print("\nMenu:")
    print("1. Explorer les ports")
    print("2. Exploiter les vulnérabilités")
    print("3. Analyser post-exploitation")
    print("4. Générer un rapport")
    print("5. Quitter")

    choice = input("Choisissez une option : ")

    if choice == "1":
        target_ip = input("Entrez l'adresse IP cible : ")
        ports_to_scan = [int(port) for port in input("Entrez les ports à scanner (séparés par des virgules) : ").split(",")]
        scan_ports(target_ip, ports_to_scan)
    elif choice == "2":
        target_ip = input("Entrez l'adresse IP cible : ")
        exploit_vulnerability(target_ip)
    elif choice == "3":
        target_ip = input("Entrez l'adresse IP cible : ")
        post_exploitation(target_ip)
    elif choice == "4":
        target_ip = input("Entrez l'adresse IP cible : ")
        ports_to_scan = [int(port) for port in input("Entrez les ports à scanner (séparés par des virgules) : ").split(",")]
        generate_report(target_ip, ports_to_scan)
    elif choice == "5":
        print("Au revoir!")
        break
    else:
        print("Option invalide. Veuillez choisir une option valide.")
