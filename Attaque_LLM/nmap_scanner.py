"""
Module de scan Nmap pour la détection de vulnérabilités
"""
import subprocess


def detect_ssl_ports(target_ip: str, port_range: str = "1-10000") -> list:
    """
    Détecte les ports SSL/TLS ouverts sur une cible.
    
    Args:
        target_ip: L'adresse IP cible
        port_range: Plage de ports à scanner (par défaut: 1-10000)
    
    Returns:
        list: Liste des ports SSL/TLS détectés
    """
    print(f"\n🔍 Détection des ports SSL/TLS sur {target_ip}...")
    print(f"   Plage de ports: {port_range}")
    
    if not check_nmap_installed():
        return []
    
    cmd = [
        "nmap",
        "-p", port_range,
        "-sV",
        "--open",
        target_ip
    ]
    
    try:
        print(f"   Commande: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )
        
        ssl_ports = []
        for line in result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                line_lower = line.lower()
                # Détecter les services SSL/TLS
                if any(keyword in line_lower for keyword in ["ssl", "https", "tls", "443"]):
                    port_num = int(line.split('/')[0].strip())
                    service = line.split()[2] if len(line.split()) > 2 else "unknown"
                    ssl_ports.append(port_num)
                    print(f"   ✓ Port SSL/TLS détecté: {port_num} ({service})")
        
        if ssl_ports:
            print(f"\n✅ {len(ssl_ports)} port(s) SSL/TLS détecté(s): {', '.join(map(str, ssl_ports))}")
        else:
            print(f"\n⚠️  Aucun port SSL/TLS détecté")
        
        return ssl_ports
    
    except subprocess.TimeoutExpired:
        print("❌ Timeout lors de la détection des ports SSL")
        return []
    except Exception as e:
        print(f"❌ Erreur lors de la détection: {e}")
        return []


def scan_for_heartbleed(target_ip: str, ports: list = None) -> dict:
    """
    Scanne directement une cible pour détecter Heartbleed avec Nmap.
    Si aucun port n'est fourni, détecte d'abord les ports SSL/TLS ouverts.
    
    Args:
        target_ip: L'adresse IP cible
        ports: Liste des ports à scanner (si None, détection automatique)
    
    Returns:
        dict: Résultats du scan {port: {status, service, vulnerable}}
    """
    # Si aucun port spécifié, détecter les ports SSL/TLS
    if ports is None:
        print(f"\n🎯 Mode: Détection automatique des ports SSL/TLS")
        ports = detect_ssl_ports(target_ip)
        
        if not ports:
            print("\n⚠️  Aucun port SSL/TLS détecté. Voulez-vous scanner les ports communs quand même?")
            fallback = input("   Scanner les ports 443, 8443, 4433? (o/N): ").strip().lower()
            if fallback in ['o', 'oui', 'y', 'yes']:
                ports = [443, 8443, 4433]
            else:
                return {}
    
    print(f"\n🔍 Test Heartbleed sur {target_ip}...")
    print(f"   Ports testés: {', '.join(map(str, ports))}")
    print(f"   Script NSE: ssl-heartbleed")
    
    # Vérifier si nmap est installé
    if not check_nmap_installed():
        return None
    
    # Construire la commande nmap
    ports_str = ",".join(map(str, ports))
    cmd = [
        "nmap",
        "-p", ports_str,
        "-sV",  # Détection de version
        "-T4",  # Timing agressif
        "--script", "ssl-heartbleed",
        "--open",
        target_ip
    ]
    
    try:
        print(f"   Commande: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        # Parser les résultats
        open_ports = parse_heartbleed_results(result.stdout)
        
        # Afficher les résultats
        display_scan_results(open_ports, ports_str)
        
        return open_ports
    
    except subprocess.TimeoutExpired:
        print("❌ Timeout du scan Nmap")
        return None
    except Exception as e:
        print(f"❌ Erreur lors du scan Nmap: {e}")
        return None


def scan_ports_nmap(target_ip: str, ports: list, nse_script: str = None) -> dict:
    """
    Scanne les ports spécifiés sur l'IP cible avec Nmap.
    Si un script NSE est fourni, l'utilise pour détecter la vulnérabilité.
    
    Args:
        target_ip: L'adresse IP cible
        ports: Liste des ports à scanner
        nse_script: Script NSE pour détecter la vulnérabilité (optionnel)
    
    Returns:
        dict: Résultats du scan {port: {status, service, vulnerable}}
    """
    print(f"\n🔍 Scan Nmap en cours sur {target_ip}...")
    print(f"   Ports ciblés: {', '.join(map(str, ports))}")
    
    if nse_script:
        print(f"   Script de détection: {nse_script}")
    
    # Vérifier si nmap est installé
    if not check_nmap_installed():
        return None
    
    # Construire la commande nmap
    ports_str = ",".join(map(str, ports))
    cmd = [
        "nmap",
        "-p", ports_str,
        "-T4",  # Timing agressif
    ]
    
    # Ajouter le script NSE si disponible
    if nse_script:
        cmd.extend(["--script", nse_script])
    else:
        cmd.append("-sV")  # Détection de version uniquement
    
    cmd.extend(["--open", target_ip])  # Seulement les ports ouverts
    
    try:
        print(f"   Commande: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120  # Augmenté pour les scripts NSE
        )
        
        # Parser les résultats
        open_ports = parse_nse_results(result.stdout, nse_script)
        
        # Afficher les résultats
        if open_ports:
            print(f"\n✅ Ports ouverts détectés:")
            for port, info in open_ports.items():
                vuln_status = ""
                if info.get("vulnerable") is True:
                    vuln_status = " 🔴 VULNÉRABLE"
                elif info.get("vulnerable") is False:
                    vuln_status = " 🟢 Non vulnérable"
                
                print(f"   • Port {port}: {info['service']} ({info['status']}){vuln_status}")
                
                if info.get("vuln_info"):
                    print(f"     └─ {info['vuln_info']}")
        else:
            print(f"\n⚠️  Aucun port ouvert détecté parmi: {ports_str}")
        
        # Afficher la sortie complète du script NSE si disponible
        if nse_script and result.stdout:
            display_nse_output(result.stdout, nse_script)
        
        return open_ports
    
    except subprocess.TimeoutExpired:
        print("❌ Timeout du scan Nmap (peut être dû au script NSE)")
        return None
    except Exception as e:
        print(f"❌ Erreur lors du scan Nmap: {e}")
        return None


def check_nmap_installed() -> bool:
    """
    Vérifie si Nmap est installé et accessible.
    
    Returns:
        bool: True si Nmap est installé, False sinon
    """
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  Nmap n'est pas installé ou introuvable dans le PATH")
        print("   Installation: https://nmap.org/download.html")
        return False


def parse_heartbleed_results(output: str) -> dict:
    """
    Parse les résultats d'un scan Heartbleed.
    
    Args:
        output: Sortie texte de Nmap
    
    Returns:
        dict: Ports avec leur statut de vulnérabilité
    """
    open_ports = {}
    lines = output.splitlines()
    current_port = None
    in_heartbleed_section = False
    
    for line in lines:
        # Détecter les ports ouverts
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 3 and "open" in parts[1]:
                port_num = int(parts[0].split('/')[0])
                service = parts[2] if len(parts) > 2 else "unknown"
                open_ports[port_num] = {
                    "status": "open",
                    "service": service,
                    "vulnerable": False,  # Par défaut non vulnérable
                    "vuln_details": []
                }
                current_port = port_num
                in_heartbleed_section = False
        
        # Détecter le début de la section ssl-heartbleed
        if "ssl-heartbleed" in line.lower() and current_port:
            in_heartbleed_section = True
        
        # Détecter la vulnérabilité dans la section ssl-heartbleed
        if in_heartbleed_section and current_port:
            line_lower = line.lower()
            
            # Détection positive de vulnérabilité
            if "state: vulnerable" in line_lower or "vulnerable:" in line_lower:
                if "not vulnerable" not in line_lower:
                    open_ports[current_port]["vulnerable"] = True
                    open_ports[current_port]["vuln_details"].append(line.strip())
            
            # Détection négative
            elif "not vulnerable" in line_lower or "state: not vulnerable" in line_lower:
                open_ports[current_port]["vulnerable"] = False
            
            # Capturer les détails
            elif line.strip().startswith("|"):
                open_ports[current_port]["vuln_details"].append(line.strip())
    
    return open_ports


def parse_nse_results(output: str, nse_script: str = None) -> dict:
    """
    Parse les résultats d'un scan NSE générique.
    
    Args:
        output: Sortie texte de Nmap
        nse_script: Nom du script NSE utilisé
    
    Returns:
        dict: Ports avec leur statut de vulnérabilité
    """
    open_ports = {}
    lines = output.splitlines()
    current_port = None
    
    for line in lines:
        # Détecter les ports ouverts
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 3 and "open" in parts[1]:
                port_num = int(parts[0].split('/')[0])
                service = parts[2] if len(parts) > 2 else "unknown"
                open_ports[port_num] = {
                    "status": "open",
                    "service": service,
                    "vulnerable": None
                }
                current_port = port_num
        
        # Détecter les résultats du script NSE (vulnérabilité)
        if nse_script and current_port:
            line_lower = line.lower()
            if "vulnerable" in line_lower or "vuln" in line_lower:
                if "not vulnerable" not in line_lower and "state: not" not in line_lower:
                    open_ports[current_port]["vulnerable"] = True
                    open_ports[current_port]["vuln_info"] = line.strip()
            elif "state: vulnerable" in line_lower:
                open_ports[current_port]["vulnerable"] = True
                open_ports[current_port]["vuln_info"] = line.strip()
    
    return open_ports


def display_scan_results(open_ports: dict, ports_str: str):
    """
    Affiche les résultats du scan de manière formatée.
    
    Args:
        open_ports: Dictionnaire des ports détectés
        ports_str: Chaîne des ports scannés
    """
    if open_ports:
        print(f"\n✅ Résultats du scan:")
        vulnerable_found = False
        
        for port, info in open_ports.items():
            vuln_status = ""
            if info.get("vulnerable"):
                vuln_status = " 🔴 VULNÉRABLE À HEARTBLEED"
                vulnerable_found = True
            else:
                vuln_status = " 🟢 Non vulnérable"
            
            print(f"   • Port {port}: {info['service']} ({info['status']}){vuln_status}")
            
            # Afficher quelques détails
            if info.get("vuln_details"):
                for detail in info["vuln_details"][:3]:
                    print(f"     {detail}")
        
        if vulnerable_found:
            print(f"\n🔴 ATTENTION: Heartbleed détecté !")
        else:
            print(f"\n🟢 Aucune vulnérabilité Heartbleed détectée")
    else:
        print(f"\n⚠️  Aucun port ouvert détecté parmi: {ports_str}")


def display_nse_output(output: str, nse_script: str):
    """
    Affiche la sortie détaillée du script NSE.
    
    Args:
        output: Sortie complète de Nmap
        nse_script: Nom du script NSE
    """
    script_output = []
    capture = False
    
    for line in output.splitlines():
        if nse_script in line or "Host script results:" in line:
            capture = True
        if capture and line.strip():
            script_output.append(line)
    
    if script_output:
        print(f"\n📋 Résultat détaillé du script {nse_script}:")
        for line in script_output[:10]:  # Limiter à 10 lignes
            print(f"   {line}")
