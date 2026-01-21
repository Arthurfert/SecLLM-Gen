#!/usr/bin/env python3
"""
Générateur de Scripts d'Exploitation CVE
Utilise Nmap pour la détection et Ollama pour la génération d'exploits

Architecture modulaire:
- nmap_scanner.py: Fonctionnalités de scan Nmap
- llm_generator.py: Génération de scripts avec LLM
- cve_database.py: Base de données des CVE
"""

from nmap_scanner import scan_for_heartbleed, scan_ports_nmap
from llm_generator_rag import generate_exploit_script, save_script, get_available_models
from cve_database import get_cve_info, is_heartbleed


def select_port_from_scan(scan_results: dict, cve: str) -> int:
    """
    Permet à l'utilisateur de sélectionner un port parmi les résultats du scan.
    Priorise automatiquement les ports vulnérables.
    
    Args:
        scan_results: Résultats du scan Nmap
        cve: Identifiant CVE
    
    Returns:
        int: Port sélectionné
    """
    if not scan_results or len(scan_results) == 0:
        print("\n⚠️  Aucun port ouvert détecté. Voulez-vous continuer quand même?")
        manual_port = input("   Entrez un port manuellement (ou Entrée pour annuler): ").strip()
        if manual_port.isdigit():
            return int(manual_port)
        else:
            print("❌ Abandon")
            exit(0)
    
    # Filtrer les ports vulnérables
    vulnerable_ports = {
        port: info for port, info in scan_results.items() 
        if info.get('vulnerable') is True
    }
    
    # Si des ports vulnérables sont détectés, les prioriser
    if vulnerable_ports:
        print(f"\n🔴 {len(vulnerable_ports)} port(s) VULNÉRABLE(S) détecté(s) !")
        
        if len(vulnerable_ports) == 1:
            selected_port = list(vulnerable_ports.keys())[0]
            print(f"✅ Port vulnérable sélectionné automatiquement: {selected_port}")
            return selected_port
        else:
            print("\nPlusieurs ports vulnérables détectés. Lequel voulez-vous exploiter?")
            for idx, (port, info) in enumerate(vulnerable_ports.items(), 1):
                print(f"   {idx}. Port {port} ({info['service']}) - VULNÉRABLE")
            
            choice = input("Votre choix (numéro ou port): ").strip()
            try:
                if choice.isdigit():
                    choice_idx = int(choice)
                    if 1 <= choice_idx <= len(vulnerable_ports):
                        return list(vulnerable_ports.keys())[choice_idx - 1]
                    else:
                        return int(choice)
                else:
                    return int(choice)
            except ValueError:
                print("⚠️  Choix invalide, utilisation du premier port vulnérable")
                return list(vulnerable_ports.keys())[0]
    
    # Si aucun port vulnérable mais des ports ouverts
    elif len(scan_results) == 1:
        selected_port = list(scan_results.keys())[0]
        vuln_status = scan_results[selected_port].get('vulnerable')
        if vuln_status is False:
            print(f"\n🟢 Port {selected_port} ouvert mais NON vulnérable selon le script NSE")
            confirm = input("Voulez-vous continuer quand même? (o/N): ").strip().lower()
            if confirm not in ['o', 'oui', 'y', 'yes']:
                print("❌ Abandon")
                exit(0)
        else:
            print(f"\n✅ Port automatiquement sélectionné: {selected_port}")
        return selected_port
    else:
        # Proposer de choisir parmi les ports ouverts
        print("\nPlusieurs ports ouverts détectés. Lequel voulez-vous exploiter?")
        for idx, (port, info) in enumerate(scan_results.items(), 1):
            vuln_marker = ""
            if info.get('vulnerable') is False:
                vuln_marker = " - 🟢 Non vulnérable"
            print(f"   {idx}. Port {port} ({info['service']}){vuln_marker}")
        
        choice = input("Votre choix (numéro ou port): ").strip()
        try:
            if choice.isdigit():
                choice_idx = int(choice)
                if 1 <= choice_idx <= len(scan_results):
                    return list(scan_results.keys())[choice_idx - 1]
                else:
                    return int(choice)
            else:
                return int(choice)
        except ValueError:
            print("⚠️  Choix invalide, utilisation du premier port détecté")
            return list(scan_results.keys())[0]


def main():
    """Programme principal"""
    print("=" * 60)
    print("🔐 Générateur de Scripts d'Exploitation CVE")
    print("⚠️  Usage éducatif et éthique uniquement")
    print("=" * 60)
    print()
    
    # Demander le CVE à exploiter
    cve = input("CVE à exploiter (ex: CVE-2014-0160): ").strip()
    
    if not cve:
        cve = "CVE-2014-0160"  # Heartbleed par défaut
        print(f"Utilisation du CVE par défaut: {cve} (Heartbleed)")
    
    print()
    
    # Demander l'IP cible
    ip = input("Adresse IP de la cible (ex: 192.168.1.10): ").strip()
    
    if not ip:
        print("❌ Adresse IP requise")
        exit(1)
    
    selected_port = None
    
    # Mode Heartbleed direct (scan sans base de données)
    if is_heartbleed(cve):
        print(f"\n🎯 Mode: Détection Heartbleed directe avec Nmap")
        
        # Demander si l'utilisateur veut spécifier des ports ou détecter automatiquement
        print("\nOptions de scan:")
        print("  1. Détection automatique des ports SSL/TLS (recommandé)")
        print("  2. Spécifier manuellement les ports")
        
        choice = input("\nVotre choix (1/2, Entrée=1): ").strip()
        
        ports_to_scan = None
        
        if choice == "2":
            ports_input = input("Ports à scanner (ex: 443,8443): ").strip()
            if ports_input:
                try:
                    ports_to_scan = [int(p.strip()) for p in ports_input.split(',')]
                except ValueError:
                    print("⚠️  Format invalide, utilisation de la détection automatique")
                    ports_to_scan = None
        
        # Scanner avec Heartbleed (détection auto si ports_to_scan est None)
        scan_results = scan_for_heartbleed(ip, ports_to_scan)
        selected_port = select_port_from_scan(scan_results, cve)
    
    # Mode avec base de données CVE
    elif cve_info := get_cve_info(cve):
        print(f"\n📋 CVE détectée: {cve_info['service']}")
        print(f"   Ports typiques: {', '.join(map(str, cve_info['ports']))}")
        
        if cve_info.get('nse_script'):
            print(f"   Script NSE: {cve_info['nse_script']}")
        
        # Demander si l'utilisateur veut scanner
        scan_choice = input("\n🔍 Voulez-vous scanner ces ports avec Nmap? (o/N): ").strip().lower()
        
        if scan_choice in ['o', 'oui', 'y', 'yes']:
            scan_results = scan_ports_nmap(
                ip, 
                cve_info['ports'],
                cve_info.get('nse_script')
            )
            selected_port = select_port_from_scan(scan_results, cve)
        else:
            # L'utilisateur ne veut pas scanner
            manual_port = input(f"Port de la cible (ex: {cve_info['ports'][0]}): ").strip()
            if manual_port.isdigit():
                selected_port = int(manual_port)
            else:
                selected_port = cve_info['ports'][0]
                print(f"Utilisation du port par défaut: {selected_port}")
    
    # CVE inconnue
    else:
        print(f"\n⚠️  CVE {cve} non reconnue dans la base de données")
        manual_port = input("Port de la cible (ex: 80): ").strip()
        if manual_port.isdigit():
            selected_port = int(manual_port)
        else:
            print("❌ Port invalide")
            exit(1)
    
    # Afficher la cible
    print(f"\n🎯 Cible: {ip}:{selected_port}")
    
    # Récupérer les modèles Ollama disponibles
    print("\n🔍 Récupération des modèles Ollama disponibles...")
    available_models = get_available_models()
    
    if available_models:
        print(f"\n📋 Modèles disponibles ({len(available_models)}):")
        for idx, model in enumerate(available_models, 1):
            print(f"   {idx}. {model}")
        
        model_choice = input("\nChoisissez un modèle (numéro ou nom, Entrée pour le 1er): ").strip()
        
        if not model_choice:
            model_name = available_models[0]
            print(f"Utilisation du modèle par défaut: {model_name}")
        elif model_choice.isdigit():
            choice_idx = int(model_choice)
            if 1 <= choice_idx <= len(available_models):
                model_name = available_models[choice_idx - 1]
                print(f"Modèle sélectionné: {model_name}")
            else:
                print(f"⚠️  Choix invalide, utilisation du premier modèle: {available_models[0]}")
                model_name = available_models[0]
        else:
            # Vérifier si le nom existe
            if model_choice in available_models:
                model_name = model_choice
                print(f"Modèle sélectionné: {model_name}")
            else:
                print(f"⚠️  Modèle '{model_choice}' non trouvé, utilisation de: {available_models[0]}")
                model_name = available_models[0]
    else:
        print("\n⚠️  Aucun modèle Ollama détecté. Assurez-vous qu'Ollama est lancé.")
        model_name = input("Entrez le nom du modèle à utiliser (ex: codestral): ").strip()
        if not model_name:
            model_name = "codestral"
            print("Utilisation du modèle par défaut: codestral")
    
    # Générer le script avec le LLM
    script_content = generate_exploit_script(cve, ip, selected_port, model_name)
    
    if script_content:
        print("\n" + "=" * 60)
        print("📝 Script généré")
        print("=" * 60)
        
        # Sauvegarder le script
        filepath = save_script(cve, script_content, ip, selected_port)
        print(f"\n✅ Script sauvegardé: {filepath}")
    else:
        print("\n❌ Échec de la génération du script.")


if __name__ == "__main__":
    main()
