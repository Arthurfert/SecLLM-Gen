#!/usr/bin/env python3
"""
Générateur de Scripts de règles IDS basées sur des CVE
"""

from llm_generator import generate_ids_script, save_script, get_available_models

def main():
    """Programme principal"""
    print("=" * 60)
    print(" Générateur de Scripts de règles IDS")
    print("=" * 60)
    print()
    
    # Demander le CVE à défendre
    cve = input("CVE à défendre (ex: CVE-2014-0160): ").strip()
    
    if not cve:
        cve = "CVE-2014-0160"  # Heartbleed par défaut
        print(f"Utilisation du CVE par défaut: {cve} (Heartbleed)")
    
    print()

    # Récupérer les modèles Ollama disponibles
    print("\n Récupération des modèles Ollama disponibles...")
    available_models = get_available_models()
    
    if available_models:
        print(f"\n Modèles disponibles ({len(available_models)}):")
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
                print(f"  Choix invalide, utilisation du premier modèle: {available_models[0]}")
                model_name = available_models[0]
        else:
            # Vérifier si le nom existe
            if model_choice in available_models:
                model_name = model_choice
                print(f"Modèle sélectionné: {model_name}")
            else:
                print(f"  Modèle '{model_choice}' non trouvé, utilisation de: {available_models[0]}")
                model_name = available_models[0]
    else:
        print("\n  Aucun modèle Ollama détecté. Assurez-vous qu'Ollama est lancé.")
        model_name = input("Entrez le nom du modèle à utiliser (ex: codestral): ").strip()
        if not model_name:
            model_name = "codestral"
            print("Utilisation du modèle par défaut: codestral")
    
    # Générer le script avec le LLM
    script_content = generate_ids_script(cve, model_name)
    
    if script_content:
        print("\n" + "=" * 60)
        print(" Script généré")
        print("=" * 60)
        
        # Sauvegarder le script
        filepath = save_script(cve, script_content)
        print(f"\n Script sauvegardé: {filepath}")
    else:
        print("\n Échec de la génération du script.")


if __name__ == "__main__":
    main()
