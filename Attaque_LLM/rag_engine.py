"""
Module RAG pour l'enrichissement de contexte CVE
Version: 2.2 (Multi-fichiers et Robustifiée - Imports mis à jour)
"""
import json
import os
import sys

# Utilisation des nouveaux packages LangChain pour éviter les warnings de dépréciation
try:
    from langchain_chroma import Chroma
    from langchain_huggingface import HuggingFaceEmbeddings
    from langchain_core.documents import Document
except ImportError as e:
    print(f"❌ Erreur d'import : {e}")
    print("pip install langchain-huggingface langchain-chroma langchain-core")
    sys.exit(1)

# Configuration - Utilisation de chemins absolus basés sur l'emplacement du script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CHROMA_PATH = os.path.join(SCRIPT_DIR, "chroma_db")

# Liste de tous les fichiers NVD à charger (assurez-vous qu'ils sont téléchargés)
# Note: Les fichiers sont dans des sous-dossiers avec le même nom
NVD_FILES_TO_PROCESS = [
    os.path.join(SCRIPT_DIR, "CVE_info_rag", "nvdcve-2.0-2025.json", "nvdcve-2.0-2025.json"),
    os.path.join(SCRIPT_DIR, "CVE_info_rag", "nvdcve-2.0-2024.json", "nvdcve-2.0-2024.json"),
    os.path.join(SCRIPT_DIR, "CVE_info_rag", "nvdcve-2.0-2021.json", "nvdcve-2.0-2021.json"), # Pour Log4Shell
    os.path.join(SCRIPT_DIR, "CVE_info_rag", "nvdcve-2.0-2016.json", "nvdcve-2.0-2016.json"),
    os.path.join(SCRIPT_DIR, "CVE_info_rag", "nvdcve-2.0-2014.json", "nvdcve-2.0-2014.json"), # Pour Heartbleed
]

def get_description(cve_item: dict) -> str:
    """
    Récupère et concatène toutes les descriptions disponibles pour une CVE.
    Supporte les deux formats NVD (ancien et nouveau).
    """
    descriptions = []
    try:
        # NOUVEAU FORMAT NVD (2024+) : vulnerabilities[].cve.descriptions[]
        # Structure: {"cve": {"descriptions": [{"lang": "en", "value": "..."}]}}
        new_format_descs = cve_item.get('cve', {}).get('descriptions', [])
        if new_format_descs:
            for desc in new_format_descs:
                # Privilégier la description en anglais
                if desc.get('lang') == 'en' and desc.get('value'):
                    descriptions.append(desc['value'])
            # Si pas de description EN, prendre la première disponible
            if not descriptions:
                for desc in new_format_descs:
                    if desc.get('value'):
                        descriptions.append(desc['value'])
                        break
        
        # ANCIEN FORMAT NVD (avant 2024) : CVE_Items[].cve.description.description_data[]
        # Structure: {"cve": {"description": {"description_data": [{"value": "..."}]}}}
        if not descriptions:
            old_format_descs = cve_item.get('cve', {}).get('description', {}).get('description_data', [])
            for desc in old_format_descs:
                if desc.get('value'):
                    descriptions.append(desc['value'])
                    
    except Exception:
        pass
    # Retourne les descriptions concaténées ou un message par défaut si rien n'est trouvé.
    return " ".join(descriptions) if descriptions else "No description available."


def get_cve_id(cve_item: dict) -> str | None:
    """
    Récupère l'ID CVE d'un item.
    Supporte les deux formats NVD (ancien et nouveau).
    """
    try:
        # NOUVEAU FORMAT: cve.id
        cve_id = cve_item.get('cve', {}).get('id')
        if cve_id:
            return cve_id
        
        # ANCIEN FORMAT: cve.CVE_data_meta.ID
        cve_id = cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
        return cve_id
    except Exception:
        return None 

def initialize_knowledge_base():
    """
    Charge les JSON NVD de plusieurs années et crée la base vectorielle.
    Optimisé pour éviter les crashs mémoire en gérant les fichiers séparément.
    """
    if os.path.exists(CHROMA_PATH) and os.listdir(CHROMA_PATH):
        print(f"✅ Base RAG détectée dans {CHROMA_PATH}")
        return

    print("🔄 Initialisation du RAG (Ingestion des données)...")
    
    documents = []
    
    # ----------------------------------------------------
    # LOGIQUE : BOUCLE SUR TOUS LES FICHIERS NVD
    # Supporte les deux formats (ancien CVE_Items et nouveau vulnerabilities)
    # ----------------------------------------------------
    
    for filename in NVD_FILES_TO_PROCESS:
        
        if not os.path.exists(filename):
            print(f"⚠️ Fichier {filename} manquant. Ignoré. Téléchargez-le sur le site du NIST.")
            continue
            
        try:
            print(f"📂 Lecture et ingestion de {filename}...")
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f) # Si la VM a < 1Go RAM, cela peut planter pour les très gros fichiers.
            
            # Support des deux formats NVD
            cve_items = data.get("CVE_Items", []) or data.get("vulnerabilities", [])
            total_cves = len(cve_items)
            print(f"📄 {total_cves} CVEs trouvées dans {filename}.")
            
            # Limite pour éviter de surcharger ChromaDB lors du dev
            for item in cve_items: 
                try:
                    cve_id = get_cve_id(item)
                    if not cve_id:
                        continue
                        
                    description = get_description(item)
                    
                    # On ignore les CVEs rejetées ou sans description
                    if "REJECT" in description or description == "No description available.":
                        continue

                    doc = Document(
                        page_content=f"CVE: {cve_id}\nDescription: {description}",
                        metadata={"cve_id": cve_id}
                    )
                    documents.append(doc)
                except KeyError:
                    continue
            
        except MemoryError:
            print(f"❌ Erreur Mémoire (OOM): Le fichier {filename} est trop gros pour la RAM. Continue au fichier suivant.")
        except Exception as e:
            print(f"❌ Erreur inattendue lors de l'init RAG pour {filename}: {e}")
    
    # Vérification finale avant vectorisation
    if not documents:
        print("❌ Aucun document n'a pu être traité. Arrêt de l'initialisation.")
        return

    print(f"🧠 Vectorisation de {len(documents)} documents au total (patience)...")
    
    try:
        # Modèle léger pour CPU
        embedding_function = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        
        Chroma.from_documents(
            documents=documents,
            embedding=embedding_function,
            persist_directory=CHROMA_PATH
        )
        print("✅ Base de connaissances créée et sauvegardée.")
        
    except Exception as e:
        print(f"❌ Erreur lors de la vectorisation: {e}")

def get_cve_context(cve_id: str) -> str | None:
    """
    Cherche la description technique de la CVE.
    Retourne None si non trouvé.
    """
    if not os.path.exists(CHROMA_PATH):
        return None

    # Normalisation : retire les espaces et passe en majuscules (ex: "cve-..." -> "CVE-...")
    cve_id = cve_id.strip().upper()

    try:
        embedding_function = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        db = Chroma(persist_directory=CHROMA_PATH, embedding_function=embedding_function)
        
        # 1. Recherche exacte par métadonnée (plus fiable et rapide)
        results = db.get(where={"cve_id": cve_id})
        
        # Correction critique : Vérification robuste de la structure retournée
        if results and results.get("documents") and len(results["documents"]) > 0:
            doc = results["documents"][0]
            # Gestion de la compatibilité : Chroma peut renvoyer une liste ou une string
            if isinstance(doc, list): 
                return doc[0] if doc else None
            return doc # Si c'est une string directement

        # 2. Fallback : Recherche par similarité vectorielle
        # Utile si l'ID est mal formaté ou si la recherche exacte ne trouve rien pour une raison X
        docs = db.similarity_search(cve_id, k=1)
        if docs:
            print(f"ℹ️ Recherche exacte échouée, résultat similaire trouvé: {docs[0].metadata}")
            return docs[0].page_content
        
        return None
    except Exception as e:
        print(f"❌ Erreur lors de la recherche RAG pour {cve_id}: {e}")
        return None