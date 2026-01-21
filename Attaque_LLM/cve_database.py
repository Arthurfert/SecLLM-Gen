"""
Base de données CVE avec mapping vers ports et scripts NSE
"""

# Mapping CVE vers ports et services vulnérables
CVE_PORT_MAPPING = {
    "CVE-2014-0160": {
        "ports": [443, 8443, 4433], 
        "service": "OpenSSL (Heartbleed)",
        "nse_script": "ssl-heartbleed"
    },
    "HEARTBLEED": {
        "ports": [443, 8443, 4433], 
        "service": "OpenSSL (Heartbleed)",
        "nse_script": "ssl-heartbleed"
    },
    "CVE-2017-0144": {
        "ports": [445, 139], 
        "service": "SMB (EternalBlue)",
        "nse_script": "smb-vuln-ms17-010"
    },
    "CVE-2021-44228": {
        "ports": [8080, 443, 9200], 
        "service": "Log4j",
        "nse_script": None
    },
    "LOG4SHELL": {
        "ports": [8080, 443, 9200], 
        "service": "Log4j",
        "nse_script": None
    },
    "CVE-2017-5638": {
        "ports": [8080, 80, 443], 
        "service": "Apache Struts",
        "nse_script": "http-vuln-cve2017-5638"
    },
    "CVE-2019-0708": {
        "ports": [3389], 
        "service": "RDP (BlueKeep)",
        "nse_script": "rdp-vuln-ms12-020"
    },
    "CVE-2014-6271": {
        "ports": [80, 443, 8080], 
        "service": "Bash (Shellshock)",
        "nse_script": "http-shellshock"
    },
    "CVE-2012-1823": {
        "ports": [80, 443, 8080], 
        "service": "PHP-CGI",
        "nse_script": None
    },
    "CVE-2015-1427": {
        "ports": [9200], 
        "service": "Elasticsearch",
        "nse_script": None
    },
}


def get_cve_info(cve: str) -> dict:
    """
    Récupère les informations associées à une CVE.
    
    Args:
        cve: L'identifiant CVE
    
    Returns:
        dict: Dictionnaire avec les ports, service et script NSE, ou None si non trouvé
    """
    return CVE_PORT_MAPPING.get(cve.upper())


def is_heartbleed(cve: str) -> bool:
    """
    Vérifie si la CVE correspond à Heartbleed.
    
    Args:
        cve: L'identifiant CVE
    
    Returns:
        bool: True si c'est Heartbleed, False sinon
    """
    return cve.upper() in ["CVE-2014-0160", "HEARTBLEED"]


def list_supported_cves() -> list:
    """
    Retourne la liste des CVE supportées.
    
    Returns:
        list: Liste des identifiants CVE
    """
    return list(CVE_PORT_MAPPING.keys())
