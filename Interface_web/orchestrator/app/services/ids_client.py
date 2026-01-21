from dataclasses import dataclass, field
from typing import Optional, List
from datetime import datetime
import paramiko
import tempfile
import os
import logging
import time
import json

logger = logging.getLogger(__name__)


@dataclass
class IDSResult:
    """Résultat d'analyse IDS."""
    detected: bool
    logs: str
    alerts: List[dict] = field(default_factory=list)
    alert_count: int = 0
    analysis_duration: float = 0.0


@dataclass
class DeployResult:
    """Résultat du déploiement de règles."""
    success: bool
    message: str
    rules_deployed: int = 0
    errors: List[str] = field(default_factory=list)


@dataclass
class IDSConfig:
    """Configuration pour la connexion SSH à la VM IDS (Suricata)."""
    host: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = None
    key_filename: Optional[str] = None
    # Chemins Suricata
    suricata_rules_dir: str = "/etc/suricata/rules"
    suricata_custom_rules_file: str = "custom.rules"
    suricata_config_path: str = "/etc/suricata/suricata.yaml"
    suricata_log_dir: str = "/var/log/suricata"
    eve_json_log: str = "eve.json"
    fast_log: str = "fast.log"
    # Commandes Suricata
    suricata_reload_cmd: str = "suricatasc -c reload-rules"
    suricata_restart_cmd: str = "systemctl restart suricata"
    suricata_status_cmd: str = "systemctl status suricata"
    suricata_test_cmd: str = "suricata -T -c /etc/suricata/suricata.yaml"
    timeout: int = 30


class IDSClient:
    """
    Client pour déployer des règles Suricata et analyser le trafic sur une VM distante via SSH.
    
    Utilisation:
        config = IDSConfig(host="192.168.1.50", username="root", password="secret")
        client = IDSClient(config)
        
        # Déployer des règles
        result = client.deploy_rules("alert tcp any any -> any 80 (msg:\\"Test\\"; sid:1000001;)")
        
        # Analyser le trafic
        analysis = client.analyze_traffic(duration=10)
    """
    
    def __init__(self, config: Optional[IDSConfig] = None):
        """
        Initialise le client avec la configuration de la VM IDS.
        
        Args:
            config: Configuration SSH de la VM IDS. Si None, utilise le mode mock.
        """
        self.config = config
        self._ssh_client: Optional[paramiko.SSHClient] = None
        self._sftp_client: Optional[paramiko.SFTPClient] = None
    
    def _connect(self) -> None:
        """Établit la connexion SSH à la VM IDS."""
        if self._ssh_client is not None:
            return
        
        self._ssh_client = paramiko.SSHClient()
        self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        connect_kwargs = {
            "hostname": self.config.host,
            "port": self.config.port,
            "username": self.config.username,
            "timeout": self.config.timeout,
        }
        
        if self.config.key_filename:
            connect_kwargs["key_filename"] = self.config.key_filename
        elif self.config.password:
            connect_kwargs["password"] = self.config.password
        
        logger.info(f"Connexion SSH à l'IDS {self.config.host}:{self.config.port}...")
        self._ssh_client.connect(**connect_kwargs)
        self._sftp_client = self._ssh_client.open_sftp()
        logger.info("Connexion SSH à l'IDS établie.")
    
    def _disconnect(self) -> None:
        """Ferme la connexion SSH."""
        if self._sftp_client:
            self._sftp_client.close()
            self._sftp_client = None
        if self._ssh_client:
            self._ssh_client.close()
            self._ssh_client = None
        logger.info("Connexion SSH à l'IDS fermée.")
    
    def _exec_command(self, command: str, timeout: Optional[int] = None) -> tuple[str, str, int]:
        """
        Exécute une commande sur la VM IDS.
        
        Returns:
            Tuple (stdout, stderr, exit_code)
        """
        timeout = timeout or self.config.timeout
        logger.debug(f"Exécution: {command}")
        
        stdin, stdout, stderr = self._ssh_client.exec_command(command, timeout=timeout)
        stdout_content = stdout.read().decode('utf-8', errors='replace')
        stderr_content = stderr.read().decode('utf-8', errors='replace')
        exit_code = stdout.channel.recv_exit_status()
        
        return stdout_content, stderr_content, exit_code
    
    def _upload_file(self, content: str, remote_path: str) -> bool:
        """Upload un fichier sur la VM IDS."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as tmp_file:
            tmp_file.write(content)
            tmp_path = tmp_file.name
        
        try:
            logger.info(f"Upload vers {remote_path}...")
            self._sftp_client.put(tmp_path, remote_path)
            return True
        except Exception as e:
            logger.error(f"Erreur upload: {e}")
            return False
        finally:
            os.unlink(tmp_path)
    
    def _read_remote_file(self, remote_path: str, tail_lines: Optional[int] = None) -> str:
        """
        Lit un fichier distant.
        
        Args:
            remote_path: Chemin du fichier sur la VM
            tail_lines: Si spécifié, lit seulement les N dernières lignes
        """
        if tail_lines:
            stdout, _, _ = self._exec_command(f"tail -n {tail_lines} {remote_path}")
            return stdout
        else:
            with self._sftp_client.open(remote_path, 'r') as f:
                return f.read().decode('utf-8', errors='replace')
    
    def _count_rules(self, rules_content: str) -> int:
        """Compte le nombre de règles dans le contenu."""
        count = 0
        for line in rules_content.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                count += 1
        return count
    
    def _validate_rules(self, rules: str) -> tuple[bool, List[str]]:
        """
        Valide la syntaxe des règles Suricata.
        
        Returns:
            Tuple (valid, errors)
        """
        errors = []
        for i, line in enumerate(rules.strip().split('\n'), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Validation basique
            if not any(line.startswith(action) for action in ['alert', 'drop', 'reject', 'pass', 'log']):
                errors.append(f"Ligne {i}: Action invalide - {line[:50]}...")
            if 'sid:' not in line:
                errors.append(f"Ligne {i}: SID manquant - {line[:50]}...")
        
        return len(errors) == 0, errors
    
    def deploy_rules(
        self, 
        rules: str, 
        append: bool = False,
        reload_suricata: bool = True,
        validate: bool = True
    ) -> DeployResult:
        """
        Déploie des règles Suricata sur la VM IDS.
        
        Args:
            rules: Contenu des règles Suricata
            append: Si True, ajoute aux règles existantes. Sinon, remplace.
            reload_suricata: Si True, recharge Suricata après déploiement
            validate: Si True, valide la syntaxe des règles avant déploiement
            
        Returns:
            DeployResult avec le statut du déploiement
        """
        # Mode mock
        if self.config is None:
            rules_count = self._count_rules(rules)
            logger.info(f"[MOCK] Déploiement simulé de {rules_count} règles")
            return DeployResult(
                success=True,
                message=f"[MOCK] {rules_count} règles déployées avec succès",
                rules_deployed=rules_count
            )
        
        try:
            self._connect()
            
            # Validation des règles
            if validate:
                is_valid, errors = self._validate_rules(rules)
                if not is_valid:
                    return DeployResult(
                        success=False,
                        message="Validation des règles échouée",
                        errors=errors
                    )
            
            rules_count = self._count_rules(rules)
            remote_rules_path = f"{self.config.suricata_rules_dir}/{self.config.suricata_custom_rules_file}"
            
            # Préparer le contenu
            header = f"# Règles personnalisées - Déployées le {datetime.now().isoformat()}\n"
            
            if append:
                # Lire les règles existantes
                try:
                    existing = self._read_remote_file(remote_rules_path)
                    rules_content = existing + "\n" + header + rules
                except FileNotFoundError:
                    rules_content = header + rules
            else:
                rules_content = header + rules
            
            # Upload des règles
            if not self._upload_file(rules_content, remote_rules_path):
                return DeployResult(
                    success=False,
                    message="Échec de l'upload des règles"
                )
            
            logger.info(f"Règles uploadées vers {remote_rules_path}")
            
            # Test de configuration Suricata
            stdout, stderr, exit_code = self._exec_command(self.config.suricata_test_cmd)
            if exit_code != 0:
                return DeployResult(
                    success=False,
                    message=f"Test de configuration Suricata échoué: {stderr}",
                    errors=[stderr]
                )
            
            # Recharger Suricata
            if reload_suricata:
                stdout, stderr, exit_code = self._exec_command(self.config.suricata_reload_cmd)
                if exit_code != 0:
                    # Essayer restart si reload échoue
                    logger.warning("Reload échoué, tentative de restart...")
                    stdout, stderr, exit_code = self._exec_command(self.config.suricata_restart_cmd)
                    if exit_code != 0:
                        return DeployResult(
                            success=False,
                            message=f"Échec du rechargement Suricata: {stderr}",
                            rules_deployed=rules_count,
                            errors=[stderr]
                        )
                
                logger.info("Suricata rechargé avec succès")
            
            return DeployResult(
                success=True,
                message=f"{rules_count} règles déployées et Suricata rechargé",
                rules_deployed=rules_count
            )
            
        except paramiko.AuthenticationException as e:
            logger.error(f"Erreur d'authentification SSH: {e}")
            return DeployResult(success=False, message=f"Erreur d'authentification: {e}")
        except paramiko.SSHException as e:
            logger.error(f"Erreur SSH: {e}")
            return DeployResult(success=False, message=f"Erreur SSH: {e}")
        except Exception as e:
            logger.error(f"Erreur inattendue: {e}")
            return DeployResult(success=False, message=f"Erreur: {e}")
        finally:
            self._disconnect()
    
    def deploy_rules_from_file(self, local_rules_path: str, **kwargs) -> DeployResult:
        """
        Déploie des règles depuis un fichier local.
        
        Args:
            local_rules_path: Chemin local du fichier de règles
            **kwargs: Arguments passés à deploy_rules()
        """
        with open(local_rules_path, 'r', encoding='utf-8') as f:
            rules_content = f.read()
        return self.deploy_rules(rules_content, **kwargs)
    
    def analyze_traffic(
        self, 
        duration: int = 10,
        check_interval: float = 1.0,
        log_lines: int = 1000
    ) -> IDSResult:
        """
        Analyse le trafic et récupère les alertes Suricata.
        
        Args:
            duration: Durée d'analyse en secondes
            check_interval: Intervalle entre les vérifications
            log_lines: Nombre de lignes de log à récupérer
            
        Returns:
            IDSResult avec les alertes détectées
        """
        # Mode mock
        if self.config is None:
            logger.info(f"[MOCK] Analyse simulée pendant {duration}s")
            return IDSResult(
                detected=True,
                logs="[MOCK] Simulated IDS detection log: attack detected.",
                alerts=[{"mock": True, "msg": "Simulated alert"}],
                alert_count=1,
                analysis_duration=float(duration)
            )
        
        try:
            self._connect()
            start_time = time.time()
            
            # Obtenir la position actuelle dans eve.json
            eve_path = f"{self.config.suricata_log_dir}/{self.config.eve_json_log}"
            stdout, _, _ = self._exec_command(f"wc -l {eve_path} 2>/dev/null || echo 0")
            try:
                initial_lines = int(stdout.strip().split()[0])
            except (ValueError, IndexError):
                initial_lines = 0
            
            logger.info(f"Début de l'analyse - Position initiale: ligne {initial_lines}")
            
            # Attendre la durée spécifiée
            time.sleep(duration)
            
            # Récupérer les nouvelles alertes
            alerts = []
            logs_content = ""
            
            # Lire les nouvelles entrées eve.json
            if initial_lines > 0:
                cmd = f"tail -n +{initial_lines + 1} {eve_path} 2>/dev/null | head -n {log_lines}"
            else:
                cmd = f"tail -n {log_lines} {eve_path} 2>/dev/null"
            
            stdout, _, _ = self._exec_command(cmd)
            
            for line in stdout.strip().split('\n'):
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get('event_type') == 'alert':
                        alerts.append({
                            'timestamp': entry.get('timestamp'),
                            'src_ip': entry.get('src_ip'),
                            'dest_ip': entry.get('dest_ip'),
                            'src_port': entry.get('src_port'),
                            'dest_port': entry.get('dest_port'),
                            'proto': entry.get('proto'),
                            'alert': entry.get('alert', {})
                        })
                except json.JSONDecodeError:
                    continue
            
            # Récupérer aussi fast.log pour les logs lisibles
            fast_log_path = f"{self.config.suricata_log_dir}/{self.config.fast_log}"
            logs_content, _, _ = self._exec_command(f"tail -n 100 {fast_log_path} 2>/dev/null")
            
            elapsed = time.time() - start_time
            detected = len(alerts) > 0
            
            logger.info(f"Analyse terminée: {len(alerts)} alertes détectées en {elapsed:.2f}s")
            
            return IDSResult(
                detected=detected,
                logs=logs_content,
                alerts=alerts,
                alert_count=len(alerts),
                analysis_duration=elapsed
            )
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse: {e}")
            return IDSResult(
                detected=False,
                logs=f"Erreur: {e}",
                analysis_duration=0.0
            )
        finally:
            self._disconnect()
    
    def get_alerts(self, limit: int = 100, since: Optional[str] = None) -> IDSResult:
        """
        Récupère les alertes Suricata récentes.
        
        Args:
            limit: Nombre maximum d'alertes à récupérer
            since: Timestamp ISO depuis lequel récupérer les alertes
            
        Returns:
            IDSResult avec les alertes
        """
        if self.config is None:
            return IDSResult(
                detected=False,
                logs="[MOCK] No alerts in mock mode",
                alerts=[],
                alert_count=0
            )
        
        try:
            self._connect()
            
            eve_path = f"{self.config.suricata_log_dir}/{self.config.eve_json_log}"
            stdout, _, _ = self._exec_command(f"tail -n {limit * 10} {eve_path} 2>/dev/null")
            
            alerts = []
            for line in stdout.strip().split('\n'):
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get('event_type') == 'alert':
                        if since and entry.get('timestamp', '') < since:
                            continue
                        alerts.append(entry)
                        if len(alerts) >= limit:
                            break
                except json.JSONDecodeError:
                    continue
            
            return IDSResult(
                detected=len(alerts) > 0,
                logs=f"Récupéré {len(alerts)} alertes",
                alerts=alerts,
                alert_count=len(alerts)
            )
            
        except Exception as e:
            logger.error(f"Erreur: {e}")
            return IDSResult(detected=False, logs=str(e))
        finally:
            self._disconnect()
    
    def clear_logs(self) -> bool:
        """Vide les logs Suricata."""
        if self.config is None:
            logger.info("[MOCK] Logs cleared")
            return True
        
        try:
            self._connect()
            
            eve_path = f"{self.config.suricata_log_dir}/{self.config.eve_json_log}"
            fast_path = f"{self.config.suricata_log_dir}/{self.config.fast_log}"
            
            self._exec_command(f"truncate -s 0 {eve_path}")
            self._exec_command(f"truncate -s 0 {fast_path}")
            
            logger.info("Logs Suricata vidés")
            return True
            
        except Exception as e:
            logger.error(f"Erreur: {e}")
            return False
        finally:
            self._disconnect()
    
    def get_status(self) -> dict:
        """Récupère le statut de Suricata."""
        if self.config is None:
            return {"status": "mock", "running": True}
        
        try:
            self._connect()
            
            stdout, stderr, exit_code = self._exec_command(self.config.suricata_status_cmd)
            running = exit_code == 0 and "active (running)" in stdout.lower()
            
            return {
                "status": "running" if running else "stopped",
                "running": running,
                "details": stdout
            }
            
        except Exception as e:
            return {"status": "error", "running": False, "error": str(e)}
        finally:
            self._disconnect()
    
    def test_connection(self) -> DeployResult:
        """Teste la connexion SSH à la VM IDS."""
        if self.config is None:
            return DeployResult(success=True, message="[MOCK] Connection test successful")
        
        try:
            self._connect()
            stdout, _, exit_code = self._exec_command("suricata --build-info | head -5")
            
            if exit_code == 0:
                return DeployResult(
                    success=True,
                    message=f"Connexion réussie. Suricata info:\n{stdout}"
                )
            else:
                return DeployResult(
                    success=False,
                    message="Connexion SSH OK mais Suricata non trouvé"
                )
                
        except Exception as e:
            return DeployResult(success=False, message=str(e))
        finally:
            self._disconnect()
    
    def __enter__(self):
        """Context manager entry."""
        if self.config:
            self._connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self._disconnect()
        return False
