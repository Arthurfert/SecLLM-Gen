from dataclasses import dataclass
from typing import Optional
import paramiko
import tempfile
import os
import logging

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    success: bool
    logs: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1


@dataclass
class VMConfig:
    """Configuration pour la connexion SSH à la VM."""
    host: str = "192.168.10.5"
    port: int = 22
    username: str = "root"
    password: Optional[str] = None
    key_filename: Optional[str] = None
    remote_scripts_dir: str = "/tmp/attack_scripts"
    python_executable: str = "python3"
    timeout: int = 30


class AttackerClient:
    """
    Client pour envoyer et exécuter des scripts Python sur une VM distante via SSH.
    
    Utilisation:
        config = VMConfig(host="192.168.1.100", username="attacker", password="secret")
        client = AttackerClient(config)
        result = client.run_script("print('Hello from VM!')")
    """
    
    def __init__(self, config: Optional[VMConfig] = None):
        """
        Initialise le client avec la configuration de la VM.
        
        Args:
            config: Configuration SSH de la VM. Si None, utilise le mode mock.
        """
        self.config = config
        self._ssh_client: Optional[paramiko.SSHClient] = None
        self._sftp_client: Optional[paramiko.SFTPClient] = None
    
    def _connect(self) -> None:
        """Établit la connexion SSH à la VM."""
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
        
        logger.info(f"Connexion SSH à {self.config.host}:{self.config.port}...")
        self._ssh_client.connect(**connect_kwargs)
        self._sftp_client = self._ssh_client.open_sftp()
        logger.info("Connexion SSH établie.")
    
    def _disconnect(self) -> None:
        """Ferme la connexion SSH."""
        if self._sftp_client:
            self._sftp_client.close()
            self._sftp_client = None
        if self._ssh_client:
            self._ssh_client.close()
            self._ssh_client = None
        logger.info("Connexion SSH fermée.")
    
    def _ensure_remote_dir(self) -> None:
        """S'assure que le répertoire distant pour les scripts existe."""
        try:
            self._sftp_client.stat(self.config.remote_scripts_dir)
        except FileNotFoundError:
            logger.info(f"Création du répertoire distant: {self.config.remote_scripts_dir}")
            self._ssh_client.exec_command(f"mkdir -p {self.config.remote_scripts_dir}")
    
    def _upload_script(self, script_content: str, script_name: str) -> str:
        """
        Upload le script sur la VM.
        
        Args:
            script_content: Contenu du script Python
            script_name: Nom du fichier script
            
        Returns:
            Chemin complet du script sur la VM
        """
        self._ensure_remote_dir()
        remote_path = f"{self.config.remote_scripts_dir}/{script_name}"
        
        # Créer un fichier temporaire local
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp_file:
            tmp_file.write(script_content)
            tmp_path = tmp_file.name
        
        try:
            logger.info(f"Upload du script vers {remote_path}...")
            self._sftp_client.put(tmp_path, remote_path)
            # Rendre le script exécutable
            self._ssh_client.exec_command(f"chmod +x {remote_path}")
            logger.info("Script uploadé avec succès.")
        finally:
            os.unlink(tmp_path)
        
        return remote_path
    
    def _execute_remote_script(self, remote_path: str, timeout: Optional[int] = None) -> ExecutionResult:
        """
        Exécute un script sur la VM distante.
        
        Args:
            remote_path: Chemin du script sur la VM
            timeout: Timeout d'exécution en secondes
            
        Returns:
            ExecutionResult avec les logs d'exécution
        """
        timeout = timeout or self.config.timeout
        command = f"{self.config.python_executable} {remote_path}"
        
        logger.info(f"Exécution de la commande: {command}")
        stdin, stdout, stderr = self._ssh_client.exec_command(command, timeout=timeout)
        
        stdout_content = stdout.read().decode('utf-8', errors='replace')
        stderr_content = stderr.read().decode('utf-8', errors='replace')
        exit_code = stdout.channel.recv_exit_status()
        
        success = exit_code == 0
        logs = f"=== STDOUT ===\n{stdout_content}\n=== STDERR ===\n{stderr_content}"
        
        logger.info(f"Exécution terminée avec code de sortie: {exit_code}")
        
        return ExecutionResult(
            success=success,
            logs=logs,
            stdout=stdout_content,
            stderr=stderr_content,
            exit_code=exit_code
        )
    
    def _cleanup_remote_script(self, remote_path: str) -> None:
        """Supprime le script distant après exécution."""
        try:
            self._sftp_client.remove(remote_path)
            logger.info(f"Script distant supprimé: {remote_path}")
        except Exception as e:
            logger.warning(f"Impossible de supprimer le script distant: {e}")
    
    def run_script(
        self, 
        script: str, 
        script_name: Optional[str] = None,
        cleanup: bool = True,
        timeout: Optional[int] = None
    ) -> ExecutionResult:
        """
        Envoie et exécute un script Python sur la VM distante.
        
        Args:
            script: Contenu du script Python à exécuter
            script_name: Nom du fichier script (généré automatiquement si non fourni)
            cleanup: Si True, supprime le script après exécution
            timeout: Timeout d'exécution en secondes
            
        Returns:
            ExecutionResult contenant le succès, les logs, stdout, stderr et le code de sortie
        """
        # Mode mock si pas de configuration
        if self.config is None:
            logger.info("Mode mock activé - simulation de l'exécution")
            return ExecutionResult(
                success=True,
                logs="[MOCK] Simulated attack execution logs...\n" + script[:200],
                stdout="[MOCK] Execution simulated",
                stderr="",
                exit_code=0
            )
        
        # Générer un nom de script si non fourni
        if script_name is None:
            import uuid
            script_name = f"attack_script_{uuid.uuid4().hex[:8]}.py"
        
        remote_path = None
        try:
            self._connect()
            remote_path = self._upload_script(script, script_name)
            result = self._execute_remote_script(remote_path, timeout)
            
            if cleanup and remote_path:
                self._cleanup_remote_script(remote_path)
            
            return result
            
        except paramiko.AuthenticationException as e:
            logger.error(f"Erreur d'authentification SSH: {e}")
            return ExecutionResult(
                success=False,
                logs=f"Erreur d'authentification SSH: {e}",
                stderr=str(e),
                exit_code=-1
            )
        except paramiko.SSHException as e:
            logger.error(f"Erreur SSH: {e}")
            return ExecutionResult(
                success=False,
                logs=f"Erreur SSH: {e}",
                stderr=str(e),
                exit_code=-1
            )
        except TimeoutError as e:
            logger.error(f"Timeout lors de l'exécution: {e}")
            return ExecutionResult(
                success=False,
                logs=f"Timeout lors de l'exécution du script: {e}",
                stderr=str(e),
                exit_code=-1
            )
        except Exception as e:
            logger.error(f"Erreur inattendue: {e}")
            return ExecutionResult(
                success=False,
                logs=f"Erreur inattendue: {e}",
                stderr=str(e),
                exit_code=-1
            )
        finally:
            self._disconnect()
    
    def run_script_from_file(
        self, 
        local_script_path: str,
        cleanup: bool = True,
        timeout: Optional[int] = None
    ) -> ExecutionResult:
        """
        Envoie et exécute un fichier script Python existant sur la VM distante.
        
        Args:
            local_script_path: Chemin local du script Python
            cleanup: Si True, supprime le script après exécution
            timeout: Timeout d'exécution en secondes
            
        Returns:
            ExecutionResult contenant le succès et les logs d'exécution
        """
        with open(local_script_path, 'r', encoding='utf-8') as f:
            script_content = f.read()
        
        script_name = os.path.basename(local_script_path)
        return self.run_script(script_content, script_name, cleanup, timeout)
    
    def test_connection(self) -> ExecutionResult:
        """
        Teste la connexion SSH à la VM.
        
        Returns:
            ExecutionResult indiquant si la connexion est réussie
        """
        return self.run_script(
            "import sys; print(f'Python {sys.version} on {sys.platform}')",
            script_name="test_connection.py",
            cleanup=True
        )
    
    def __enter__(self):
        """Context manager entry."""
        if self.config:
            self._connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self._disconnect()
        return False
