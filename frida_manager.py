"""
Frida Manager Module

Handles Frida script injection, process management, and bypass execution.
"""

import frida
import sys
import os
import time
from typing import Optional, List, Dict
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

console = Console()


class FridaManager:
    """Manages Frida operations for SSL pinning bypass."""
    
    def __init__(self, config: dict, device_id: Optional[str] = None):
        """
        Initialize Frida Manager.
        
        Args:
            config: Configuration dictionary
            device_id: Specific device ID to connect to
        """
        self.config = config
        self.device_id = device_id
        self.device = None
        self.session = None
        self.script = None
        self.script_logs = []
    
    def connect_device(self) -> bool:
        """
        Connect to Android device via Frida.
        
        Returns:
            bool: True if connected successfully
        """
        try:
            if self.device_id:
                self.device = frida.get_device(self.device_id)
            else:
                # Get USB device
                self.device = frida.get_usb_device(timeout=10)
            
            console.print(f"[green]✓[/green] Connected to device: {self.device.name}")
            return True
            
        except frida.TimedOutError:
            console.print("[red]✗[/red] Connection timed out. Is Frida server running?")
            return False
        except frida.ServerNotRunningError:
            console.print("[red]✗[/red] Frida server is not running on the device")
            console.print("\n[bold]To start Frida server:[/bold]")
            console.print("  1. adb shell")
            console.print("  2. su")
            console.print("  3. /data/local/tmp/frida-server &")
            return False
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to connect: {str(e)}")
            return False
    
    def list_processes(self, filter_str: Optional[str] = None) -> List[Dict]:
        """
        List running processes on the device.
        
        Args:
            filter_str: Optional filter string for process names
            
        Returns:
            List of process dictionaries
        """
        if not self.device:
            console.print("[red]✗[/red] Not connected to device")
            return []
        
        try:
            processes = self.device.enumerate_processes()
            
            if filter_str:
                processes = [p for p in processes if filter_str.lower() in p.name.lower()]
            
            return [{'pid': p.pid, 'name': p.name} for p in processes]
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to list processes: {str(e)}")
            return []
    
    def attach_to_process(self, package_name: str) -> bool:
        """
        Attach to a running process.
        
        Args:
            package_name: Package name or PID of the process
            
        Returns:
            bool: True if attached successfully
        """
        if not self.device:
            console.print("[red]✗[/red] Not connected to device")
            return False
        
        try:
            # Try to attach by package name first
            try:
                self.session = self.device.attach(package_name)
                console.print(f"[green]✓[/green] Attached to process: {package_name}")
                return True
            except:
                # Try as PID
                pid = int(package_name)
                self.session = self.device.attach(pid)
                console.print(f"[green]✓[/green] Attached to PID: {pid}")
                return True
                
        except frida.ProcessNotFoundError:
            console.print(f"[red]✗[/red] Process not found: {package_name}")
            console.print("[yellow]⚠[/yellow] Make sure the app is running")
            return False
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to attach: {str(e)}")
            return False
    
    def spawn_process(self, package_name: str) -> bool:
        """
        Spawn a new process and attach to it.
        
        Args:
            package_name: Package name to spawn
            
        Returns:
            bool: True if spawned successfully
        """
        if not self.device:
            console.print("[red]✗[/red] Not connected to device")
            return False
        
        try:
            console.print(f"[cyan]→[/cyan] Spawning {package_name}...")
            
            pid = self.device.spawn([package_name])
            self.session = self.device.attach(pid)
            
            console.print(f"[green]✓[/green] Spawned and attached to {package_name} (PID: {pid})")
            
            # Resume the process after script injection
            # (will be called after load_script)
            self.spawned_pid = pid
            
            return True
            
        except frida.NotSupportedError:
            console.print(f"[red]✗[/red] Cannot spawn {package_name}")
            return False
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to spawn: {str(e)}")
            return False
    
    def load_script(self, script_path: str) -> bool:
        """
        Load and inject a Frida script.
        
        Args:
            script_path: Path to the JavaScript file
            
        Returns:
            bool: True if loaded successfully
        """
        if not self.session:
            console.print("[red]✗[/red] No active session")
            return False
        
        if not os.path.exists(script_path):
            console.print(f"[red]✗[/red] Script not found: {script_path}")
            return False
        
        try:
            with open(script_path, 'r') as f:
                script_code = f.read()
            
            console.print(f"[cyan]→[/cyan] Loading script: {os.path.basename(script_path)}")
            
            self.script = self.session.create_script(script_code)
            self.script.on('message', self._on_message)
            self.script.load()
            
            console.print(f"[green]✓[/green] Script loaded successfully")
            
            # Resume if we spawned the process
            if hasattr(self, 'spawned_pid'):
                self.device.resume(self.spawned_pid)
                console.print(f"[green]✓[/green] Process resumed")
                delattr(self, 'spawned_pid')
            
            return True
            
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to load script: {str(e)}")
            return False
    
    def load_multiple_scripts(self, script_paths: List[str]) -> bool:
        """
        Load multiple Frida scripts in order.
        
        Args:
            script_paths: List of script paths
            
        Returns:
            bool: True if all loaded successfully
        """
        if not self.session:
            console.print("[red]✗[/red] No active session")
            return False
        
        combined_script = ""
        
        for script_path in script_paths:
            if not os.path.exists(script_path):
                console.print(f"[yellow]⚠[/yellow] Script not found: {script_path}")
                continue
            
            with open(script_path, 'r') as f:
                combined_script += f"\n// === {os.path.basename(script_path)} ===\n"
                combined_script += f.read()
                combined_script += "\n\n"
        
        if not combined_script:
            console.print("[red]✗[/red] No valid scripts to load")
            return False
        
        try:
            console.print(f"[cyan]→[/cyan] Loading {len(script_paths)} scripts...")
            
            self.script = self.session.create_script(combined_script)
            self.script.on('message', self._on_message)
            self.script.load()
            
            console.print(f"[green]✓[/green] All scripts loaded successfully")
            
            # Resume if we spawned the process
            if hasattr(self, 'spawned_pid'):
                self.device.resume(self.spawned_pid)
                console.print(f"[green]✓[/green] Process resumed")
                delattr(self, 'spawned_pid')
            
            return True
            
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to load scripts: {str(e)}")
            return False
    
    def _on_message(self, message: dict, data: bytes) -> None:
        """
        Handle messages from Frida script.
        
        Args:
            message: Message dictionary
            data: Optional binary data
        """
        if message['type'] == 'send':
            payload = message.get('payload', '')
            self.script_logs.append(payload)
            
            # Color code based on content
            if '[+]' in str(payload):
                console.print(f"[green]{payload}[/green]")
            elif '[-]' in str(payload):
                console.print(f"[red]{payload}[/red]")
            elif '[*]' in str(payload):
                console.print(f"[cyan]{payload}[/cyan]")
            else:
                console.print(payload)
                
        elif message['type'] == 'error':
            error_msg = message.get('description', 'Unknown error')
            console.print(f"[red]Script Error:[/red] {error_msg}")
            self.script_logs.append(f"ERROR: {error_msg}")
    
    def run_bypass(self, package_name: str, pinning_types: List[str], spawn: bool = False) -> bool:
        """
        Run SSL pinning bypass for a specific app.
        
        Args:
            package_name: Package name of the app
            pinning_types: List of detected pinning types
            spawn: Whether to spawn the app or attach to running instance
            
        Returns:
            bool: True if bypass was successful
        """
        console.print("\n[bold cyan]Starting SSL Pinning Bypass[/bold cyan]")
        console.print("="*70)
        
        # Connect to device
        if not self.connect_device():
            return False
        
        # Attach or spawn
        if spawn:
            if not self.spawn_process(package_name):
                return False
        else:
            if not self.attach_to_process(package_name):
                return False
        
        # Select appropriate scripts based on detected pinning types
        scripts_dir = self.config['bypass']['scripts_dir']
        scripts_to_load = []
        
        # Add specific scripts for detected pinning types
        for pinning_type in pinning_types:
            if pinning_type == 'flutter':
                scripts_to_load.append(os.path.join(scripts_dir, 'flutter_bypass.js'))
            elif pinning_type == 'okhttp':
                scripts_to_load.append(os.path.join(scripts_dir, 'okhttp_bypass.js'))
            elif pinning_type in ['trustmanager', 'custom_pinning']:
                scripts_to_load.append(os.path.join(scripts_dir, 'trustmanager_bypass.js'))
        
        # Always add universal bypass as fallback
        scripts_to_load.append(os.path.join(scripts_dir, 'universal_bypass.js'))
        
        # Remove duplicates while preserving order
        scripts_to_load = list(dict.fromkeys(scripts_to_load))
        
        console.print(f"\n[bold]Scripts to inject:[/bold]")
        for script in scripts_to_load:
            console.print(f"  • {os.path.basename(script)}")
        
        # Load scripts
        if not self.load_multiple_scripts(scripts_to_load):
            return False
        
        console.print("\n[bold green]✓ Bypass active![/bold green]")
        console.print("\n[bold]Next steps:[/bold]")
        console.print("  1. Configure your device proxy to point to Burp Suite")
        console.print("  2. Use the app and monitor traffic in Burp")
        console.print("  3. Press Ctrl+C to stop the bypass\n")
        
        # Keep script running
        try:
            console.print("[cyan]Monitoring... (Press Ctrl+C to stop)[/cyan]\n")
            sys.stdin.read()
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopping bypass...[/yellow]")
        
        return True
    
    def cleanup(self) -> None:
        """Clean up Frida resources."""
        if self.script:
            self.script.unload()
        if self.session:
            self.session.detach()
        
        console.print("[green]✓[/green] Cleanup complete")
