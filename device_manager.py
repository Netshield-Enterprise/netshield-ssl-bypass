"""
Device Manager Module

Handles Android device connection, Frida server management, and device configuration.
"""

import subprocess
import os
import platform
import time
from typing import Optional, List, Dict
from rich.console import Console
from rich.table import Table

console = Console()


class DeviceManager:
    """Manages Android device connections and Frida server operations."""
    
    def __init__(self, config: dict):
        """
        Initialize DeviceManager.
        
        Args:
            config: Configuration dictionary from config.yaml
        """
        self.config = config
        self.adb_path = config['device']['adb_path']
        self.frida_server_path = config['frida']['server_path']
        self.frida_port = config['frida']['default_port']
        self.selected_device = None
    
    def check_adb_available(self) -> bool:
        """
        Check if ADB is available in the system.
        
        Returns:
            bool: True if ADB is available, False otherwise
        """
        try:
            result = subprocess.run(
                [self.adb_path, 'version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                console.print("[green]✓[/green] ADB is available")
                return True
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            console.print("[red]✗[/red] ADB not found. Please install Android SDK Platform Tools.")
            return False
    
    def list_devices(self) -> List[Dict[str, str]]:
        """
        List all connected Android devices.
        
        Returns:
            List of device dictionaries with 'id' and 'status' keys
        """
        try:
            result = subprocess.run(
                [self.adb_path, 'devices'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            devices = []
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            
            for line in lines:
                if line.strip():
                    parts = line.split('\t')
                    if len(parts) == 2:
                        devices.append({
                            'id': parts[0],
                            'status': parts[1]
                        })
            
            return devices
        except subprocess.TimeoutExpired:
            console.print("[red]✗[/red] ADB command timed out")
            return []
    
    def display_devices(self) -> None:
        """Display connected devices in a formatted table."""
        devices = self.list_devices()
        
        if not devices:
            console.print("[yellow]⚠[/yellow] No devices connected")
            console.print("\n[bold]Please ensure:[/bold]")
            console.print("  1. Device is connected via USB")
            console.print("  2. USB debugging is enabled")
            console.print("  3. You've authorized the computer on the device")
            return
        
        table = Table(title="Connected Android Devices")
        table.add_column("Device ID", style="cyan")
        table.add_column("Status", style="green")
        
        for device in devices:
            table.add_row(device['id'], device['status'])
        
        console.print(table)
    
    def select_device(self, device_id: Optional[str] = None) -> bool:
        """
        Select a device to work with.
        
        Args:
            device_id: Specific device ID, or None to auto-select
            
        Returns:
            bool: True if device selected successfully
        """
        devices = self.list_devices()
        
        if not devices:
            console.print("[red]✗[/red] No devices available")
            return False
        
        if device_id:
            # Check if specified device exists
            if any(d['id'] == device_id for d in devices):
                self.selected_device = device_id
                console.print(f"[green]✓[/green] Selected device: {device_id}")
                return True
            else:
                console.print(f"[red]✗[/red] Device {device_id} not found")
                return False
        else:
            # Auto-select first device
            self.selected_device = devices[0]['id']
            console.print(f"[green]✓[/green] Auto-selected device: {self.selected_device}")
            return True
    
    def check_root_access(self) -> bool:
        """
        Check if the selected device has root access.
        
        Returns:
            bool: True if device is rooted
        """
        if not self.selected_device:
            console.print("[red]✗[/red] No device selected")
            return False
        
        try:
            # Use shell piping for compatibility with all su implementations
            result = subprocess.run(
                [self.adb_path, '-s', self.selected_device, 'shell'],
                input='su\nid\nexit\n',
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and 'uid=0' in result.stdout:
                console.print("[green]✓[/green] Device has root access")
                return True
            else:
                console.print("[red]✗[/red] Device does not have root access")
                console.print("\n[bold]Root access is required for this tool.[/bold]")
                console.print("Please root your device or use a rooted emulator.")
                return False
        except subprocess.TimeoutExpired:
            console.print("[red]✗[/red] Root check timed out")
            return False
    
    def push_frida_server(self, local_path: str) -> bool:
        """
        Push Frida server to the device.
        
        Args:
            local_path: Path to local frida-server binary
            
        Returns:
            bool: True if successful
        """
        if not self.selected_device:
            console.print("[red]✗[/red] No device selected")
            return False
        
        if not os.path.exists(local_path):
            console.print(f"[red]✗[/red] Frida server not found at: {local_path}")
            return False
        
        console.print(f"[cyan]→[/cyan] Pushing Frida server to device...")
        
        try:
            # Push the file
            result = subprocess.run(
                [self.adb_path, '-s', self.selected_device, 'push', 
                 local_path, self.frida_server_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                console.print(f"[red]✗[/red] Failed to push Frida server: {result.stderr}")
                return False
            
            # Make it executable using shell piping (compatible with all su implementations)
            result = subprocess.run(
                [self.adb_path, '-s', self.selected_device, 'shell'],
                input=f'su\nchmod 755 {self.frida_server_path}\nexit\n',
                capture_output=True,
                text=True,
                timeout=10
            )
            
            console.print("[green]✓[/green] Frida server pushed successfully")
            return True
            
        except subprocess.TimeoutExpired:
            console.print("[red]✗[/red] Push operation timed out")
            return False
    
    def start_frida_server(self) -> bool:
        """
        Start Frida server on the device.
        
        Returns:
            bool: True if started successfully
        """
        if not self.selected_device:
            console.print("[red]✗[/red] No device selected")
            return False
        
        console.print("[cyan]→[/cyan] Starting Frida server...")
        
        try:
            # Kill any existing frida-server processes using shell piping
            subprocess.run(
                [self.adb_path, '-s', self.selected_device, 'shell'],
                input='su\nkillall frida-server 2>/dev/null\nexit\n',
                capture_output=True,
                text=True,
                timeout=5
            )
            
            time.sleep(1)
            
            # Start frida-server in background using nohup for persistence
            subprocess.Popen(
                [self.adb_path, '-s', self.selected_device, 'shell'],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True
            ).communicate(input=f'su\nnohup {self.frida_server_path} &\nexit\n', timeout=3)
            
            time.sleep(2)
            
            # Verify it's running
            if self.check_frida_server_running():
                console.print("[green]✓[/green] Frida server started successfully")
                return True
            else:
                console.print("[red]✗[/red] Frida server failed to start")
                return False
                
        except Exception as e:
            console.print(f"[red]✗[/red] Error starting Frida server: {str(e)}")
            return False
    
    def check_frida_server_running(self) -> bool:
        """
        Check if Frida server is running on the device.
        
        Returns:
            bool: True if running
        """
        if not self.selected_device:
            return False
        
        try:
            # Use shell piping for compatibility
            result = subprocess.run(
                [self.adb_path, '-s', self.selected_device, 'shell'],
                input='su\nps | grep frida-server\nexit\n',
                capture_output=True,
                text=True,
                timeout=5
            )
            
            return 'frida-server' in result.stdout
        except:
            return False
    
    def setup_port_forwarding(self) -> bool:
        """
        Setup ADB port forwarding for Frida.
        
        Returns:
            bool: True if successful
        """
        if not self.selected_device:
            console.print("[red]✗[/red] No device selected")
            return False
        
        try:
            result = subprocess.run(
                [self.adb_path, '-s', self.selected_device, 'forward', 
                 f'tcp:{self.frida_port}', f'tcp:{self.frida_port}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                console.print(f"[green]✓[/green] Port forwarding setup: {self.frida_port}")
                return True
            return False
        except:
            return False
    
    def install_certificate(self, cert_path: str) -> bool:
        """
        Guide user through certificate installation.
        
        Args:
            cert_path: Path to CA certificate file
            
        Returns:
            bool: True if user confirms installation
        """
        console.print("\n[bold cyan]Certificate Installation Guide:[/bold cyan]")
        console.print("\n1. Push certificate to device:")
        console.print(f"   [yellow]adb push {cert_path} /sdcard/[/yellow]")
        console.print("\n2. On your device:")
        console.print("   • Go to Settings → Security → Install from storage")
        console.print("   • Select the certificate file")
        console.print("   • Name it (e.g., 'BurpSuite CA')")
        console.print("   • Confirm installation")
        console.print("\n3. For system certificate (requires root):")
        console.print("   [yellow]# Convert to system format and push[/yellow]")
        
        response = console.input("\n[bold]Have you installed the certificate? (y/n): [/bold]")
        return response.lower() == 'y'
