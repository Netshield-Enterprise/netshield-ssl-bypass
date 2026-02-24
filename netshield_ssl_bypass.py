#!/usr/bin/env python3
"""
NetShield SSL Bypass Tool

A comprehensive tool for detecting and bypassing SSL pinning in Android applications.

Usage:
    netshield-ssl-bypass detect <apk_path>
    netshield-ssl-bypass bypass <package_name> [--apk <apk_path>] [--spawn]
    netshield-ssl-bypass interactive
    netshield-ssl-bypass setup
    netshield-ssl-bypass list-devices
"""

import click
import yaml
import os
import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

from device_manager import DeviceManager
from apk_analyzer import SSLPinningDetector
from frida_manager import FridaManager

console = Console()

# Load configuration
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.yaml')

def load_config():
    """Load configuration from config.yaml"""
    if not os.path.exists(CONFIG_PATH):
        console.print(f"[red]✗[/red] Configuration file not found: {CONFIG_PATH}")
        sys.exit(1)
    
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """NetShield SSL Bypass Tool - Detect and bypass SSL pinning in Android apps"""
    pass


@cli.command()
def setup():
    """Verify prerequisites and setup environment"""
    console.print(Panel.fit(
        "[bold cyan]NetShield SSL Bypass Tool - Setup[/bold cyan]",
        border_style="cyan"
    ))
    
    config = load_config()
    device_mgr = DeviceManager(config)
    
    console.print("\n[bold]Checking Prerequisites...[/bold]\n")
    
    # Check ADB
    adb_ok = device_mgr.check_adb_available()
    
    # Check Frida
    try:
        import frida
        console.print(f"[green]✓[/green] Frida installed (version {frida.__version__})")
        frida_ok = True
    except ImportError:
        console.print("[red]✗[/red] Frida not installed")
        console.print("   Install with: pip install frida-tools")
        frida_ok = False
    
    # Check APKTool
    import subprocess
    try:
        result = subprocess.run(['apktool', '--version'], capture_output=True, timeout=5)
        if result.returncode == 0:
            console.print("[green]✓[/green] APKTool is available")
            apktool_ok = True
        else:
            apktool_ok = False
    except:
        console.print("[red]✗[/red] APKTool not found")
        console.print("   Install from: https://ibotpeaches.github.io/Apktool/")
        apktool_ok = False
    
    # Check for connected devices
    console.print("\n[bold]Checking Devices...[/bold]\n")
    device_mgr.display_devices()
    
    # Summary
    console.print("\n[bold]Setup Summary:[/bold]\n")
    
    all_ok = adb_ok and frida_ok and apktool_ok
    
    if all_ok:
        console.print("[bold green]✓ All prerequisites met![/bold green]")
        console.print("\n[bold]Next steps:[/bold]")
        console.print("  1. Ensure your device is rooted")
        console.print("  2. Install Frida server on the device")
        console.print("  3. Configure your proxy tool (e.g., Burp Suite)")
        console.print("  4. Install proxy CA certificate on device")
    else:
        console.print("[bold red]✗ Some prerequisites are missing[/bold red]")
        console.print("Please install the missing components and run setup again")


@cli.command()
@click.argument('apk_path', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output file for detection results (JSON)')
def detect(apk_path, output):
    """Detect SSL pinning implementation in an APK"""
    console.print(Panel.fit(
        "[bold cyan]NetShield SSL Bypass Tool - Detection[/bold cyan]",
        border_style="cyan"
    ))
    
    config = load_config()
    detector = SSLPinningDetector(config)
    
    # Analyze APK
    results = detector.analyze_apk(apk_path)
    
    # Save results if requested
    if output:
        import json
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[green]✓[/green] Results saved to: {output}")


@cli.command()
@click.argument('package_name')
@click.option('--apk', type=click.Path(exists=True), help='APK file for analysis')
@click.option('--spawn', is_flag=True, help='Spawn the app instead of attaching')
@click.option('--device', '-d', help='Specific device ID to use')
def bypass(package_name, apk, spawn, device):
    """Bypass SSL pinning for a running or spawned app"""
    console.print(Panel.fit(
        "[bold cyan]NetShield SSL Bypass Tool - Bypass[/bold cyan]",
        border_style="cyan"
    ))
    
    config = load_config()
    pinning_types = []
    
    # If APK provided, analyze it first
    if apk:
        console.print("\n[bold]Step 1: Analyzing APK[/bold]")
        detector = SSLPinningDetector(config)
        results = detector.analyze_apk(apk)
        pinning_types = results.get('pinning_types', [])
    else:
        console.print("\n[yellow]⚠[/yellow] No APK provided, using universal bypass")
        pinning_types = ['universal']
    
    # Run bypass
    console.print("\n[bold]Step 2: Running Bypass[/bold]")
    frida_mgr = FridaManager(config, device_id=device)
    
    try:
        success = frida_mgr.run_bypass(package_name, pinning_types, spawn=spawn)
        
        if success:
            console.print("\n[bold green]✓ Bypass completed successfully![/bold green]")
        else:
            console.print("\n[bold red]✗ Bypass failed[/bold red]")
            sys.exit(1)
    finally:
        frida_mgr.cleanup()


@cli.command()
def interactive():
    """Interactive mode with step-by-step guidance"""
    console.print(Panel.fit(
        "[bold cyan]NetShield SSL Bypass Tool - Interactive Mode[/bold cyan]",
        border_style="cyan"
    ))
    
    config = load_config()
    
    # Step 1: Device selection
    console.print("\n[bold cyan]Step 1: Device Setup[/bold cyan]")
    device_mgr = DeviceManager(config)
    device_mgr.display_devices()
    
    device_id = console.input("\n[bold]Enter device ID (or press Enter for auto-select): [/bold]")
    if not device_id:
        device_id = None
    
    if not device_mgr.select_device(device_id):
        console.print("[red]✗[/red] Failed to select device")
        sys.exit(1)
    
    # Step 2: Root check
    console.print("\n[bold cyan]Step 2: Checking Root Access[/bold cyan]")
    if not device_mgr.check_root_access():
        sys.exit(1)
    
    # Step 3: Frida server check
    console.print("\n[bold cyan]Step 3: Frida Server[/bold cyan]")
    if device_mgr.check_frida_server_running():
        console.print("[green]✓[/green] Frida server is running")
    else:
        console.print("[yellow]⚠[/yellow] Frida server is not running")
        
        start_frida = console.input("[bold]Would you like to start it? (y/n): [/bold]")
        if start_frida.lower() == 'y':
            frida_path = console.input("[bold]Enter path to frida-server binary: [/bold]")
            if device_mgr.push_frida_server(frida_path):
                device_mgr.start_frida_server()
    
    # Step 4: APK analysis
    console.print("\n[bold cyan]Step 4: APK Analysis[/bold cyan]")
    apk_path = console.input("[bold]Enter path to APK file (or press Enter to skip): [/bold]")
    
    pinning_types = []
    package_name = None
    
    if apk_path and os.path.exists(apk_path):
        detector = SSLPinningDetector(config)
        results = detector.analyze_apk(apk_path)
        pinning_types = results.get('pinning_types', [])
        package_name = results.get('package_name')
    
    # Step 5: Package name
    if not package_name:
        console.print("\n[bold cyan]Step 5: Target Application[/bold cyan]")
        package_name = console.input("[bold]Enter package name: [/bold]")
    else:
        console.print(f"\n[bold cyan]Step 5: Target Application[/bold cyan]")
        console.print(f"[green]✓[/green] Package name from APK: {package_name}")
    
    # Step 6: Spawn or attach
    console.print("\n[bold cyan]Step 6: Execution Mode[/bold cyan]")
    console.print("  1. Attach to running app")
    console.print("  2. Spawn app")
    
    mode = console.input("[bold]Select mode (1/2): [/bold]")
    spawn = (mode == '2')
    
    # Step 7: Run bypass
    console.print("\n[bold cyan]Step 7: Running Bypass[/bold cyan]")
    
    if not pinning_types:
        pinning_types = ['universal']
    
    frida_mgr = FridaManager(config, device_id=device_mgr.selected_device)
    
    try:
        frida_mgr.run_bypass(package_name, pinning_types, spawn=spawn)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    finally:
        frida_mgr.cleanup()


@cli.command('list-devices')
def list_devices():
    """List all connected Android devices"""
    config = load_config()
    device_mgr = DeviceManager(config)
    device_mgr.display_devices()


if __name__ == '__main__':
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {str(e)}")
        sys.exit(1)
