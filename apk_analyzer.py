"""
Enhanced APK Analyzer Module with Obfuscation Resistance

Performs static analysis on Android APK files to detect SSL pinning implementations,
even when code is obfuscated with ProGuard, R8, or DexGuard.
"""

import os
import subprocess
import re
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class SSLPinningDetector:
    """Detects various SSL pinning implementations in Android APKs."""
    
    # Detection patterns for different pinning types
    PATTERNS = {
        'okhttp': [
            r'okhttp3\.CertificatePinner',
            r'CertificatePinner\.Builder',
            r'\.certificatePinner\(',
            r'\.add\(["\']sha256/',
        ],
        'trustmanager': [
            r'X509TrustManager',
            r'checkServerTrusted',
            r'TrustManagerFactory',
            r'SSLContext\.getInstance',
        ],
        'network_config': [
            r'network_security_config',
            r'<pin-set>',
            r'<trust-anchors>',
            r'<certificates\s+src=',
        ],
        'flutter': [
            r'libflutter\.so',
            r'io\.flutter',
            r'package:flutter',
        ],
        'conscrypt': [
            r'org\.conscrypt',
            r'libconscrypt',
            r'Conscrypt\.newProvider',
        ],
        'apache_http': [
            r'org\.apache\.http',
            r'SSLSocketFactory',
            r'SchemeRegistry',
        ],
        'custom_pinning': [
            r'certificate.*pin',
            r'public.*key.*pin',
            r'sha256.*fingerprint',
        ]
    }
    
    # Obfuscation-resistant indicators (strings that can't be obfuscated)
    OBFUSCATION_RESISTANT_INDICATORS = {
        'certificate_pins': [
            r'sha256/[A-Za-z0-9+/=]{40,}',  # SHA256 pin format
            r'sha1/[A-Za-z0-9+/=]{25,}',    # SHA1 pin format
        ],
        'ssl_strings': [
            r'SSL',
            r'TLS',
            r'X\.509',
            r'certificate',
            r'trustmanager',
        ],
        'okhttp_strings': [
            r'Certificate pinning failure',
            r'CertificatePinner',
        ]
    }
    
    def __init__(self, config: dict):
        """
        Initialize SSL Pinning Detector.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.apktool_path = config['apk']['apktool_path']
        # Resolve output_dir relative to the tool's directory, not CWD
        output_dir = config['apk']['output_dir']
        if not os.path.isabs(output_dir):
            tool_dir = os.path.dirname(os.path.abspath(__file__))
            output_dir = os.path.join(tool_dir, output_dir)
        self.output_dir = output_dir
        self.detection_results = {}
    
    def analyze_apk(self, apk_path: str, split_apks: List[str] = None) -> Dict:
        """
        Perform comprehensive analysis on an APK file.
        
        Args:
            apk_path: Path to the APK file
            split_apks: Optional list of split APK paths (e.g. arch-specific) for native lib detection
            
        Returns:
            Dictionary containing detection results
        """
        if not os.path.exists(apk_path):
            console.print(f"[red]✗[/red] APK file not found: {apk_path}")
            return {}
        
        console.print(f"\n[bold cyan]Analyzing APK:[/bold cyan] {os.path.basename(apk_path)}")
        
        results = {
            'apk_path': apk_path,
            'package_name': None,
            'pinning_detected': False,
            'pinning_types': [],
            'details': {},
            'native_libraries': [],
            'obfuscation_detected': False,
            'confidence_level': 'unknown',  # low, medium, high
            'recommendations': []
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Extract package name
            task = progress.add_task("Extracting package info...", total=1)
            results['package_name'] = self._get_package_name(apk_path)
            progress.update(task, completed=1)
            
            # Check for network security config
            task = progress.add_task("Checking network security config...", total=1)
            network_config = self._check_network_security_config(apk_path)
            if network_config:
                results['pinning_detected'] = True
                results['pinning_types'].append('network_security_config')
                results['details']['network_security_config'] = network_config
            progress.update(task, completed=1)
            
            # Decompile APK
            task = progress.add_task("Decompiling APK...", total=1)
            decompiled_path = self._decompile_apk(apk_path)
            progress.update(task, completed=1)
            
            if decompiled_path:
                # Check for obfuscation
                task = progress.add_task("Detecting obfuscation...", total=1)
                results['obfuscation_detected'] = self._detect_obfuscation(decompiled_path)
                progress.update(task, completed=1)
                
                # Analyze decompiled code
                task = progress.add_task("Analyzing code patterns...", total=1)
                code_analysis = self._analyze_code_patterns(decompiled_path)
                results['details'].update(code_analysis)
                progress.update(task, completed=1)
                
                # Check for native libraries (from decompiled APK + arch split APKs)
                task = progress.add_task("Checking native libraries...", total=1)
                native_libs = self._check_native_libraries(decompiled_path, split_apks=split_apks or [])
                results['native_libraries'] = native_libs
                progress.update(task, completed=1)
                
                # Obfuscation-resistant string analysis
                task = progress.add_task("Analyzing string pool (obfuscation-resistant)...", total=1)
                string_analysis = self._analyze_string_pool(apk_path)
                results['details']['string_analysis'] = string_analysis
                progress.update(task, completed=1)
                
                # Detect Flutter
                if 'libflutter.so' in native_libs:
                    results['pinning_detected'] = True
                    if 'flutter' not in results['pinning_types']:
                        results['pinning_types'].append('flutter')
                
                # Update pinning types based on code analysis
                for pinning_type, detected in code_analysis.items():
                    if isinstance(detected, dict) and detected.get('detected') and pinning_type not in results['pinning_types']:
                        results['pinning_detected'] = True
                        results['pinning_types'].append(pinning_type)
                
                # Update based on string analysis (works even with obfuscation)
                if string_analysis.get('certificate_pins_found'):
                    results['pinning_detected'] = True
                    if 'custom_pinning' not in results['pinning_types']:
                        results['pinning_types'].append('custom_pinning')
                
                # Determine confidence level
                results['confidence_level'] = self._calculate_confidence(results)
        
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)
        
        # Display results
        self._display_results(results)
        
        return results
    
    def _get_package_name(self, apk_path: str) -> Optional[str]:
        """Extract package name from APK."""
        try:
            result = subprocess.run(
                ['aapt', 'dump', 'badging', apk_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            match = re.search(r"package: name='([^']+)'", result.stdout)
            if match:
                package_name = match.group(1)
                console.print(f"[green]✓[/green] Package: {package_name}")
                return package_name
        except:
            # Fallback: try with androguard
            try:
                from androguard.core.apk import APK
                apk = APK(apk_path)
                return apk.get_package()
            except:
                pass
        
        return None
    
    def _check_network_security_config(self, apk_path: str) -> Optional[Dict]:
        """Check for network security configuration with pinning."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                # Try to find network_security_config.xml
                config_paths = [
                    'res/xml/network_security_config.xml',
                    'res/xml-v24/network_security_config.xml',
                ]
                
                for config_path in config_paths:
                    try:
                        raw_data = zip_ref.read(config_path)
                        config_data = None
                        
                        # Try plain text first (rebuilt APKs)
                        try:
                            config_data = raw_data.decode('utf-8')
                        except (UnicodeDecodeError, ValueError):
                            pass
                        
                        # Fallback: try parsing as Android binary XML
                        if config_data is None:
                            try:
                                from pyaxmlparser import APK as PyAPK
                                import tempfile
                                # Write raw data to temp file for parsing
                                with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as tmp:
                                    tmp.write(raw_data)
                                    tmp_path = tmp.name
                                try:
                                    from pyaxmlparser.axmlprinter import AXMLPrinter
                                    printer = AXMLPrinter(raw_data)
                                    config_data = printer.get_xml()
                                    if isinstance(config_data, bytes):
                                        config_data = config_data.decode('utf-8')
                                finally:
                                    os.unlink(tmp_path)
                            except ImportError:
                                console.print("[yellow]⚠[/yellow] pyaxmlparser not available for binary XML parsing")
                            except Exception:
                                pass
                        
                        if config_data is None:
                            continue
                        
                        # Check for pin-set elements
                        if '<pin-set' in config_data or 'pin digest' in config_data or 'pin-set' in config_data:
                            console.print("[yellow]⚠[/yellow] Network security config with pinning detected")
                            return {
                                'found': True,
                                'path': config_path,
                                'content_preview': config_data[:500]
                            }
                    except KeyError:
                        continue
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Could not check network config: {str(e)}")
        
        return None
    
    def _decompile_apk(self, apk_path: str) -> Optional[str]:
        """Decompile APK using apktool."""
        apk_name = Path(apk_path).stem
        output_path = os.path.join(self.output_dir, apk_name)
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Check if already decompiled
        if os.path.exists(output_path):
            console.print(f"[cyan]→[/cyan] Using existing decompiled APK at {output_path}")
            return output_path
        
        try:
            result = subprocess.run(
                [self.apktool_path, 'd', apk_path, '-o', output_path, '-f'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                console.print(f"[green]✓[/green] APK decompiled to {output_path}")
                return output_path
            else:
                console.print(f"[red]✗[/red] Decompilation failed: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            console.print("[red]✗[/red] Decompilation timed out")
            return None
        except FileNotFoundError:
            console.print("[red]✗[/red] apktool not found. Please install apktool.")
            return None
    
    def _detect_obfuscation(self, decompiled_path: str) -> bool:
        """Detect if the APK is obfuscated (ProGuard, R8, DexGuard)."""
        smali_dir = os.path.join(decompiled_path, 'smali')
        if not os.path.exists(smali_dir):
            return False
        
        total_classes = 0
        short_named_classes = 0
        max_sample = 100
        
        # Sample up to max_sample smali files across the entire tree
        for root, dirs, files in os.walk(smali_dir):
            for file in files:
                if total_classes >= max_sample:
                    break
                if file.endswith('.smali'):
                    total_classes += 1
                    # Check for single-letter class names (common in obfuscation)
                    class_name = file.replace('.smali', '')
                    if len(class_name) <= 2 and class_name.isalpha():
                        short_named_classes += 1
            if total_classes >= max_sample:
                break
        
        if total_classes > 0:
            obfuscation_ratio = short_named_classes / total_classes
            if obfuscation_ratio > 0.3:  # More than 30% short names
                console.print("[yellow]⚠[/yellow] Obfuscation detected (ProGuard/R8)")
                console.print("[cyan]→[/cyan] Using obfuscation-resistant detection methods...")
                return True
        
        return False
    
    def _analyze_string_pool(self, apk_path: str) -> Dict:
        """Analyze string pool for pinning indicators (works even with obfuscation)."""
        results = {
            'certificate_pins_found': False,
            'pin_count': 0,
            'ssl_related_strings': [],
            'suspicious_strings': []
        }
        
        try:
            # Use androguard to analyze DEX strings
            from androguard.core.apk import APK
            from androguard.core.dex import DEX
            
            apk = APK(apk_path)
            dex_files = apk.get_all_dex()
            
            for dex_data in dex_files:
                dex = DEX(dex_data)
                strings = dex.get_strings()
                
                for s in strings:
                    # Check for certificate pins (SHA256/SHA1 format)
                    if re.match(r'sha256/[A-Za-z0-9+/=]{40,}', s, re.IGNORECASE):
                        results['certificate_pins_found'] = True
                        results['pin_count'] += 1
                        results['suspicious_strings'].append(s[:50])  # Truncate
                    elif re.match(r'sha1/[A-Za-z0-9+/=]{25,}', s, re.IGNORECASE):
                        results['certificate_pins_found'] = True
                        results['pin_count'] += 1
                        results['suspicious_strings'].append(s[:50])
                    
                    # Check for SSL-related strings
                    elif any(keyword in s.lower() for keyword in ['certificate pin', 'cert pin', 'ssl pin']):
                        results['ssl_related_strings'].append(s[:50])
            
            if results['certificate_pins_found']:
                console.print(f"[yellow]⚠[/yellow] Found {results['pin_count']} certificate pins in string pool")
                console.print("[cyan]→[/cyan] SSL pinning likely present (obfuscation-resistant detection)")
            
        except ImportError:
            console.print("[yellow]⚠[/yellow] androguard not available for string analysis")
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] String pool analysis failed: {str(e)}")
        
        return results
    
    def _calculate_confidence(self, results: Dict) -> str:
        """Calculate confidence level of detection."""
        if not results['pinning_detected']:
            return 'high'  # High confidence no pinning
        
        confidence_score = 0
        
        # Native libraries are strong indicators
        if 'libflutter.so' in results.get('native_libraries', []):
            confidence_score += 3
        
        # Network security config is definitive
        if 'network_security_config' in results.get('pinning_types', []):
            confidence_score += 3
        
        # String pool analysis is obfuscation-resistant
        if results.get('details', {}).get('string_analysis', {}).get('certificate_pins_found'):
            confidence_score += 2
        
        # Code pattern matches (less reliable with obfuscation)
        if not results.get('obfuscation_detected', False):
            confidence_score += len(results.get('pinning_types', [])) * 1
        
        if confidence_score >= 5:
            return 'high'
        elif confidence_score >= 2:
            return 'medium'
        else:
            return 'low'
    
    def _analyze_code_patterns(self, decompiled_path: str) -> Dict:
        """Analyze decompiled code for SSL pinning patterns."""
        results = {}
        
        # Search in smali files
        smali_dir = os.path.join(decompiled_path, 'smali')
        if not os.path.exists(smali_dir):
            return results
        
        for pinning_type, patterns in self.PATTERNS.items():
            matches = []
            
            for root, dirs, files in os.walk(smali_dir):
                for file in files:
                    if file.endswith('.smali'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                                for pattern in patterns:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        rel_path = os.path.relpath(file_path, decompiled_path)
                                        matches.append({
                                            'file': rel_path,
                                            'pattern': pattern
                                        })
                                        break  # Found match in this file
                        except:
                            continue
            
            if matches:
                results[pinning_type] = {
                    'detected': True,
                    'matches': matches[:10]  # Limit to first 10 matches
                }
                console.print(f"[yellow]⚠[/yellow] {pinning_type.upper()} pinning detected ({len(matches)} matches)")
            else:
                results[pinning_type] = {'detected': False}
        
        return results
    
    def _check_native_libraries(self, decompiled_path: str, split_apks: List[str] = None) -> List[str]:
        """Check for native libraries in the APK and any arch split APKs."""
        native_libs = []
        
        # Check decompiled base APK lib directory
        lib_dir = os.path.join(decompiled_path, 'lib')
        if os.path.exists(lib_dir):
            for root, dirs, files in os.walk(lib_dir):
                for file in files:
                    if file.endswith('.so') and file not in native_libs:
                        native_libs.append(file)
        
        # Also scan architecture split APKs (e.g. split_config.arm64_v8a.apk)
        # These contain native libraries that aren't in base.apk
        for split_apk in (split_apks or []):
            try:
                import zipfile
                with zipfile.ZipFile(split_apk, 'r') as zf:
                    for entry in zf.namelist():
                        if entry.endswith('.so'):
                            lib_name = os.path.basename(entry)
                            if lib_name not in native_libs:
                                native_libs.append(lib_name)
                    if any(e.endswith('.so') for e in zf.namelist()):
                        console.print(f"[cyan]→[/cyan] Scanned {os.path.basename(split_apk)} for native libraries")
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] Could not scan {os.path.basename(split_apk)}: {e}")
        
        if native_libs:
            console.print(f"[cyan]→[/cyan] Found {len(native_libs)} native libraries")
            for lib in native_libs:
                if 'flutter' in lib.lower():
                    console.print(f"  [yellow]⚠[/yellow] {lib} (Flutter detected)")
                elif 'conscrypt' in lib.lower():
                    console.print(f"  [yellow]⚠[/yellow] {lib} (Conscrypt detected)")
        
        return native_libs
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate bypass recommendations based on detection results."""
        recommendations = []
        
        if not results['pinning_detected']:
            recommendations.append("No SSL pinning detected. Standard MITM proxy should work.")
            return recommendations
        
        # Add obfuscation note
        if results.get('obfuscation_detected'):
            recommendations.append(
                f"⚠ Obfuscation detected - Detection confidence: {results.get('confidence_level', 'unknown').upper()}"
            )
            recommendations.append(
                "Note: Even with obfuscation, Frida bypass works by hooking Android framework APIs at runtime"
            )
        
        for pinning_type in results['pinning_types']:
            if pinning_type == 'flutter':
                recommendations.append(
                    "Flutter app detected: Use flutter_bypass.js Frida script targeting libflutter.so"
                )
            elif pinning_type == 'okhttp':
                recommendations.append(
                    "OkHttp pinning detected: Use okhttp_bypass.js to hook CertificatePinner"
                )
            elif pinning_type == 'network_security_config':
                recommendations.append(
                    "Network security config: Modify APK to remove pin-set or use Frida bypass"
                )
            elif pinning_type == 'trustmanager':
                recommendations.append(
                    "Custom TrustManager: Use trustmanager_bypass.js to hook verification methods"
                )
            elif pinning_type == 'conscrypt':
                recommendations.append(
                    "Conscrypt detected: May require native library hooking"
                )
            elif pinning_type == 'custom_pinning':
                recommendations.append(
                    "Custom pinning detected via string analysis: Use universal_bypass.js"
                )
        
        recommendations.append(
            "Try universal_bypass.js as a fallback for comprehensive hooking"
        )
        
        return recommendations
    
    def _display_results(self, results: Dict) -> None:
        """Display analysis results in a formatted way."""
        console.print("\n" + "="*70)
        console.print("[bold cyan]Analysis Results[/bold cyan]")
        console.print("="*70)
        
        if results['package_name']:
            console.print(f"\n[bold]Package:[/bold] {results['package_name']}")
        
        if results.get('obfuscation_detected'):
            console.print(f"[bold yellow]Obfuscation:[/bold yellow] Detected (ProGuard/R8/DexGuard)")
        
        if results['pinning_detected']:
            console.print(f"\n[bold red]SSL Pinning Detected:[/bold red] Yes")
            console.print(f"[bold]Pinning Types:[/bold] {', '.join(results['pinning_types'])}")
            console.print(f"[bold]Confidence Level:[/bold] {results.get('confidence_level', 'unknown').upper()}")
        else:
            console.print(f"\n[bold green]SSL Pinning Detected:[/bold green] No")
        
        # Show string analysis results if obfuscation detected
        if results.get('obfuscation_detected'):
            string_analysis = results.get('details', {}).get('string_analysis', {})
            if string_analysis.get('certificate_pins_found'):
                console.print(f"\n[bold]String Pool Analysis (Obfuscation-Resistant):[/bold]")
                console.print(f"  • Certificate pins found: {string_analysis.get('pin_count', 0)}")
        
        if results['native_libraries']:
            console.print(f"\n[bold]Native Libraries:[/bold] {len(results['native_libraries'])}")
            for lib in results['native_libraries'][:5]:
                console.print(f"  • {lib}")
            if len(results['native_libraries']) > 5:
                console.print(f"  ... and {len(results['native_libraries']) - 5} more")
        
        if results['recommendations']:
            console.print("\n[bold cyan]Recommendations:[/bold cyan]")
            for i, rec in enumerate(results['recommendations'], 1):
                console.print(f"  {i}. {rec}")
        
        console.print("\n" + "="*70 + "\n")
