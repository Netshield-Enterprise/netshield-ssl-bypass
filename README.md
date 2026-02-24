# NetShield SSL Bypass Tool

A comprehensive Python tool for detecting and bypassing SSL pinning in Android applications. Designed for security researchers and penetration testers.

## Features

- 🔍 **Automatic Detection** - Identifies multiple SSL pinning implementations:
  - OkHttp CertificatePinner
  - Flutter/Dart (libflutter.so with BoringSSL)
  - Custom X509TrustManager
  - Network Security Configuration
  - Conscrypt/BoringSSL native libraries
  - Apache HttpClient (legacy)

- 🚀 **Automated Bypass** - Frida-based runtime instrumentation:
  - Framework-specific bypass scripts
  - Universal fallback hooks
  - Support for spawned and running apps

- 💡 **User-Friendly** - Excellent guidance and feedback:
  - Interactive mode with step-by-step instructions
  - Color-coded output and progress indicators
  - Comprehensive error messages
  - Prerequisite checking

## Prerequisites

### Required Tools

1. **Python 3.8+**
2. **ADB (Android Debug Bridge)** - Part of Android SDK Platform Tools
3. **APKTool** - For APK decompilation
4. **Frida Tools** - Dynamic instrumentation framework
5. **Rooted Android Device** - With USB debugging enabled
6. **Proxy Tool** - Burp Suite, mitmproxy, or similar

### Installation

```bash
# Clone or download the tool
cd netshield-ssl-bypass

# Install Python dependencies
pip install -r requirements.txt

# Verify setup
python netshield_ssl_bypass.py setup
```

### Device Setup

1. **Root your Android device** (or use a rooted emulator like Genymotion)

2. **Enable USB debugging**:
   - Settings → About Phone → Tap "Build Number" 7 times
   - Settings → Developer Options → Enable "USB Debugging"

3. **Download Frida Server**:
   ```bash
   # Find your device architecture
   adb shell getprop ro.product.cpu.abi
   
   # Download matching frida-server from:
   # https://github.com/frida/frida/releases
   ```

4. **Install Frida Server**:
   ```bash
   # Push the file
   adb push frida-server /data/local/tmp/
   
   # Make executable and start (works on all devices)
   adb shell
   su
   chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &
   exit
   exit
   ```
   
   Or as a one-liner:
   ```bash
   adb shell "su -c 'chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &'" 2>/dev/null || \
   adb shell << 'EOF'
   ```

5. **Install Proxy CA Certificate**:
   - Export CA cert from Burp Suite (DER format)
   - Convert to PEM: `openssl x509 -inform DER -in cacert.der -out cacert.pem`
   - Install on device: Settings → Security → Install from storage

6. **Configure Proxy**:
   - Settings → Wi-Fi → Long press network → Modify → Proxy (Manual)
   - Set to your computer's IP and Burp Suite port (usually 8080)

## Usage

### Quick Start

```bash
# Interactive mode (recommended for first-time users)
python netshield_ssl_bypass.py interactive

# Detect SSL pinning in an APK
python netshield_ssl_bypass.py detect /path/to/app.apk

# Bypass SSL pinning (with APK analysis)
python netshield_ssl_bypass.py bypass com.example.app --apk /path/to/app.apk

# Bypass SSL pinning (spawn app)
python netshield_ssl_bypass.py bypass com.example.app --spawn

# List connected devices
python netshield_ssl_bypass.py list-devices
```

### Command Reference

#### `setup` - Verify Prerequisites
```bash
python netshield_ssl_bypass.py setup
```
Checks that all required tools are installed and devices are connected.

#### `detect` - Analyze APK
```bash
python netshield_ssl_bypass.py detect <apk_path> [--output results.json]
```
Performs static analysis to detect SSL pinning implementations.

**Example**:
```bash
python netshield_ssl_bypass.py detect ~/Downloads/app.apk -o results.json
```

#### `bypass` - Run SSL Bypass
```bash
python netshield_ssl_bypass.py bypass <package_name> [OPTIONS]
```

**Options**:
- `--apk <path>` - APK file for analysis (recommended)
- `--spawn` - Spawn the app instead of attaching to running instance
- `--device <id>` - Specific device ID to use

**Examples**:
```bash
# Attach to running app with APK analysis
python netshield_ssl_bypass.py bypass com.example.app --apk app.apk

# Spawn app and bypass
python netshield_ssl_bypass.py bypass com.example.app --spawn

# Use specific device
python netshield_ssl_bypass.py bypass com.example.app --device emulator-5554
```

#### `interactive` - Interactive Mode
```bash
python netshield_ssl_bypass.py interactive
```
Guided step-by-step process for complete setup and bypass.

#### `list-devices` - Show Connected Devices
```bash
python netshield_ssl_bypass.py list-devices
```

## How It Works

### Detection Phase

1. **APK Decompilation** - Uses APKTool to decompile the APK
2. **Manifest Analysis** - Checks for network security configuration
3. **Code Pattern Matching** - Searches for SSL pinning patterns in Smali code
4. **Native Library Detection** - Identifies Flutter, Conscrypt, and other native libraries
5. **Report Generation** - Provides detailed findings and recommendations

### Bypass Phase

1. **Device Connection** - Connects to Android device via Frida
2. **Process Attachment** - Attaches to running app or spawns new instance
3. **Script Selection** - Chooses appropriate bypass scripts based on detection
4. **Hook Injection** - Injects Frida scripts to hook SSL/TLS functions
5. **Runtime Monitoring** - Monitors and logs bypass activity

### Bypass Scripts

- **`universal_bypass.js`** - Hooks standard Android SSL APIs (TrustManager, SSLContext, etc.)
- **`flutter_bypass.js`** - Targets Flutter's libflutter.so and BoringSSL functions
- **`okhttp_bypass.js`** - Bypasses OkHttp3 CertificatePinner
- **`trustmanager_bypass.js`** - Hooks custom TrustManager implementations

## Troubleshooting

### Frida Server Not Running
```bash
# Check if running
adb shell "su -c 'ps | grep frida-server'"

# Start manually
adb shell "su -c '/data/local/tmp/frida-server &'"
```

### Cannot Attach to Process
- Ensure the app is running before using attach mode
- Try `--spawn` flag to launch the app fresh
- Check that package name is correct: `adb shell pm list packages | grep <name>`

### Flutter Apps Not Working
- Flutter apps are challenging due to native SSL implementation
- Try the detection first to confirm it's Flutter
- The bypass may take a few seconds to hook libflutter.so
- Consider using [reFlutter](https://github.com/Impact-I/reFlutter) for static patching as an alternative

### APKTool Errors
- Ensure you have the latest APKTool version
- Some obfuscated apps may fail to decompile - bypass can still work without detection

### Certificate Errors Persist
- Verify proxy CA certificate is installed correctly
- For Android 7+, certificate must be installed as system certificate (requires root)
- Check proxy configuration on device matches your setup

## Configuration

Edit `config.yaml` to customize:

```yaml
# Frida settings
frida:
  server_path: "/data/local/tmp/frida-server"
  default_port: 27042

# Detection patterns
detection:
  patterns:
    okhttp: ["okhttp3.CertificatePinner", ...]
    # Add custom patterns

# Logging
logging:
  level: "INFO"  # DEBUG for verbose output
  color_output: true
```

## Security & Ethics

⚠️ **IMPORTANT**: This tool is designed for **authorized security testing only**.

- Only test applications you own or have explicit permission to test
- Comply with all applicable laws and regulations
- Use responsibly and ethically
- Respect intellectual property and privacy

Unauthorized testing of applications may be illegal in your jurisdiction.

## Limitations

- Requires rooted Android device
- Some heavily obfuscated apps may be difficult to analyze
- Native code pinning may require custom hooks
- Anti-Frida detection may interfere with bypass
- iOS support not included (Android only)

## Contributing

Contributions are welcome! Areas for improvement:

- Additional bypass scripts for specific libraries
- iOS support
- Anti-anti-Frida techniques
- Automated report generation
- GUI interface

## License

MIT License - See LICENSE file for details

## Acknowledgments

- [Frida](https://frida.re/) - Dynamic instrumentation toolkit
- [APKTool](https://ibotpeaches.github.io/Apktool/) - APK decompilation
- [Androguard](https://github.com/androguard/androguard) - Android analysis
- Community Frida scripts and research

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check existing Frida SSL bypass scripts for reference
- Consult Frida documentation for advanced hooking

---

**NetShield Security** - Advanced Mobile Security Testing Tools
