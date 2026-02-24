/**
 * Flutter SSL Pinning Bypass
 * 
 * Bypasses SSL pinning in Flutter applications by hooking into libflutter.so.
 * Targets BoringSSL certificate verification functions.
 */

console.log("[*] Flutter SSL Bypass Script Loaded");

// Function to find and hook ssl_crypto_x509_session_verify_cert_chain
function hookFlutterSSL() {
    var moduleName = "libflutter.so";
    var module = Process.findModuleByName(moduleName);

    if (!module) {
        console.log("[-] libflutter.so not found");
        return false;
    }

    console.log("[+] libflutter.so found at: " + module.base);
    console.log("[+] Module size: " + module.size);

    // Try to find ssl_crypto_x509_session_verify_cert_chain (newer Flutter versions)
    var targetFunction = "ssl_crypto_x509_session_verify_cert_chain";
    var targetAddress = Module.findExportByName(moduleName, targetFunction);

    if (targetAddress) {
        console.log("[+] Found " + targetFunction + " at: " + targetAddress);

        Interceptor.replace(targetAddress, new NativeCallback(function (ssl, out_alert) {
            console.log("[+] ssl_crypto_x509_session_verify_cert_chain called - returning success");
            return 1; // SSL_VERIFY_OK
        }, 'int', ['pointer', 'pointer']));

        console.log("[+] Successfully hooked " + targetFunction);
        return true;
    }

    // Fallback: Try older function name
    targetFunction = "ssl_verify_result";
    targetAddress = Module.findExportByName(moduleName, targetFunction);

    if (targetAddress) {
        console.log("[+] Found " + targetFunction + " at: " + targetAddress);

        Interceptor.replace(targetAddress, new NativeCallback(function (ssl) {
            console.log("[+] ssl_verify_result called - returning success");
            return 1; // SSL_VERIFY_OK
        }, 'int', ['pointer']));

        console.log("[+] Successfully hooked " + targetFunction);
        return true;
    }

    // If exports not found, try pattern matching
    console.log("[*] Attempting pattern-based hooking...");
    return hookFlutterByPattern(module);
}

// Pattern-based hooking for stripped binaries
function hookFlutterByPattern(module) {
    try {
        // Pattern for ssl_crypto_x509_session_verify_cert_chain
        // This is a common pattern in BoringSSL's certificate verification
        var pattern = "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC";

        var matches = Memory.scanSync(module.base, module.size, pattern);

        if (matches.length > 0) {
            console.log("[+] Found " + matches.length + " potential matches");

            // Hook the first match (usually the right one)
            var targetAddress = matches[0].address;
            console.log("[+] Hooking at: " + targetAddress);

            Interceptor.attach(targetAddress, {
                onEnter: function (args) {
                    console.log("[+] Certificate verification function called");
                },
                onLeave: function (retval) {
                    console.log("[+] Original return value: " + retval);
                    retval.replace(1); // Force success
                    console.log("[+] Modified return value to: 1 (success)");
                }
            });

            return true;
        }
    } catch (err) {
        console.log("[-] Pattern matching failed: " + err);
    }

    return false;
}

// Alternative: Hook session_verify_cert_chain via offset calculation
function hookFlutterByOffset() {
    var moduleName = "libflutter.so";
    var module = Process.findModuleByName(moduleName);

    if (!module) {
        return false;
    }

    // Try to find JNI_OnLoad as a reference point
    var jniOnLoad = Module.findExportByName(moduleName, "JNI_OnLoad");

    if (jniOnLoad) {
        console.log("[+] JNI_OnLoad found at: " + jniOnLoad);

        // Note: Offsets vary by Flutter version and architecture
        // These would need to be calculated for specific versions
        console.log("[*] Offset-based hooking requires version-specific offsets");
        console.log("[*] Consider using reFlutter for static patching instead");
    }

    return false;
}

// Hook SSL_CTX_set_custom_verify (alternative approach)
function hookSSLContextVerify() {
    var moduleName = "libflutter.so";

    try {
        var SSL_CTX_set_custom_verify = Module.findExportByName(moduleName, "SSL_CTX_set_custom_verify");

        if (SSL_CTX_set_custom_verify) {
            console.log("[+] Found SSL_CTX_set_custom_verify");

            Interceptor.attach(SSL_CTX_set_custom_verify, {
                onEnter: function (args) {
                    console.log("[+] SSL_CTX_set_custom_verify called");
                    // args[1] is the callback function
                    // We could replace it with our own
                }
            });

            return true;
        }
    } catch (err) {
        console.log("[-] SSL_CTX_set_custom_verify hook failed: " + err);
    }

    return false;
}

// Wait for libflutter.so to load
function waitForLibFlutter() {
    var maxAttempts = 10;
    var attempt = 0;

    var intervalId = setInterval(function () {
        attempt++;

        if (hookFlutterSSL()) {
            console.log("[+] Flutter SSL bypass successful!");
            clearInterval(intervalId);
        } else if (attempt >= maxAttempts) {
            console.log("[-] Failed to hook Flutter SSL after " + maxAttempts + " attempts");
            console.log("[*] The app may not be using Flutter, or libflutter.so hasn't loaded yet");
            clearInterval(intervalId);
        } else {
            console.log("[*] Attempt " + attempt + "/" + maxAttempts + " - waiting for libflutter.so...");
        }
    }, 1000);
}

// Start the bypass
if (Java.available) {
    Java.perform(function () {
        console.log("[*] Java runtime available, starting Flutter bypass...");
        waitForLibFlutter();
    });
} else {
    console.log("[*] Starting Flutter bypass without Java runtime...");
    setTimeout(hookFlutterSSL, 1000);
}

console.log("[*] Flutter SSL Bypass Script Complete");
