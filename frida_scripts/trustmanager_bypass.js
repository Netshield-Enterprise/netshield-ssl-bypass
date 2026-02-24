/**
 * Custom TrustManager SSL Pinning Bypass
 * 
 * Hooks custom X509TrustManager implementations to bypass certificate validation.
 */

console.log("[*] TrustManager SSL Bypass Script Loaded");

// Find and hook all X509TrustManager implementations
function hookAllTrustManagers() {
    Java.perform(function () {
        console.log("[*] Enumerating all loaded classes...");

        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                // Look for classes that implement X509TrustManager
                if (className.indexOf("TrustManager") !== -1 ||
                    className.indexOf("trustmanager") !== -1) {

                    try {
                        var clazz = Java.use(className);

                        // Check if it has checkServerTrusted method
                        if (clazz.checkServerTrusted) {
                            console.log("[+] Found TrustManager: " + className);

                            // Hook all overloads of checkServerTrusted
                            var overloads = clazz.checkServerTrusted.overloads;

                            overloads.forEach(function (overload) {
                                overload.implementation = function () {
                                    console.log("[+] Bypassing " + className + ".checkServerTrusted()");
                                    return;
                                };
                            });

                            console.log("[+] Hooked " + overloads.length + " overload(s) of checkServerTrusted");
                        }

                        // Also hook checkClientTrusted if present
                        if (clazz.checkClientTrusted) {
                            var overloads = clazz.checkClientTrusted.overloads;

                            overloads.forEach(function (overload) {
                                overload.implementation = function () {
                                    console.log("[+] Bypassing " + className + ".checkClientTrusted()");
                                    return;
                                };
                            });
                        }

                    } catch (err) {
                        // Class might not be a TrustManager, skip
                    }
                }
            },
            onComplete: function () {
                console.log("[*] Class enumeration complete");
            }
        });
    });
}

// Hook specific known TrustManager implementations
Java.perform(function () {

    // Hook standard X509TrustManager
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        console.log("[+] X509TrustManager interface found");
    } catch (err) {
        console.log("[-] X509TrustManager not found: " + err);
    }

    // Hook TrustManagerFactory
    try {
        var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");

        TrustManagerFactory.getTrustManagers.implementation = function () {
            console.log("[+] TrustManagerFactory.getTrustManagers() called");
            var trustManagers = this.getTrustManagers();

            // Log what TrustManagers are being used
            for (var i = 0; i < trustManagers.length; i++) {
                console.log("[*] TrustManager[" + i + "]: " + trustManagers[i].$className);
            }

            return trustManagers;
        };

        console.log("[+] TrustManagerFactory hooks installed");
    } catch (err) {
        console.log("[-] TrustManagerFactory hook failed: " + err);
    }

    // Hook common custom TrustManager patterns
    var commonTrustManagers = [
        "com.android.org.conscrypt.TrustManagerImpl",
        "org.apache.harmony.xnet.provider.jsse.TrustManagerImpl",
        "com.google.android.gms.org.conscrypt.TrustManagerImpl"
    ];

    commonTrustManagers.forEach(function (className) {
        try {
            var TrustManagerImpl = Java.use(className);

            if (TrustManagerImpl.checkServerTrusted) {
                TrustManagerImpl.checkServerTrusted.overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        console.log("[+] Bypassing " + className + ".checkServerTrusted()");
                        return;
                    };
                });

                console.log("[+] Hooked " + className);
            }
        } catch (err) {
            // Class not found, skip
        }
    });

    // Hook PinningTrustManager (common in custom implementations)
    try {
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                if (className.toLowerCase().indexOf("pinning") !== -1 &&
                    className.toLowerCase().indexOf("trust") !== -1) {

                    try {
                        var PinningClass = Java.use(className);
                        console.log("[+] Found potential pinning class: " + className);

                        // Try to hook common pinning methods
                        var methodsToHook = [
                            "checkServerTrusted",
                            "checkPinning",
                            "verify",
                            "validateCertificateChain"
                        ];

                        methodsToHook.forEach(function (methodName) {
                            try {
                                if (PinningClass[methodName]) {
                                    PinningClass[methodName].overloads.forEach(function (overload) {
                                        overload.implementation = function () {
                                            console.log("[+] Bypassing " + className + "." + methodName + "()");
                                            return;
                                        };
                                    });
                                    console.log("[+] Hooked " + className + "." + methodName);
                                }
                            } catch (err) {
                                // Method not found
                            }
                        });

                    } catch (err) {
                        // Skip
                    }
                }
            },
            onComplete: function () { }
        });
    } catch (err) {
        console.log("[-] Pinning class enumeration failed: " + err);
    }

    // Start comprehensive TrustManager hooking
    setTimeout(hookAllTrustManagers, 2000);
});

console.log("[*] TrustManager SSL Bypass Script Complete");
