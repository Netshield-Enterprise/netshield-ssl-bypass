/**
 * Universal Android SSL Pinning Bypass
 * 
 * Hooks common Android SSL/TLS APIs to bypass certificate pinning.
 * Works with standard Android SSL implementations.
 */

console.log("[*] Universal SSL Bypass Script Loaded");

// Bypass TrustManagerImpl (Android)
try {
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log("[+] Bypassing TrustManagerImpl.verifyChain for: " + host);
        return untrustedChain;
    };
    
    TrustManagerImpl.checkTrustedRecursive.implementation = function(certs, host, clientAuth, untrustedChain, trustAnchorChain, used) {
        console.log("[+] Bypassing TrustManagerImpl.checkTrustedRecursive for: " + host);
        return certs;
    };
    
    console.log("[+] TrustManagerImpl hooks installed");
} catch (err) {
    console.log("[-] TrustManagerImpl not found: " + err);
}

// Bypass X509TrustManager
try {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    
    var TrustManager = Java.registerClass({
        name: "com.netshield.bypass.CustomTrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {
                console.log("[+] checkClientTrusted bypassed");
            },
            checkServerTrusted: function(chain, authType) {
                console.log("[+] checkServerTrusted bypassed");
            },
            getAcceptedIssuers: function() {
                return [];
            }
        }
    });
    
    var TrustManagers = [TrustManager.$new()];
    var SSLContext_init = SSLContext.init.overload(
        "[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;",
        "java.security.SecureRandom"
    );
    
    SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
        console.log("[+] SSLContext.init() called, replacing TrustManager");
        SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
    };
    
    console.log("[+] X509TrustManager hooks installed");
} catch (err) {
    console.log("[-] X509TrustManager hook failed: " + err);
}

// Bypass SSLContext
try {
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    
    SSLContext.init.overload(
        "[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;",
        "java.security.SecureRandom"
    ).implementation = function(keyManager, trustManager, secureRandom) {
        console.log("[+] SSLContext.init() bypassed");
        this.init(keyManager, null, secureRandom);
    };
    
    console.log("[+] SSLContext hooks installed");
} catch (err) {
    console.log("[-] SSLContext hook failed: " + err);
}

// Bypass HostnameVerifier
try {
    var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
    var AllowAllHostnameVerifier = Java.registerClass({
        name: "com.netshield.bypass.AllowAllHostnameVerifier",
        implements: [HostnameVerifier],
        methods: {
            verify: function(hostname, session) {
                console.log("[+] HostnameVerifier bypassed for: " + hostname);
                return true;
            }
        }
    });
    
    console.log("[+] HostnameVerifier hooks installed");
} catch (err) {
    console.log("[-] HostnameVerifier hook failed: " + err);
}

// Bypass HttpsURLConnection
try {
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    
    HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
        console.log("[+] HttpsURLConnection.setDefaultHostnameVerifier bypassed");
    };
    
    HttpsURLConnection.setSSLSocketFactory.implementation = function(sslSocketFactory) {
        console.log("[+] HttpsURLConnection.setSSLSocketFactory bypassed");
    };
    
    HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
        console.log("[+] HttpsURLConnection.setHostnameVerifier bypassed");
    };
    
    console.log("[+] HttpsURLConnection hooks installed");
} catch (err) {
    console.log("[-] HttpsURLConnection hook failed: " + err);
}

// Bypass WebViewClient
try {
    var WebViewClient = Java.use("android.webkit.WebViewClient");
    
    WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
        console.log("[+] WebViewClient.onReceivedSslError bypassed");
        handler.proceed();
    };
    
    console.log("[+] WebViewClient hooks installed");
} catch (err) {
    console.log("[-] WebViewClient hook failed: " + err);
}

console.log("[*] Universal SSL Bypass Script Complete");
