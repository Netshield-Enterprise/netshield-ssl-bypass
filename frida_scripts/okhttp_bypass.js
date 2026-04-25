/**
 * OkHttp SSL Pinning Bypass
 * 
 * Bypasses OkHttp3 CertificatePinner implementation.
 * Compatible with OkHttp v3 and v4.
 */

console.log("[*] OkHttp SSL Bypass Script Loaded");

Java.perform(function() {

// Bypass OkHttp3 CertificatePinner
try {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");

    // Hook the check method (primary verification)
    CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCertificates) {
        console.log("[+] OkHttp CertificatePinner.check() bypassed for: " + hostname);
        return;
    };

    // Hook alternative check method (may not exist in all versions)
    try {
        CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function (hostname, peerCertificates) {
            console.log("[+] OkHttp CertificatePinner.check() (alt) bypassed for: " + hostname);
            return;
        };
    } catch (e) {
        console.log("[*] Alternative check overload not found (normal for some OkHttp versions)");
    }

    console.log("[+] OkHttp3 CertificatePinner hooks installed");
} catch (err) {
    console.log("[-] OkHttp3 CertificatePinner not found: " + err);
}

// Bypass CertificatePinner.Builder
try {
    var CertificatePinnerBuilder = Java.use("okhttp3.CertificatePinner$Builder");

    CertificatePinnerBuilder.add.overload("java.lang.String", "[Ljava.lang.String;").implementation = function (pattern, pins) {
        console.log("[+] OkHttp CertificatePinner.Builder.add() bypassed for pattern: " + pattern);
        return this;
    };

    CertificatePinnerBuilder.build.implementation = function () {
        console.log("[+] OkHttp CertificatePinner.Builder.build() - returning empty pinner");
        return Java.use("okhttp3.CertificatePinner").DEFAULT.value;
    };

    console.log("[+] OkHttp3 CertificatePinner.Builder hooks installed");
} catch (err) {
    console.log("[-] OkHttp3 CertificatePinner.Builder hook failed: " + err);
}

// Bypass OkHttpClient Builder
try {
    var OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");

    OkHttpClientBuilder.certificatePinner.implementation = function (certificatePinner) {
        console.log("[+] OkHttpClient.Builder.certificatePinner() bypassed");
        return this;
    };

    console.log("[+] OkHttpClient.Builder hooks installed");
} catch (err) {
    console.log("[-] OkHttpClient.Builder hook failed: " + err);
}

// Bypass for older OkHttp versions (if present)
try {
    var OkHttpClient = Java.use("com.squareup.okhttp.OkHttpClient");

    OkHttpClient.setCertificatePinner.implementation = function (certificatePinner) {
        console.log("[+] OkHttpClient.setCertificatePinner() (old) bypassed");
        return this;
    };

    console.log("[+] Legacy OkHttp hooks installed");
} catch (err) {
    console.log("[-] Legacy OkHttp not found (this is normal for newer apps)");
}

console.log("[*] OkHttp SSL Bypass Script Complete");

}); // end Java.perform
