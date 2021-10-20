DSS10 - SignServer sample PKI 10
--------------------------------

This folder contains sample CA keystores, CA certificates, signer keystore and signer certificates that can be used for testing SignServer.

All keystores uses the password "foo123" if not otherwise specified.

WARNING: This certificates and keystores should only be used in closed test systems. 
They MUST NOT be trusted in a production system or any system connected to an untrusted network.


CA Certificates/Keystores:
    DSSRootCA10
	Serial Number:
            32:4d:41:38:af:02:c1:3c
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=DSS Root CA 10, OU=Testing, O=SignServer, C=SE
        Validity
            Not Before: May 27 08:14:27 2011 GMT
            Not After : May 27 08:14:27 2036 GMT
        Subject: CN=DSS Root CA 10, OU=Testing, O=SignServer, C=SE
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (4096 bit)

	X509v3 Key Usage: critical
    		Digital Signature, Certificate Sign, CRL Sign

Signer crypto token keystore:
    dss10_keystore.p12
        This can be used as a sample keystore crypto token for signers signing docuement, timestamp
	signer, code signing, e-passport signing and for TLS clients.
        Aliases for document signing: signer00001, signer00002, signer00003, signer00004
            Keys with certificates issued directly by the root CA, by the root CA using ECDSA key,
            using RSA issued by a sub CA and DSA key.
        Aliases for timestamp signing: ts00001, ts00002, ts00003, ts40003
            Using the same variations as for the document signing keys (with critical EKU timestamping),
            and additionally a certificate issued by a sub CA using a 4096 bit RSA key.
        Aliases for code signing: code00001, code00002, code00003, code40003
            Using the same variations as for the document signing keys (with critical EKU codeSigning),
            and additionally a certificate issued by a sub CA using a 4096 bit RSA key.
        Alias for e-passport signing: sod00001, sod00002
            Using RSA and ECDSA respectively.
        Key with certificates issued directly by the root CA.
	Alias for TLS: ra00001
	    Keys with a certificate suitable for TLS (with EKU tlsClient).
        Aliases for APK signing (with self-signed certificates): apk00001, apk00002
            Using RSA 2048 and ECDSA prime256v1.

TLS Server keystores:
    dss10_demo-tls.jks
        This file can be used as keystore.jks in the application server for HTTPS.
        Password: serverpwd
        Alias: localhost
        Subject alternative names: localhost, dssdemo
    
    dss10_truststore.jks
        This file can be used as truststore.jks/cacerts in the application server for HTTPS and contains the DSSRootCA10 as trusted certificate.
        Password: changeit

TLS Client keystores:
    dss10_admin1.p12
        This file can be imported into your browser or used by the Administration GUI to connect to SignServer when DSSRootCA10 is trusted by the server.
        Password: foo123
    dss10_admin2.p12
        This file can be imported into your browser or used by the Administration GUI to connect to SignServer when DSSRootCA10 is trusted by the server.
        Password: foo123
    dss10_admin3.p12
        This file can be imported into your browser or used by the Administration GUI to connect to SignServer when DSSRootCA10 is trusted by the server.
	The certificate has OCSP revocation informat (AIA), assuming a testing instance of EJBCA is running as a VA on locallhost with a port offset of 10000.
        Password: foo123
    dss10_admin4.p12
        This file can be imported into your browser or used by the Administration GUI to connect to SignServer when DSSRootCA10 is trusted by the server.
        The certificate is issued by the intermediate CA (DSS Sub CA 11).
        Password: foo123
    dss10_client1.p12
        This file can be imported into your browser or used by the Administration GUI to connect to SignServer when DSSRootCA10 is trusted by the server.
        Password:foo123
