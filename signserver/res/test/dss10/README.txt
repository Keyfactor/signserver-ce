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
	signer, code signing, and for TLS clients.
        Aliases for document signing: signer00001, signer00002, signer00003
            Keys with certificates issued directly by the root CA, by the root CA using ECDSA key
            and using RSA issued by a sub CA.
        Aliases for timestamp signing: ts00001, ts00002, ts00003
            Using the same variations as for the document signing keys (with critical EKU timestamping).
        Aliases for code signing: code00001, code00002, code00003
            Using the same variations as for the document signing keys (with critical EKU codeSigning).
	Alias for TLS: ra00001
	    Keys with a certificate suitable for TLS (with EKU tlsClient).

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
