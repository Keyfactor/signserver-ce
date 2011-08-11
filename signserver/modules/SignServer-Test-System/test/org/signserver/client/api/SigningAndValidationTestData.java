/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.client.api;

/**
 * TODO: Document me!
 *
 * @version $Id$
 */
public class SigningAndValidationTestData {

    /**
     * 		Certificate:
                Data:
                    Version: 3 (0x2)
                    Serial Number:
                        4b:f4:0c:cc:8c:f0:36:d7
                    Signature Algorithm: sha1WithRSAEncryption
                    Issuer: CN=EightCA, O=EJBCA Testing, C=SE
                    Validity
                        Not Before: Jun 10 15:44:51 2009 GMT
                        Not After : Jun  8 15:44:51 2019 GMT
                    Subject: CN=EightCA, O=EJBCA Testing, C=SE
                    Subject Public Key Info:
                        Public Key Algorithm: rsaEncryption
                        RSA Public Key: (1024 bit)
                            Modulus (1024 bit):
                                00:93:6a:42:dc:42:65:5f:b9:2c:88:62:9e:72:ed:
                                d4:fe:58:9a:7a:5a:d4:f8:50:4d:7e:94:97:27:b8:
                                3e:93:67:a6:0b:6a:b0:da:2c:b7:ce:a6:01:6c:26:
                                57:ae:c5:7b:47:7e:02:fc:de:8b:db:b4:4a:38:79:
                                ac:de:29:61:a1:8e:e7:53:77:eb:50:14:71:15:2b:
                                ca:5b:62:07:12:23:48:38:a6:15:fb:74:b5:d9:51:
                                c6:9e:d5:2e:e1:b3:af:63:80:eb:64:09:38:76:e1:
                                4b:8d:7f:e8:fc:07:84:0f:98:d6:aa:30:8c:c2:25:
                                fd:f7:09:35:a8:7f:cb:ab:b7
                            Exponent: 65537 (0x10001)
                    X509v3 extensions:
                        X509v3 Subject Key Identifier: 
                            DE:7D:65:1E:67:74:37:83:B0:F8:EC:61:E4:7C:BC:F5:5C:67:DB:D3
                        X509v3 Basic Constraints: critical
                            CA:TRUE
                        X509v3 Authority Key Identifier: 
                            keyid:DE:7D:65:1E:67:74:37:83:B0:F8:EC:61:E4:7C:BC:F5:5C:67:DB:D3

                        X509v3 Key Usage: critical
                            Digital Signature, Certificate Sign, CRL Sign
                Signature Algorithm: sha1WithRSAEncryption
                    7a:5f:6e:3d:93:b0:52:33:b2:d6:25:73:38:7c:83:0b:06:6f:
                    4b:5e:8a:2e:19:10:52:94:ce:df:0f:13:22:ec:30:02:1f:d5:
                    a5:47:06:87:78:2a:35:40:1f:09:12:5d:5b:05:fc:de:99:88:
                    c7:1f:f8:d6:3d:7d:ee:1d:dd:6c:ac:fd:04:1a:2e:2d:b0:dd:
                    5d:16:e8:4d:54:e4:ca:a8:65:d7:ee:da:e0:9e:10:bd:ec:74:
                    c5:90:ae:cb:f2:cb:e0:e5:fe:a7:d3:37:21:9a:1b:ab:95:91:
                    01:26:c6:9c:6b:90:6e:b8:61:e5:4f:93:e2:af:d0:67:e1:39:
                    7a:6a
     */
    public static final String CERT_EIGHTCA = 
            "MIICTjCCAbegAwIBAgIIS/QMzIzwNtcwDQYJKoZIhvcNAQEFBQAwNzEQMA4GA1UE"
            + "AwwHRWlnaHRDQTEWMBQGA1UECgwNRUpCQ0EgVGVzdGluZzELMAkGA1UEBhMCU0Uw"
            + "HhcNMDkwNjEwMTU0NDUxWhcNMTkwNjA4MTU0NDUxWjA3MRAwDgYDVQQDDAdFaWdo"
            + "dENBMRYwFAYDVQQKDA1FSkJDQSBUZXN0aW5nMQswCQYDVQQGEwJTRTCBnzANBgkq"
            + "hkiG9w0BAQEFAAOBjQAwgYkCgYEAk2pC3EJlX7ksiGKecu3U/liaelrU+FBNfpSX"
            + "J7g+k2emC2qw2iy3zqYBbCZXrsV7R34C/N6L27RKOHms3ilhoY7nU3frUBRxFSvK"
            + "W2IHEiNIOKYV+3S12VHGntUu4bOvY4DrZAk4duFLjX/o/AeED5jWqjCMwiX99wk1"
            + "qH/Lq7cCAwEAAaNjMGEwHQYDVR0OBBYEFN59ZR5ndDeDsPjsYeR8vPVcZ9vTMA8G"
            + "A1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU3n1lHmd0N4Ow+Oxh5Hy89Vxn29Mw"
            + "DgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4GBAHpfbj2TsFIzstYlczh8"
            + "gwsGb0teii4ZEFKUzt8PEyLsMAIf1aVHBod4KjVAHwkSXVsF/N6ZiMcf+NY9fe4d"
            + "3Wys/QQaLi2w3V0W6E1U5MqoZdfu2uCeEL3sdMWQrsvyy+Dl/qfTNyGaG6uVkQEm"
            + "xpxrkG64YeVPk+Kv0GfhOXpq";

    /**
    Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            0a:26:14:c8:76:38:e3:65
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: CN=EightCA, O=EJBCA Testing, C=SE
        Validity
            Not Before: Jun 10 15:40:23 2009 GMT
            Not After : Jun  8 15:40:23 2016 GMT
        Subject: CN=endentity8
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (1024 bit)
                Modulus (1024 bit):
                    00:b2:72:30:72:d3:cf:f3:a5:16:6e:18:64:ae:ba:
                    50:6f:fc:6d:ff:ba:b5:79:55:2c:80:88:54:2f:2e:
                    0c:f4:30:6b:26:a1:d1:ef:66:73:70:e4:e3:df:2f:
                    5e:19:8c:ff:fc:4e:a3:71:dc:f6:bf:e6:49:b4:67:
                    c6:46:e5:c4:d5:03:f9:99:48:bb:e5:50:f7:53:2e:
                    85:2d:03:11:de:0f:e0:2b:66:1e:66:07:24:4a:51:
                    5b:2d:6d:e8:e1:65:a3:d8:b3:4e:dd:9b:d4:10:23:
                    9a:64:85:c6:ec:40:2f:1d:78:b1:31:d4:f5:a6:b6:
                    c3:ca:80:70:42:e8:a8:51:c7
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                B0:2C:D2:F8:CF:CD:68:A9:D6:D8:62:21:49:0F:F9:3E:3B:14:5C:E7
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Authority Key Identifier: 
                keyid:DE:7D:65:1E:67:74:37:83:B0:F8:EC:61:E4:7C:BC:F5:5C:67:DB:D3

            X509v3 CRL Distribution Points: critical
                CRLissuer:<UNSUPPORTED>

            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication, E-mail Protection
    Signature Algorithm: sha1WithRSAEncryption
        5d:22:4b:a1:22:71:06:2e:55:ab:89:d4:ee:58:84:86:6f:09:
        c5:86:31:a9:07:95:a3:0a:c6:cd:46:bc:53:85:09:3a:94:d0:
        e4:41:51:be:68:35:b3:96:74:4b:ad:d3:67:92:f0:6a:28:c2:
        b8:b5:20:fb:0c:ad:f7:64:f9:23:2d:09:2e:5e:9e:87:3d:10:
        6e:45:bd:ba:f1:73:af:7d:4d:96:07:88:f2:7f:44:68:94:2b:
        c0:68:4b:79:8f:2c:89:7f:d7:5e:87:46:c1:c8:66:a8:dc:89:
        db:e1:ee:63:8f:13:88:e7:d9:2a:a1:8a:bc:37:d0:cc:d7:8e:
        67:37
    */
    public static final String CERT_ENDENTITY8 =
            "MIIClzCCAgCgAwIBAgIICiYUyHY442UwDQYJKoZIhvcNAQEFBQAwNzEQMA4GA1UE"
            + "AwwHRWlnaHRDQTEWMBQGA1UECgwNRUpCQ0EgVGVzdGluZzELMAkGA1UEBhMCU0Uw"
            + "HhcNMDkwNjEwMTU0MDIzWhcNMTYwNjA4MTU0MDIzWjAVMRMwEQYDVQQDDAplbmRl"
            + "bnRpdHk4MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCycjBy08/zpRZuGGSu"
            + "ulBv/G3/urV5VSyAiFQvLgz0MGsmodHvZnNw5OPfL14ZjP/8TqNx3Pa/5km0Z8ZG"
            + "5cTVA/mZSLvlUPdTLoUtAxHeD+ArZh5mByRKUVstbejhZaPYs07dm9QQI5pkhcbs"
            + "QC8deLEx1PWmtsPKgHBC6KhRxwIDAQABo4HNMIHKMB0GA1UdDgQWBBSwLNL4z81o"
            + "qdbYYiFJD/k+OxRc5zAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFN59ZR5ndDeD"
            + "sPjsYeR8vPVcZ9vTMEsGA1UdHwEB/wRBMD8wPaI7pDkwNzEQMA4GA1UEAwwHRWln"
            + "aHRDQTEWMBQGA1UECgwNRUpCQ0EgVGVzdGluZzELMAkGA1UEBhMCU0UwDgYDVR0P"
            + "AQH/BAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDANBgkqhkiG"
            + "9w0BAQUFAAOBgQBdIkuhInEGLlWridTuWISGbwnFhjGpB5WjCsbNRrxThQk6lNDk"
            + "QVG+aDWzlnRLrdNnkvBqKMK4tSD7DK33ZPkjLQkuXp6HPRBuRb268XOvfU2WB4jy"
            + "f0RolCvAaEt5jyyJf9deh0bByGao3Inb4e5jjxOI59kqoYq8N9DM145nNw==";

	
    /**
     * Subject: CN=FirstCA,O=EJBCA Testing,C=SE
     * Issuer:  CN=FirstCA,O=EJBCA Testing,C=SE
     */
    public static final String CERT_FIRSTCA =
            "MIICTjCCAbegAwIBAgIIFJUfMRSPUTswDQYJKoZIhvcNAQEFBQAwNzEQMA4GA1UE"
            + "AwwHRmlyc3RDQTEWMBQGA1UECgwNRUpCQ0EgVGVzdGluZzELMAkGA1UEBhMCU0Uw"
            + "HhcNMDkwNjA0MTYzOTQ0WhcNMTkwNjAyMTYzOTQ0WjA3MRAwDgYDVQQDDAdGaXJz"
            + "dENBMRYwFAYDVQQKDA1FSkJDQSBUZXN0aW5nMQswCQYDVQQGEwJTRTCBnzANBgkq"
            + "hkiG9w0BAQEFAAOBjQAwgYkCgYEAqiN9DJGgViydLMfu9YbhJuPink5UyFwGOKBz"
            + "RmS03w0Qdjr59auzq0WCpypQ8+s1Tu8nISWOVI1mX/30fgbpnYvMcLQFyEWuBOrs"
            + "ZBnFGGOZTnMVMti9TQgVf+bTfEDXoYmHvLS8k8ZHGlGoibh8D8lAPIYOm4mC3nFP"
            + "42J/668CAwEAAaNjMGEwHQYDVR0OBBYEFONib4wtykPvtqlshrrxAP+sXDTxMA8G"
            + "A1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU42JvjC3KQ++2qWyGuvEA/6xcNPEw"
            + "DgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4GBAJNZVYkN2AIAvExdduy6"
            + "tJ5MYhfOYA2V0hflWmzrbBYK0OLubzEtAU6aWeh/UYYg6f2Wf7mBbQw/DMIczDvl"
            + "l9pAkuUFAWZczh1D4ytwl9ASRuQUWL+n/S5PyjTQ0uuWa0m510HV0drzBSNS4mZk"
            + "NkdfpNx3/NJVOyzaSp56KR4c";
	
    /**
     * Subject    : C=SE, O=EJBCA Testing, CN=endentity1
     * Issuer     : C=SE, O=EJBCA Testing, CN=FirstCA
     */
    public static final String CERT_ENDENTITY1 = 
            "MIICbTCCAdagAwIBAgIIdpfNAUY23BQwDQYJKoZIhvcNAQEFBQAwNzEQMA4GA1UE"
            + "AwwHRmlyc3RDQTEWMBQGA1UECgwNRUpCQ0EgVGVzdGluZzELMAkGA1UEBhMCU0Uw"
            + "HhcNMDkwNjA4MDgyMzQzWhcNMTEwNjA4MDgyMzQzWjA6MRMwEQYDVQQDDAplbmRl"
            + "bnRpdHkxMRYwFAYDVQQKDA1FSkJDQSBUZXN0aW5nMQswCQYDVQQGEwJTRTCBnzAN"
            + "BgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApYHGk52L1XQtZNYien9L3fju8deSpB5c"
            + "Ne5cqr0Pce37KK1guknmHf7svm7mHEwsbpdMBrdQ+YNtMAREOKvQeRAm9FO4twYg"
            + "MnkzDp3v/K9CNbYGxoVZB5rI+PQug8aTSohnD2ZzyJh+vBEpAktxCWNonyhscsxK"
            + "dxSdESZ3ncUCAwEAAaN/MH0wHQYDVR0OBBYEFAf1rnolyolNsOeJbHfSfi/KOnbd"
            + "MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU42JvjC3KQ++2qWyGuvEA/6xcNPEw"
            + "DgYDVR0PAQH/BAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAN"
            + "BgkqhkiG9w0BAQUFAAOBgQBktjK+6N7rgh2RmLSBrDDbh5EeBJHhid3flgl/Pfpr"
            + "Ac041PrY4a08ezzW2oECcVfmCMk0GZSrmhgNELFP0LCGAq25C6Zz/wCOlSRZNSeK"
            + "jzYr+d41hz4EHNp+42qJlEGrSY6wUhDXO9kMuQzVw/GEQBW9dDBE9TImQBQ2HC4i"
            + "iw==";
	
    /**
     * 
     */
    public static final String CERT_ENDENTITY2 =
            "MIICSDCCAbGgAwIBAgIIJMFclCdO0dowDQYJKoZIhvcNAQEFBQAwNzEQMA4GA1UE"
            + "AwwHRmlyc3RDQTEWMBQGA1UECgwNRUpCQ0EgVGVzdGluZzELMAkGA1UEBhMCU0Uw"
            + "HhcNMDkwNjA4MDkzNTM1WhcNMTEwNjA4MDkzNTM1WjAVMRMwEQYDVQQDDAplbmRl"
            + "bnRpdHkyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFOv1Fz6Q1oJsLlL9"
            + "seIHH+MYvRhMq8Fj+dfRYei0DpktcFrtARpZjTsSnN410iebtZqJmBmmKeYEu9cn"
            + "UyhQhNDi8hQ+lyWE4noiudLMehFruZiTojP+IhKqtcRMPCsRLG8UhBdoJUwRniMw"
            + "wsSt+/n2Mw0RAJOYJl/0ADYkMwIDAQABo38wfTAdBgNVHQ4EFgQU+iib9vsdNq0O"
            + "mQHVMY9gQzsHNMswDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTjYm+MLcpD77ap"
            + "bIa68QD/rFw08TAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIG"
            + "CCsGAQUFBwMEMA0GCSqGSIb3DQEBBQUAA4GBAHLv0Y5qQbqV6ta2nOV/YVX4fYAL"
            + "goFFAeZwbz0P/4dNUT+1kZqxd/ju3pGUofj21P2wqMmvRcIqPQFNoycx8I9x5p04"
            + "tnxtTMj9U9hNKZUR69LtTAwVY3uUk3bGxfSQRvejHkaffSXaf43vtOSp1DpSaHbU"
            + "GUfKfM8Tu+OKjA0+";
		
	
    public static final String SIGNATURE_BY_ENDENTITY1 =
            "eBS5DYS3QWmpAIRoHgMuR1a72OPXC5cYg1M3KXzlRW471vOQq0zx7LI3NnNSyfhjWuQf0zQTyGv9"
            + "oKhCnGSFqTO+uwSfsajGL4HsWWm8ot+HkzgL0fcWl5EATntqGmaS2nKPR/cVl+P4BehjFcD3BZ70"
            + "gD+07DZjFd/tmjioH/w=";
	
    public static final String SIGNATURE_BY_ENDENTITY8 =
            "AahdAhSFwJ/f8mBZzY/B9iMTnyg7yKSKnzne6imP7/TRe17it/EHiVCO1F4oCpOtW2rURQyicMY3\n"
            + "dXmDXyEflf/mEd2Y55ZWDGNwKa1MWzl+qjBZvQyQabl4zd6F8la12VCKJ/UCJMkZHeDGLGWD7Tcf\n"
            + "rjN+LjgoIoZTAe0jrb0=";
	
    
    private static final String CERT_OTHER =
         "MIIDTjCCAjagAwIBAgIIH51RSUxYOpYwDQYJKoZIhvcNAQEFBQAwPTEXMBUGA1UEAwwOQWRtaW5U"
        +"cnVuazJDQTExFTATBgNVBAoMDEVKQkNBIFRydW5rMjELMAkGA1UEBhMCU0UwHhcNMDkwNTA2MTEx"
        +"ODMxWhcNMTEwNTA2MTExODMxWjAQMQ4wDAYDVQQDDAV1c2VyMTCCASIwDQYJKoZIhvcNAQEBBQAD"
        +"ggEPADCCAQoCggEBAM1Qs6eVhfLKpK21Iog18Ulx/x5uQVCwGdo2lfRFGwT93sAtUvHujrPppxyQ"
        +"pKc7//3NrKJ27N8KcuLr2qmtjA14rIzVzfehSyr8GusNmRa9UKN7QjRDbkb3TED9ib2TbKzz9EQW"
        +"tuQrYC5vpcEug1QjJ/sd/LWV7gqMlR+M1p1abRywrpBlsZrryMwnkCE3COneGKRmMUF9LGOYzehW"
        +"x7NbpfGQuY+E7677bys9yTb6y+gDWBEPxfnhysRYGI/Ze0Wa04g/ICwi/nUd5LHV1NW9ibwvsCSV"
        +"V5iMtaGYjh6jR0uuk3evDJNI0loLBpEsMBleBC9XWFU+sfwjDnWXBEsCAwEAAaN/MH0wHQYDVR0O"
        +"BBYEFLkQvTnoDO9LQN4tA7pOB8AFsLyiMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUMAjPtLnd"
        +"SML5y9FmcUXD8C4Xtx8wDgYDVR0PAQH/BAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEF"
        +"BQcDBDANBgkqhkiG9w0BAQUFAAOCAQEAKOa3XCgjWHD9rwv+dZrLtrQDtLSoj8DFgLghQ5alhPs2"
        +"/6v/DpjQUFLUmNqg9CwUy/UZwz09zJm4SDfnvbH3JjaCwNgp4VvG1TRK4D3wgaBaVZHrXONAyBDB"
        +"3XtSOoJuvR4pW1URG5kvL0wqB825dWsVzomUwhOPM1lMPgINWJwRun89bV9wAVcRNEdKM2d4Gb8A"
        +"Otn8gzx/E/MSaPzexW66Dd9dEHTJIjUpVdHd5Mp4BL/BdNYT2GtU+R1clObcDXUGFjMI9HaT2ARg"
        +"pN5nwZxfMj6Zz+9Y9fAZdWzjUa4rBwbNzZlvZ/uXQaIb4U0DPmSJZC0YwXmUqU5u7W7Zow==";
	 
	 
    private static final String SIGNATURE_BY_OTHER =
         "vNPmEQ9ckorNrQ793HZsVP8/NB07S2pNZkJ7JvfALNBkyDCntC+7UsiXWPRM1YMz3dnDF9WkjWHF"
                +"549XnjiwT7k0cBnKH0563rB0KWSjgAN7dT27g/+dKbvz7B6Q+v1uQDodahBW8Cpm6JuLwO0hZpHF"
                +"subk1bfz/iCUsJEuzGq++OyTGQJiVyJ7D/+fxRefVdORAcGRXBmvRUh3/pKGnv36BzYOR3z4lDLE"
                +"obSmC8X62cTYA+uCW3UJAhuxGEmXdYzrNTA0RH5ybC8kSkPmMvbxeA45hiyT6k8BiEhVAumncRkd"
                +"lWowqRrdOL0XaGczUUsp+BN6xsIqzfk3RCVtSQ==";
	 
    /**
     * Ok sig, ok cert.
     */
    public static final String TESTXML10 = 
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
                            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
                            +"    <SignatureValue>"+SIGNATURE_BY_ENDENTITY8+"</SignatureValue>"
                            +"    <KeyInfo>"
                            +"        <X509Data>"
                            +"            <X509Certificate>"+CERT_ENDENTITY8+"</X509Certificate>"
                            +"        </X509Data>"
                            +"    </KeyInfo>"
                            +"</Signature ></root>";

    /**
     * Ok sig, untrusted issuer.
     */
    public static final String TESTXML2 =
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                            +"<root-tag>"
                            +"    <tag2>Hello</tag2>"
                            +"<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>zMaM/bDls8EAts/a0NHQSHFoMqQ=</DigestValue></Reference></SignedInfo><SignatureValue>"
                            +SIGNATURE_BY_OTHER+"</SignatureValue><KeyInfo><X509Data><X509Certificate>"+CERT_OTHER+"</X509Certificate></X509Data></KeyInfo></Signature></root-tag>";
	
	
    /**
     * Ok sig, wrong certificate (issuer's instead of signer's).
     */
    public static final String TESTXML3 = 
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
                            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
                            +"    <SignatureValue>"+SIGNATURE_BY_ENDENTITY8+"</SignatureValue>"
                            +"    <KeyInfo>"
                            +"        <X509Data>"
                            +"        <X509Certificate>"+CERT_EIGHTCA+"</X509Certificate>"
                            +"        </X509Data>"
                            +"    </KeyInfo>"
                            +"</Signature ></root>";
	
    /**
     * Ok sig, no certificate.
     */
    public static final String TESTXML33 = 
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
                            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
                            +"    <SignatureValue>"+SIGNATURE_BY_ENDENTITY8+"</SignatureValue>"
                            +"    <KeyInfo>"
                            +"        <X509Data>"
                            +"        </X509Data>"
                            +"    </KeyInfo>"
                            +"</Signature ></root>";

    /**
     * OK signature, first ca cert then signer cert.
     */
    public static final String TESTXML5 = 
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
            +"    <SignatureValue>"+SIGNATURE_BY_ENDENTITY8+"</SignatureValue>"
            +"    <KeyInfo>"
            +"        <X509Data>"
            +"        <X509Certificate>"+CERT_EIGHTCA+"</X509Certificate>"
            +"            <X509Certificate>"+CERT_ENDENTITY8+"</X509Certificate>"
            +"        </X509Data>"
            +"    </KeyInfo>"
            +"</Signature ></root>";
	

    static final String DUMMY_XML1 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><my-tag>My Data</my-tag></root>";	
}
