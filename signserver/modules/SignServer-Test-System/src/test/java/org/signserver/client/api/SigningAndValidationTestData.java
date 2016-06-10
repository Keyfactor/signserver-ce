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
    private static final String CERT_EIGHTCA = 
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
     * signer00001 from dss10_keystore.p12.
     */
    private static final String CERT_SIGNER00001 =
            "MIIEmDCCAoCgAwIBAgIIa4ipW9G59Z0wDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UE\n" +
            "AwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNp\n" +
            "Z25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTE2MDMwMzA4MjQwOVoXDTM2MDIyNzA4\n" +
            "MjQwOVowSjEUMBIGA1UEAwwLc2lnbmVyMDAwMDExEDAOBgNVBAsMB1Rlc3Rpbmcx\n" +
            "EzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0B\n" +
            "AQEFAAOCAQ8AMIIBCgKCAQEApzvRZ6gX/u2T1AqL7EVrpKHEFDtKlBehjqJ05/kI\n" +
            "zFNbGNkmTLQkbCRRirfHcd6jhY9wmFnYFTTHBS9JFWI7Q6Q/nehHApSaoh+eb5Qr\n" +
            "ZYW2Cq5wLrQg18ckpecarXratsPQEKvTGWBCnJ1bhHmMeWHj56LYIB2EqES09gmK\n" +
            "IVbNoAX/XymZ3lDgtfGXUc5SndTh1iIPFVMUzRbXoSvZGIfvQ6rRJDVS3/epBRfW\n" +
            "tGzLaDK+dXMHisLsOahQARp5XU8DXd5+CwZC1dA+zQNixYEhStHXVuKfv4a89ONS\n" +
            "pEdv2KHgOLiQP2N+hjszzSasRbhwLSENMEbeL5GbMIJTRQIDAQABo38wfTAdBgNV\n" +
            "HQ4EFgQUlkvLMTR+fW1eSjV4irWUdoJifMwwDAYDVR0TAQH/BAIwADAfBgNVHSME\n" +
            "GDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0l\n" +
            "BBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQANg0pI\n" +
            "IifUnDHjffnpiep7eITU6V6odovsj3+1tYIaAahW+HtI5T2ishEt++huFiUFIdwb\n" +
            "FyF4Ep5cQe9cMfQghUJ//YqC1WHnxVQH234ELdO1FzaC1YcHis2zeW7HFpugd9Wr\n" +
            "Lgms/p2gXTLkLEfbUVE5ujUjelBUKyIA3ADDnWRxaz2vlOvRV+8ZgrvxSN+jYkrA\n" +
            "SeoDHeBh9qGknu1AmgaIUuQV6j/SSuf9+em3E7RSpFzOFwQTKq1MlKcxb3EC32O/\n" +
            "JHu8T8jHWHZDmq2IkmwyGm3vTJH9bLNKvgM+wLWBJpbU5Ku/ijRNvOCAVrt90QKl\n" +
            "MtA2/JZfLqZFiBNdB43VrM6cxWMdCL7gRIb50rR/CNAgblHq0DvpnXwS16SdaEib\n" +
            "H6LjzTIJjoLwVbW+23j5w5r+XgxeNpoGxD5WY+Kq/h7D4eoL3e+oXHEfNwvXEuuR\n" +
            "FpFXv4+4kOibRklG79VHSXEWclMvMlplIqHjHYh4gGSyvktCkV7YmqWteK9NEKeL\n" +
            "OFoJ5Y5S4S9a+aCFkaHoUrW/PwR8Qp/0vOCK8+UduaDVbEQaM8Z2KeZwWafVdFxg\n" +
            "b41nu6vcDVL/OQU0JyvdmNYmVoujboC3kNVfYJRgWeGceW2yo5anh5EuVwpMDncN\n" +
            "HRF8V0TNwfORKDMmKoX5rcdgjmrR7Ebh29qalg==";

    private static final String CERT_DSSROOTCA10 =
            "MIIFfzCCA2egAwIBAgIIMk1BOK8CwTwwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UE\n" +
            "AwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNp\n" +
            "Z25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA4MTQyN1oXDTM2MDUyNzA4\n" +
            "MTQyN1owTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3Rp\n" +
            "bmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIICIjANBgkqhkiG\n" +
            "9w0BAQEFAAOCAg8AMIICCgKCAgEAgblgjTTkMp1QAhgWDprhvqE9zX1Ux/A/RTOu\n" +
            "4G4f6CTkd6JEEkbdKZv+CKv4cRoVCtfO3wnOokFRw/1JMmHHiQ1Z//uDoDjo8jk8\n" +
            "nek0ArFE9R5NT02wMJCQa/mP1wU9ZSl1tx3jQRUFB+rTNeCcPTft+1FL7UjYMdkR\n" +
            "zl261IOlmXzDMA+EYIGJ2c2wYhOv2DqfQygNz5GOf0EFqlQZIt/pzopSS+0K8mNb\n" +
            "53ROhg9GJujwzugSH5Z+r0fsVHbCV0QUkZBfkRo9KMcdaDEPa8xpYTjsFPqU6Rcn\n" +
            "GkVABhn8OS8SIWw2re1f+htj6p9EGbk1m0I9pWGBA9ktWnrqlqDXV+tEhhh1O4f+\n" +
            "LHieoxiscrF7RXxlYqyam6oabfXsX3VAC0M1UkwIciE8wA1Sj/+dgoSMqvEDNDfw\n" +
            "pEYt6l8Z8czDTWDi7MM2u5VY0nP3+A+PepKrOtrdaGSP396f4a7A3un1o6nQWHsy\n" +
            "WQ7kc8GIn8zN5nykQaghGyYlHHYe1XUSPtHmxjbdsyztrkIis3cfjFne0XgPAiQu\n" +
            "Yx3T/B+po9BhGIUwCV0Qi/gWVN6NkydsbzMeRXELQYyK+lHgIGiEaBzQRRtXbnB+\n" +
            "wQXi2IacJNdKqICwDsl/PvvcZI9ZV6pB/KIzB+8IJm0CLY24K0OXJs3Bqij8gmpv\n" +
            "bI+o0wUCAwEAAaNjMGEwHQYDVR0OBBYEFCB6Id7orbsCqPtxWKQJYrnYWAWiMA8G\n" +
            "A1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUIHoh3uituwKo+3FYpAliudhYBaIw\n" +
            "DgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQAxFvpOZF6Kol48cQeK\n" +
            "WQ48VAe+h5dmyKMfDLDZX51IRzfKKsHLpFPxzGNw4t9Uv4YOR0CD9z81dR+c93t1\n" +
            "lwwIpKbx9Qmq8jViHEHKYD9FXThM+cVpsT25pg35m3ONeUX/b++l2d+2QNNTWMvd\n" +
            "sCtaQdybZqbYFIk0IjPwLLqdsA8Io60kuES4JnQahPdLkfm70rgAdmRDozOfSDaa\n" +
            "WHY20DovkfvKUYjPR6MGAPD5w9dEb4wp/ZjATblyZnH+LTflwfftUAonmAw46E0Z\n" +
            "gg143sO6RfOOnbwjXEc+KXd/KQ6kTQ560mlyRd6q7EIDYRfD4n4agKV2R5gvVPhM\n" +
            "D0+IK7kagqKNfWa9z8Ue2N3MedyWnb9wv4wC69qFndGaIfYADkUykoOyLsVVteJ7\n" +
            "0PVJPXO7s66LucfD2R0wo2MpuOYCsTOm7HHS+uZ9VjHl2qQ0ZQG89Xn+AXnzPbk1\n" +
            "INe2z0lq3hzCW5DTYBKsJEexErzMpLwiEqUYJUfR9EeCM8UPMtLSqz1utdPoIYhU\n" +
            "LGzt5lSJEpMHMbquYfWJxQiKCbvfxQsP5dLUMEIqTgjNdo98OlM7Z7zjYH9Kimz3\n" +
            "wgAKSAIoQZr7Oy1dMHO5GK4jBtZ8wgsyyQ6DzQQ7R68XFVKarIW8SATeyubAP+Wj\n" +
            "dMwk/ZXzsDjMZEtENaBXzAefYA==";
    
	
    /**
     * Subject: CN=FirstCA,O=EJBCA Testing,C=SE
     * Issuer:  CN=FirstCA,O=EJBCA Testing,C=SE
     */
    private static final String CERT_FIRSTCA =
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
    private static final String CERT_ENDENTITY1 = 
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
    private static final String CERT_ENDENTITY2 =
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
		
	
    private static final String SIGNATURE_BY_ENDENTITY1 =
            "eBS5DYS3QWmpAIRoHgMuR1a72OPXC5cYg1M3KXzlRW471vOQq0zx7LI3NnNSyfhjWuQf0zQTyGv9"
            + "oKhCnGSFqTO+uwSfsajGL4HsWWm8ot+HkzgL0fcWl5EATntqGmaS2nKPR/cVl+P4BehjFcD3BZ70"
            + "gD+07DZjFd/tmjioH/w=";
	
    private static final String SIGNATURE_BY_SIGNER00001 =
            "TVHbxQyoBoLXqDICQ1gGHxfkVn3HUZ6KW66bNRWmwjzXvyjEkqcRYHohj9Z8hbnRxBObw3feZRkHz8UFaELXH1QcEiklGDTIMQoqiaWUQ9rwa8gnaN9hjHx2R82vwztNu0DhG51ovzUj29XXBth3+Lo84WtbbfZo1vXOApKd25R574Ethelxss0zRjfCTiCMyg4GCt3fF0u3JElydg6EfpOtA8wSEolQ6S/KS/FEkjCBCy/0EwkimTZuBoR7CFlMlox2pUV9hAfS5VavzdYCVB1kRCTAVs+Pjc+hSOUUH+cNpwHmacKoy0eQTgM5L8/l3Ep/p443dEmbTmx2doDIew==";
	
    
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
	 
	 
    /** Signature by signer00002. */
    private static final String SIGNATURE_BY_OTHER =
         "a7q9iXVRt1dOLZR101L7GNgXyOAb1nVJ+/acR+8NM+Qof3URaSnuqmNCUoRQRBP2JIv9b/itfoZpf0/m2Sbpuw==";
	 
    /**
     * Ok sig, ok cert.
     */
    public static final String TESTXML10 = 
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
                            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
                            +"    <SignatureValue>"+SIGNATURE_BY_SIGNER00001+"</SignatureValue>"
                            +"    <KeyInfo>"
                            +"        <X509Data>"
                            +"            <X509Certificate>"+CERT_SIGNER00001+"</X509Certificate>"
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
                            +"    <SignatureValue>"+SIGNATURE_BY_SIGNER00001+"</SignatureValue>"
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
                            +"    <SignatureValue>"+SIGNATURE_BY_SIGNER00001+"</SignatureValue>"
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
            +"    <SignatureValue>"+SIGNATURE_BY_SIGNER00001+"</SignatureValue>"
            +"    <KeyInfo>"
            +"        <X509Data>"
            +"        <X509Certificate>"+CERT_DSSROOTCA10+"</X509Certificate>"
            +"            <X509Certificate>"+CERT_SIGNER00001+"</X509Certificate>"
            +"        </X509Data>"
            +"    </KeyInfo>"
            +"</Signature ></root>";
	

    static final String DUMMY_XML1 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><my-tag>My Data</my-tag></root>";	
}
