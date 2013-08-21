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

package org.signserver.module.xmlvalidator;

/**
 * Test data for TestXMLValidator.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class XMLValidatorTestData {

    /**
      *   SerialNumber: 05:3f:69:92:d0:81:24:8a
      *   IssuerDN: CN=DSS Root CA 10, OU=Testing, O=SignServer, C=SE
      *   Not Before: May 27 09:50:37 2011 GMT
      *   Not After : May 27 09:50:37 2021 GMT
      *   SubjectDN: CN=Signer 2, OU=Testing, O=SignServer, C=SE
      */
    static final String CERT_XMLSIGNER =
          "MIIElTCCAn2gAwIBAgIIBT9pktCBJIowDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UE"
	+ "AwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNp"
	+ "Z25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA5NTAzN1oXDTIxMDUyNzA5"
	+ "NTAzN1owRzERMA8GA1UEAwwIU2lnbmVyIDIxEDAOBgNVBAsMB1Rlc3RpbmcxEzAR"
	+ "BgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEF"
	+ "AAOCAQ8AMIIBCgKCAQEAokJJPVkPrn3a55rO6A3Bnbe0nfJR9IDSI8AmFhYEBLoK"
	+ "fiavx0oMdbdDe+Dkwv78xBkgbj//2lhMCVmss90RzY+d0d0rg2SP8y/DsyxwriqC"
	+ "fuM7lnlgvSHCYwoX8+uDM7zI53ykKVhqI3ttyFPa8RsjfFOIWqf39++sJUheW4j9"
	+ "x9rutf6qgtjxOYPQwDygT9cIVpM7ZehhqVYlcQZRsprMg55s2SN/a78krAW51mso"
	+ "IDgd9+zbsIvzuGqCspO3AN8b2m8tlHTlA/E4+3OZkSqgpx8FSKIfbKUa866pRzpt"
	+ "vcbL/wpFxYkyxqcB6o7CFnWbr3gUPpz8KjuY7ypMmwIDAQABo38wfTAdBgNVHQ4E"
	+ "FgQUSkR/B71idJmR8deZziBAqSzWzhMwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAW"
	+ "gBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYw"
	+ "FAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQA+pQuI1QmZ"
	+ "LdheCVmc+k1h53uIv9pBnBKSbKn0/CVznmlPOpJIwwuzcLfCesa6gkG6BabHJwMr"
	+ "U/SpZuWurHxdEKe6fS/ngYnIjFI5R0Kgl1czqq/tXDjGEpv2x0tZECqLFrkC7a+g"
	+ "jXJPE8TDj8nvi40pcKFvv2tbRiyYrIPIxefrXmkT91F3zUKbQL0iW7Aot/0Klj+i"
	+ "4uivqFu359OymJ2C5wJOyZqPPsxUvTdA2EZNX4BseFvJREmvx1CAgZkANZD4Qzn1"
	+ "b/0WrXfYsbWA4cBeTRR7vjGajBc/oGo2wki0dJksImU8b2dLEf3n3M9dfxiFEAnl"
	+ "3YKDmT21wamO/hRdWklT+7Ivz6SFnW6HneT42IMNkC4k3d0i0Y2/q7XN5rvMFbH1"
	+ "n6O4NUqHIkzbCtVljV6+XESmMseyJGKlY6RD7jnhEJq6dGPGSr5h6SAohYljs5Y1"
	+ "e/Dyg243sP75ZO7HfOYPd2Sp+p5R5szWOuZp5UtLFBhuwlI41LnpuL+4t25LjNHo"
	+ "GhzZCl1rxqcSBGVKLG2sN0XVXfqrt/EykOAV0WW+S72tRPI73eq0AeRJRRfzcZie"
	+ "qui694eP10Ehh/iiOpQ28yfhsWDvMIxu8o8oK+hpgQvCwecP7rupdqM9OQYnePb5"
	+ "3dd8Tt4hw4WhvSWC/9aNfFXc3jwbHVy5Rw==";

    /**
     * Certificate for xmlsigner4.
     * <pre>
     * Serial Number: 23:14:08:b6:eb:aa:42:dc
     *  Signature Algorithm: dsaWithSHA1
     *  Issuer: CN=DemoRootCA2, OU=EJBCA, O=SignServer Sample, C=SE
     *  Validity
     *      Not Before: Nov 10 11:22:11 2009 GMT
     *      Not After : Nov 10 11:22:11 2019 GMT
     *  Subject: CN=xmlsigner4
     * </pre>
     */
    static final String CERT_XMLSIGNER4 =
        "MIIDADCCAsCgAwIBAgIIIxQItuuqQtwwCQYHKoZIzjgEAzBPMRQwEgYDVQQDDAtE"
        +"ZW1vUm9vdENBMjEOMAwGA1UECwwFRUpCQ0ExGjAYBgNVBAoMEVNpZ25TZXJ2ZXIg"
        +"U2FtcGxlMQswCQYDVQQGEwJTRTAeFw0wOTExMTAxMTIyMTFaFw0xOTExMTAxMTIy"
        +"MTFaMBUxEzARBgNVBAMMCnhtbHNpZ25lcjQwggG4MIIBLAYHKoZIzjgEATCCAR8C"
        +"gYEA/X9TgR11EilS30qcLuzk5/YRt1I870QAwx4/gLZRJmlFXUAiUftZPY1Y+r/F"
        +"9bow9subVWzXgTuAHTRv8mZgt2uZUKWkn5/oBHsQIsJPu6nX/rfGG/g7V+fGqKYV"
        +"DwT7g/bTxR7DAjVUE1oWkTL2dfOuK2HXKu/yIgMZndFIAccCFQCXYFCPFSMLzLKS"
        +"uYKi64QL8Fgc9QKBgQD34aCF1ps93su8q1w2uFe5eZSvu/o66oL5V0wLPQeCZ1FZ"
        +"V4661FlP5nEHEIGAtEkWcSPoTCgWE7fPCTKMyKbhPBZ6i1R8jSjgo64eK7OmdZFu"
        +"o38L+iE1YvH7YnoBJDvMpPG+qFGQiaiD3+Fa5Z8GkotmXoB7VSVkAUw7/s9JKgOB"
        +"hQACgYEA1CXfT00olSOapmZl4zT1/tUQzOzttQ/DCB8qYwH5fKD4cw1O2IutdntO"
        +"P+Pd+Q6PV6r/cckmpvO12/sMpxWOmY1oio44L8Pl76MWqKiBecAsNgxjXkXiFdJ8"
        +"llhTj9Z8vSYP8TUyY4UaITm3oZOp60eamFL93LjvpOkrDj7orXijYDBeMB0GA1Ud"
        +"DgQWBBRqEubbKMwapnZFeqgUNRFEkKGpWjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQY"
        +"MBaAFEnfFS7KXpmugPeUWbefD8CEI94lMA4GA1UdDwEB/wQEAwIGwDAJBgcqhkjO"
        +"OAQDAy8AMCwCFDnp413fYl32LXvI/FrHLxfo5hW6AhRv3xxzl07QDdL/oWCtW0rs"
        +"tmtQmg==";
	  
    /**
      * SerialNumber: 32:4d:41:38:af:02:c1:3c
      * IssuerDN: CN=DSS Root CA 10, OU=Testing, O=SignServer, C=SE
      * Not Before: May 27 08:14:27 2011 GMT
      * Not After : May 27 08:14:27 2036 GMT
      *  SubjectDN: CN=DSS Root CA 10, OU=Testing, O=SignServer, C=SE
      */
    public static final String CERT_ISSUER =
         "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"
	+ "dMwk/ZXzsDjMZEtENaBXzAefYA==";

    /**
     * Certificate for DemoRootCA2.
     *
     * <pre>
     * Serial Number: 26:02:00:71:07:af:7f:95
     *   Signature Algorithm: dsaWithSHA1
     *   Issuer: CN=DemoRootCA2, OU=EJBCA, O=SignServer Sample, C=SE
     *   Validity
     *       Not Before: Nov  9 16:09:48 2009 GMT
     *       Not After : Nov 10 16:09:48 2034 GMT
     *   Subject: CN=DemoRootCA2, OU=EJBCA, O=SignServer Sample, C=SE
     * </pre>
     */
    public static final String CERT_ISSUER4 =
        "MIIDPTCCAvygAwIBAgIIJgIAcQevf5UwCQYHKoZIzjgEAzBPMRQwEgYDVQQDDAtE"
        +"ZW1vUm9vdENBMjEOMAwGA1UECwwFRUpCQ0ExGjAYBgNVBAoMEVNpZ25TZXJ2ZXIg"
        +"U2FtcGxlMQswCQYDVQQGEwJTRTAeFw0wOTExMDkxNjA5NDhaFw0zNDExMTAxNjA5"
        +"NDhaME8xFDASBgNVBAMMC0RlbW9Sb290Q0EyMQ4wDAYDVQQLDAVFSkJDQTEaMBgG"
        +"A1UECgwRU2lnblNlcnZlciBTYW1wbGUxCzAJBgNVBAYTAlNFMIIBtzCCASsGByqG"
        +"SM44BAEwggEeAoGBAI+d9uiMBBzqdvlV3wSMdwRv/Qx2POGqh+m0M0tMYEwIGBdZ"
        +"Hm3+QSKIDTjcLRJgCGgTXSAJPCZtp43+kWCV5iGbbemBchOCh4Oe/4IPQERlfJhy"
        +"MH0gXLglG9KSbuKkqMSzaZoZk06q750KBKusKhK+mvhp08++KyXZna3p6itdAhUA"
        +"ntjYRJsYqqQtIt0htCGCEAHCkg8CgYA4E4VMplm16uizoUL+9erNtLI886f8pdO5"
        +"vXhcQG9IpZ0J7N6M4WQy8CFzTKjRJLs27TO2gDP8BE50mMOnbRvYmGIJsQ9lZHTj"
        +"UqltWh9PJ0VKF0fCwQbA3aY+v8PiHxELvami+YyBiYjE2C6b1ArKOw1QsEL0KakJ"
        +"cr22yWFaKgOBhQACgYEAiTsSMcEKhYCWg2ULDwD/4ueYyDcRvyoSrT7uCdGU0Y/w"
        +"2wPuI+kV5RfHxjs6YLDuJsQJg6rfi3RfgmwQJVzClDfgUN12qzRbSidepg/7ipkC"
        +"Gk0/eyY1A99z3K+FUZm2MVgune4ywCorPUpxz6WHS7/dSWYMWtSrr92PzgnwZbKj"
        +"YzBhMB0GA1UdDgQWBBRJ3xUuyl6ZroD3lFm3nw/AhCPeJTAPBgNVHRMBAf8EBTAD"
        +"AQH/MB8GA1UdIwQYMBaAFEnfFS7KXpmugPeUWbefD8CEI94lMA4GA1UdDwEB/wQE"
        +"AwIBhjAJBgcqhkjOOAQDAzAAMC0CFQCEGSmvJf6rxy6u7ZqY25qE7Hy21gIUPW4q"
        +"++YIS2fHyu+H4Pjgnodx5zI=";

    
    public static final String CERT_ISSUER_ECDSA =
            "MIIBdzCCAR2gAwIBAgIIVC+Dgmoirs0wCgYIKoZIzj0EAwIwDzENMAsGA1UEAwwERUNDQTAeFw0x"
            +"MzA4MjAxMzIwMzFaFw0yMzA4MjAxMzIwMzFaMA8xDTALBgNVBAMMBEVDQ0EwWTATBgcqhkjOPQIB"
            +"BggqhkjOPQMBBwNCAAQkIXc1SKnM/mNsGiK2ldpUmg6LFiJSF6pJk30sPLs9X6WUEwCtjE57CLch"
            +"Pyk5TaDjosYtTyAK0JMilQO1jSzHo2MwYTAdBgNVHQ4EFgQUdFxJXhx6KUz16PlSiD94IE3KTx8w"
            +"DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBR0XEleHHopTPXo+VKIP3ggTcpPHzAOBgNVHQ8B"
            +"Af8EBAMCAYYwCgYIKoZIzj0EAwIDSAAwRQIgVkarQSrY+mlfGhsUagHnOmfj274Xx5LmlisUKdRC"
            +"nz0CIQChndlBeog3cimhCgYNli+zAuKN3+st8FZqPiqe3cZgvA==";
     
    public static final String CERT_XMLSIGNER_ECDSA =
            "MIIBnDCCAUGgAwIBAgIIZ7YTjit1+tIwCgYIKoZIzj0EAwIwDzENMAsGA1UEAwwERUNDQTAeFw0x"
            +"MzA4MjEwODAzMTZaFw0yMzA4MjAxMzIwMzFaMBoxGDAWBgNVBAMMD1Rlc3RYTUxTaWduZXJFQzBW"
            +"MBAGByqGSM49AgEGBSuBBAAKA0IABPNbDHlOmo5S7xC9NaX8qLAVZj1cPOONlWkGU+vrM+1J1Wej"
            +"c2jXVAkSaxG13omgEdcp6axx1QBPM0mY0Sm79pyjfzB9MB0GA1UdDgQWBBQCxloPGJdVjF7zTQhR"
            +"FOFQ4SaDIjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFHRcSV4ceilM9ej5Uog/eCBNyk8fMA4G"
            +"A1UdDwEB/wQEAwIF4DAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwCgYIKoZIzj0EAwID"
            +"SQAwRgIhAO4Y5vHYsHa6EJUgSy3nobtrMaDlfYizlziQjfER05CQAiEAjEuF6sEbQEgsAtZegUaO"
            +"j6dyDoVID5JASDarQHELW3I=";      
    
    public static final String CERT_OTHER =
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
	
    static final String SIGNATURE_BY_XMLSIGNER2 =
        "TLroNwxZtAflrBvdMrKscqn0Rho2YzWGt0ydBRWo85she7faAhz+cfniLDgWNAWly27zc15KMdMa"
        + "FsELxgPg4J544Mx5RutkhGEn6dj6zMv+OoSjraDSP3PJ8tislpJw95SbmcrCKxSUqhQUdgO/ifNp"
        + "M9wcQZGUMNhNxvBdrhoezcOkKmCdxO8PI+dJgmuxcF3WS+dN3rgH4DKE7+6UwcPUNX1y5Atg0qjr"
        + "4fm2NUMFPcr/PWwaUv+5lOapnqSO1mN6P3lI7huk4bKrnKX39JnPmmTbnC8ihMqH+6Zdt6YNfgMH"
        + "wWqnHSqXmZvbJyJLnIIQskw8Oi+tnEMBgwW11g==";

    static final String SIGNATURE_BY_XMLSIGNER4 =
            "gy+9iGYV0FjNscOyKGEy0rtsBWVjjSzonuk36nhzBGVKxWHSgLVtow==";
	
    static final String SIGNATURE_BY_OTHER =
            "vNPmEQ9ckorNrQ793HZsVP8/NB07S2pNZkJ7JvfALNBkyDCntC+7UsiXWPRM1YMz3dnDF9WkjWHF"
            +"549XnjiwT7k0cBnKH0563rB0KWSjgAN7dT27g/+dKbvz7B6Q+v1uQDodahBW8Cpm6JuLwO0hZpHF"
            +"subk1bfz/iCUsJEuzGq++OyTGQJiVyJ7D/+fxRefVdORAcGRXBmvRUh3/pKGnv36BzYOR3z4lDLE"
            +"obSmC8X62cTYA+uCW3UJAhuxGEmXdYzrNTA0RH5ybC8kSkPmMvbxeA45hiyT6k8BiEhVAumncRkd"
            +"lWowqRrdOL0XaGczUUsp+BN6xsIqzfk3RCVtSQ==";
    
    static final String SIGNATURE_RSA_SHA256 =
            "bU6VTlrxeitxNmS5GPh5BmkDlK/jweHwbxEDg8q+Kjv+AZUNkmrZEMGyFyF+J6G7QhmvRLvm6mGf"
            +"HTZagObEpBSuYWz0dUyfEje9fRP4LooaowJ1FLxtsgHzQlc1m+3iyXpiLmaU0Nqg2R6lZXwhOPpl"
            +"thHvRxGcyFWIx193Ai5Lnfao9ODnjAiypjEmWXwDUeqyXyr2cu2SkzlHYb1klc7WKba8HRSwoXEE"
            +"RpTISKxcbbBRhJ8zZJ3Dyky07mZo5QIFcyWlICC7IzP982S9DWRPldWKqjCh4429Wq4BBwUcWZOD"
            +"z/dipBBFLzo/1vEr12d0jmoD6sXjBVYFvqtGZQ==";
    
    static final String SIGNATURE_RSA_SHA384 =
            "oElpxMLnogsjxK3gxlTS1rqXp3fD4blsOmjLWXY66yQIDQ7ZVo1FryLPg8z6jUxg6dYhkXuvxGd3"
            +"cRA0a5D3ogBRIR4l2LD5CkzJ0IrxyQ6/27PwvXHU5p2t8xxI11jCMQWRy+oK46uFMH+W7CplSMQq"
            +"EN2zxjmhOiRHnFByyVjMAySP73qPo6QxaLryrEfmwdmAf9I5ZE8V13fqe9/s5gAP9LT9ERafpJ4A"
            +"xY8vTu76u7MGEd2Y345C8jnsDNCJmK6DdsbpXVKirgc87lIOdHEJR9B0d94Z5ZCHTlQKYamEExk5"
            +"g4FCX0jwKS+eR+sjDgP0/qBNIJXNs/7iQUgfhw==";
    
    static final String SIGNATURE_RSA_SHA512 =
            "RlPLAOJDK7uGxe6ig3J1B9jhgHJ5MMitSUncGBfxP0Wtcr8yG84Vm3Wknl8QsfMIREaS7bW8M6tQ"
            +"UoO2hHTKhynCRHDcVIWrQMSbnvSF9aue+AxWN/ZL7GvU7O99I6cpl7bGVTpmg7RcFDhByE9IlFjR"
            +"Os6bjpwtohKOmRNhXO/cHMeySb38p/oi6LRneT/LioCQbgJfa9gJHxk6ABB1a47a/xdPasbt2tZv"
            +"yCVn9EmoTZId1Xzr0vmiFBOQt55If6lwfhniKHbCcoFy/Yap5ISsc3ha3ZI+Sbop+DIohHxR9F+1"
            +"BrnSTMT6qjEXhDgs2AItRciLaz4h4QJxrKQo3Q==";
    
    static final String SIGNATURE_ECDSA_SHA1 =
            "9v6sdc/CPn6YqNnko0YIkkNUeCLIz5HWINAmC8e02tkU8OZETFFY5MJtAi/i25SMuyf3IBVRBvKk"
            +"2RZvOZ1hpw==";
    
    static final String SIGNATURE_ECDSA_SHA256 =
            "/bFy7PxJmNKAPwUEiQO59QOmsIWjNMHZ7hwPGPV/0bEagKb7x7FnFhr9kkYbdTTm5IlWNO8Cf5nW"
            +"wdemL9zVPw==";
    
    /**
     * Ok sig, ok cert.
     */
    public static final String TESTXML1 =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
            +"    <SignatureValue>"+SIGNATURE_BY_XMLSIGNER2+"</SignatureValue>"
            +"    <KeyInfo>"
            +"        <X509Data>"
            +"            <X509Certificate>"+CERT_XMLSIGNER+"</X509Certificate>"
            +"        <X509Certificate>"+CERT_ISSUER+"</X509Certificate>"
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
     * Ok sig, wrong certificate.
     */
    static final String TESTXML3 = 
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
            +"    <SignatureValue>"+SIGNATURE_BY_XMLSIGNER2+"</SignatureValue>"
            +"    <KeyInfo>"
            +"        <X509Data>"
            +"        <X509Certificate>"+CERT_ISSUER+"</X509Certificate>"
            +"        </X509Data>"
            +"    </KeyInfo>"
            +"</Signature ></root>";
	
    /**
     * Ok sig, no certificate.
     */
    static final String TESTXML33 = 
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
            +"    <SignatureValue>"+SIGNATURE_BY_XMLSIGNER2+"</SignatureValue>"
            +"    <KeyInfo>"
            +"        <X509Data>"
            +"        </X509Data>"
            +"    </KeyInfo>"
            +"</Signature ></root>";
	
    /**
     * OK signature, first ca cert then signer cert.
     */
    static final String TESTXML5 = 
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
            +"    <SignatureValue>"+SIGNATURE_BY_XMLSIGNER2+"</SignatureValue>"
            +"    <KeyInfo>"
            +"        <X509Data>"
            +"        <X509Certificate>"+CERT_ISSUER+"</X509Certificate>"
            +"            <X509Certificate>"+CERT_XMLSIGNER+"</X509Certificate>"
            +"        </X509Data>"
            +"    </KeyInfo>"
            +"</Signature ></root>";

    /**
     * Ok sig, ok cert. Using DSA.
     */
    static final String TESTXML1_DSA =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#dsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
            +"    <SignatureValue>"+SIGNATURE_BY_XMLSIGNER4+"</SignatureValue>"
            +"    <KeyInfo>"
            +"        <X509Data>"
            +"            <X509Certificate>"+CERT_XMLSIGNER4+"</X509Certificate>"
            +"        <X509Certificate>"+CERT_ISSUER4+"</X509Certificate>"
            +"        </X509Data>"
            +"    </KeyInfo>"
            +"</Signature ></root>";
    
    /**
     * Ok sig, ok cert. Using SHA256 with RSA
     */
    public static final String TESTXML_SHA256withRSA =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
            +"    <SignatureValue>"+SIGNATURE_RSA_SHA256+"</SignatureValue>"
            +"    <KeyInfo>"
            +"        <X509Data>"
            +"            <X509Certificate>"+CERT_XMLSIGNER+"</X509Certificate>"
            +"        <X509Certificate>"+CERT_ISSUER+"</X509Certificate>"
            +"        </X509Data>"
            +"    </KeyInfo>"
            +"</Signature ></root>";
    
    /**
     * Ok sig, ok cert. Using SHA384 with RSA
     */
    public static final String TESTXML_SHA384withRSA =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
            +"    <SignatureValue>"+SIGNATURE_RSA_SHA384+"</SignatureValue>"
            +"    <KeyInfo>"
            +"        <X509Data>"
            +"            <X509Certificate>"+CERT_XMLSIGNER+"</X509Certificate>"
            +"        <X509Certificate>"+CERT_ISSUER+"</X509Certificate>"
            +"        </X509Data>"
            +"    </KeyInfo>"
            +"</Signature ></root>";
    
    /**
     * Ok sig, ok cert. Using SHA512 with RSA
     */
    public static final String TESTXML_SHA512withRSA =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
            +"    <SignatureValue>"+SIGNATURE_RSA_SHA512+"</SignatureValue>"
            +"    <KeyInfo>"
            +"        <X509Data>"
            +"            <X509Certificate>"+CERT_XMLSIGNER+"</X509Certificate>"
            +"        <X509Certificate>"+CERT_ISSUER+"</X509Certificate>"
            +"        </X509Data>"
            +"    </KeyInfo>"
            +"</Signature ></root>";
    
    public static final String TESTXML_SHA1withECDSA =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
            +"    <SignatureValue>"+SIGNATURE_ECDSA_SHA1+"</SignatureValue>"
            +"    <KeyInfo>"
            +"        <X509Data>"
            +"        <X509Certificate>"+CERT_XMLSIGNER_ECDSA+"</X509Certificate>"
            +"        <X509Certificate>"+CERT_ISSUER_ECDSA+"</X509Certificate>"
            +"        </X509Data>"
            +"    </KeyInfo>"
            +"</Signature ></root>";
    
    public static final String TESTXML_SHA256withECDSA =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
            +"    <SignatureValue>"+SIGNATURE_ECDSA_SHA256+"</SignatureValue>"
            +"    <KeyInfo>"
            +"        <X509Data>"
            +"        <X509Certificate>"+CERT_XMLSIGNER_ECDSA+"</X509Certificate>"
            +"        <X509Certificate>"+CERT_ISSUER_ECDSA+"</X509Certificate>"
            +"        </X509Data>"
            +"    </KeyInfo>"
            +"</Signature ></root>";
}
