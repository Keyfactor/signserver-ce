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
     * Certificate for signer00001.
     *
     * Serial Number 	6b88a95bd1b9f59d
     * Issuer 	CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE
     * Validity Not Before: 	2016-03-03 09:24:09 CET
     * Validity Not After: 	2036-02-27 09:24:09 CET
     * Subject 	CN=signer00001,OU=Testing,O=SignServer,C=SE
     * Subject Public Key Algorithm 	RSA
      */
    static final String CERT_XMLSIGNER =
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

    /**
     * Certificate for xmlsigner4.
     * <pre>
     * Serial Number: 73:9a:2f:10:6e:81:ba:04:77:2d:03:1a:66:02:a0:a5:49:78:b1:60
     *  Signature Algorithm: dsaWithSHA1
     *  Issuer: CN=DemoRootCA2, OU=EJBCA, O=SignServer Sample, C=SE
     *  Validity
     *      Not Before: Mon Dec 30 14:41:15 CET 2019
     *      Not After : Fri Nov 10 17:09:48 CET 2034
     *  Subject: CN=xmlsigner4
     * </pre>
     */
    static final String CERT_XMLSIGNER4 =
        "MIIDLDCCAuugAwIBAgIUc5ovEG6BugR3LQMaZgKgpUl4sWAwCQYHKoZIzjgEAzBPMRQwEgYDVQQDDAtEZW1vUm9vdENBMjEOMAwGA1UECwwFRUpCQ0ExGjAYBgNVBAoMEVNpZ25TZXJ2ZXIgU2FtcGxlMQswCQYDVQQGEwJTRTAeFw0xOTEyMzAxMzQxMTVaFw0zNDExMTAxNjA5NDhaMBUxEzARBgNVBAMMCnhtbHNpZ25lcjQwggG4MIIBLAYHKoZIzjgEATCCAR8CgYEA/X9TgR11EilS30qcLuzk5/YRt1I870QAwx4/gLZRJmlFXUAiUftZPY1Y+r/F9bow9subVWzXgTuAHTRv8mZgt2uZUKWkn5/oBHsQIsJPu6nX/rfGG/g7V+fGqKYVDwT7g/bTxR7DAjVUE1oWkTL2dfOuK2HXKu/yIgMZndFIAccCFQCXYFCPFSMLzLKSuYKi64QL8Fgc9QKBgQD34aCF1ps93su8q1w2uFe5eZSvu/o66oL5V0wLPQeCZ1FZV4661FlP5nEHEIGAtEkWcSPoTCgWE7fPCTKMyKbhPBZ6i1R8jSjgo64eK7OmdZFuo38L+iE1YvH7YnoBJDvMpPG+qFGQiaiD3+Fa5Z8GkotmXoB7VSVkAUw7/s9JKgOBhQACgYEA1CXfT00olSOapmZl4zT1/tUQzOzttQ/DCB8qYwH5fKD4cw1O2IutdntOP+Pd+Q6PV6r/cckmpvO12/sMpxWOmY1oio44L8Pl76MWqKiBecAsNgxjXkXiFdJ8llhTj9Z8vSYP8TUyY4UaITm3oZOp60eamFL93LjvpOkrDj7orXijfzB9MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUSd8VLspema6A95RZt58PwIQj3iUwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMB0GA1UdDgQWBBRqEubbKMwapnZFeqgUNRFEkKGpWjAOBgNVHQ8BAf8EBAMCBeAwCQYHKoZIzjgEAwMwADAtAhQ9OV4HFv9pTpRM4okw/R+H+jtgBgIVAIJfnJ5H8FRcjOANlGL61tg5ciJC";
	  
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

    /**
     * Test CA certificate for ECDSA signatures.
     * 
     * <pre>
     *  Serial Number: 3249049230434342325 (0x2d16f10f95cb95b5)
     *  Signature Algorithm: ecdsa-with-SHA256
     *       Issuer: CN=ECCA
     *       Validity
     *           Not Before: Jul 15 14:45:55 2015 GMT
     *           Not After : Jul 15 14:45:55 2040 GMT
     *       Subject: CN=ECCA
     *       Subject Public Key Info:
     *           Public Key Algorithm: id-ecPublicKey
     *               Public-Key: (256 bit)
     *               pub: 
     *                   04:50:ae:f5:90:68:c6:4e:d6:09:85:9f:eb:3b:22:
     *                   41:4c:e5:ca:e2:43:50:38:94:c9:da:c8:60:f2:0d:
     *                   02:1d:02:b5:58:b9:d7:9b:d3:f8:b6:9c:f2:86:95:
     *                   92:3e:c7:46:9b:b9:e9:1e:89:c8:d0:7b:d6:d7:c8:
     *                   17:ce:ed:e1:16
     *               ASN1 OID: prime256v1
     * </pre>
     */
    public static final String CERT_ISSUER_ECDSA =
        "MIIBdjCCAR2gAwIBAgIILRbxD5XLlbUwCgYIKoZIzj0EAwIwDzENMAsGA1UEAwwE\n" +
        "RUNDQTAeFw0xNTA3MTUxNDQ1NTVaFw00MDA3MTUxNDQ1NTVaMA8xDTALBgNVBAMM\n" +
        "BEVDQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARQrvWQaMZO1gmFn+s7IkFM\n" +
        "5criQ1A4lMnayGDyDQIdArVYudeb0/i2nPKGlZI+x0abuekeicjQe9bXyBfO7eEW\n" +
        "o2MwYTAdBgNVHQ4EFgQU3K35Xo+7YRt2sZ04QabVBIxkvp0wDwYDVR0TAQH/BAUw\n" +
        "AwEB/zAfBgNVHSMEGDAWgBTcrflej7thG3axnThBptUEjGS+nTAOBgNVHQ8BAf8E\n" +
        "BAMCAYYwCgYIKoZIzj0EAwIDRwAwRAIgbzETZ1s4R01zQxnUIKHJTMb+dORlqU1f\n" +
        "zfxZFNPd8P4CIFcijw9guK0kCh8L1dC3fGroqdzo5HU4Z1BNh31x3uh2";
     
    /**
     * Test signer certificate for ECDSA signatures.
     * 
     * <pre>
     * Serial Number: 2468830956166921450 (0x22430cac98d13cea)
     * Signature Algorithm: ecdsa-with-SHA256
     *   Issuer: CN=ECCA
     *   Validity
     *       Not Before: Jul 16 08:27:59 2015 GMT
     *       Not After : Jul 15 14:45:55 2040 GMT
     *   Subject: CN=TestXMLSignerEC, OU=Testing, O=SignServer, C=SE
     *   Subject Public Key Info:
     *       Public Key Algorithm: id-ecPublicKey
     *           Public-Key: (256 bit)
     *           pub: 
     *               04:b4:65:bd:d5:52:65:02:39:3f:be:67:f9:47:61:
     *               7b:52:a6:06:9a:02:7a:12:66:40:99:c8:7a:15:31:
     *               39:af:1c:28:38:d1:45:09:b5:8c:4e:10:46:59:7a:
     *               93:e7:44:dd:1d:1e:52:1b:49:1b:a1:58:3d:15:e5:
     *               76:0a:c2:8c:ef
     *           ASN1 OID: prime256v1
     * </pre>
     */
    public static final String CERT_XMLSIGNER_ECDSA =
        "MIIB0jCCAXigAwIBAgIIIkMMrJjRPOowCgYIKoZIzj0EAwIwDzENMAsGA1UEAwwE\n" +
        "RUNDQTAeFw0xNTA3MTYwODI3NTlaFw00MDA3MTUxNDQ1NTVaME4xGDAWBgNVBAMM\n" +
        "D1Rlc3RYTUxTaWduZXJFQzEQMA4GA1UECwwHVGVzdGluZzETMBEGA1UECgwKU2ln\n" +
        "blNlcnZlcjELMAkGA1UEBhMCU0UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS0\n" +
        "Zb3VUmUCOT++Z/lHYXtSpgaaAnoSZkCZyHoVMTmvHCg40UUJtYxOEEZZepPnRN0d\n" +
        "HlIbSRuhWD0V5XYKwozvo38wfTAdBgNVHQ4EFgQUBzUh0nHCSGru6EmeNyZUKTUC\n" +
        "/sUwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTcrflej7thG3axnThBptUEjGS+\n" +
        "nTAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwME\n" +
        "MAoGCCqGSM49BAMCA0gAMEUCIGI2m0wGmD/gJjqLdTUu0rYPjFxpLBxMO3Zs+GwD\n" +
        "P8lxAiEA59jfL0R4Nmc0MbaRdhnW+gmP1VfhlKJwVMmPqRrlZ9E=";    
    
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
             "TVHbxQyoBoLXqDICQ1gGHxfkVn3HUZ6KW66bNRWmwjzXvyjEkqcRYHohj9Z8hbnRxBObw3feZRkH"
            + "z8UFaELXH1QcEiklGDTIMQoqiaWUQ9rwa8gnaN9hjHx2R82vwztNu0DhG51ovzUj29XXBth3+Lo"
            + "84WtbbfZo1vXOApKd25R574Ethelxss0zRjfCTiCMyg4GCt3fF0u3JElydg6EfpOtA8wSEolQ6S"
            + "/KS/FEkjCBCy/0EwkimTZuBoR7CFlMlox2pUV9hAfS5VavzdYCVB1kRCTAVs+Pjc+hSOUUH+cNp"
            + "wHmacKoy0eQTgM5L8/l3Ep/p443dEmbTmx2doDIew==";

    static final String SIGNATURE_BY_XMLSIGNER4 =
            "YAIZt+p+oHbNTeVrW03MNDt3bL85x3mpwDn3nd58txFB/k/Ad1/lCA==";
	
    static final String SIGNATURE_BY_OTHER =
            "vNPmEQ9ckorNrQ793HZsVP8/NB07S2pNZkJ7JvfALNBkyDCntC+7UsiXWPRM1YMz3dnDF9WkjWHF"
            +"549XnjiwT7k0cBnKH0563rB0KWSjgAN7dT27g/+dKbvz7B6Q+v1uQDodahBW8Cpm6JuLwO0hZpHF"
            +"subk1bfz/iCUsJEuzGq++OyTGQJiVyJ7D/+fxRefVdORAcGRXBmvRUh3/pKGnv36BzYOR3z4lDLE"
            +"obSmC8X62cTYA+uCW3UJAhuxGEmXdYzrNTA0RH5ybC8kSkPmMvbxeA45hiyT6k8BiEhVAumncRkd"
            +"lWowqRrdOL0XaGczUUsp+BN6xsIqzfk3RCVtSQ==";
    
    static final String SIGNATURE_RSA_SHA256 =
             "b4PpwZ52orUA6zbA7JdWjzmQEyu/cJpBHnRI0J/Y74nDfaF7Cjzf7AHt4AszKmBHRtSJe59CbTys"
            + "msf6U2y1yybA9DYLUgWGjA+uQyvF7GIi5EPl3D+a/2b2kuAVMypTFDYeoKTqqYyLL6mBMfxpU0/"
            + "ftIB+4M0P1r61qBZEEraY9LRmaz8KoKMYW/cdb0n3wHp8/QRyUZdJ2rHqv2dQggrZWlgLawKHIl"
            + "iI2Tgo3/Dr+6ZD8vl3qsdEUxjz0amJMOkdAjy7lNY3jB5s+4cGx4I8XD6vt/Y2W4ZGGvdZ9r9gh"
            + "IRtsW8tfzpPRaDe+ZbzhTf0xNNkmqqud7ZWKHLxXQ==";
    
    static final String SIGNATURE_RSA_SHA384 =
             "oMKlV+ovqJ2rith7zqwhtVbXXbOhsUzFn4j6EGS0LVhdO86SyATQvkCoRaf3lQX9jcvXyN6jjdz5"
            + "Dvvld4AEZDmI77j+x+2jf/sHoOWOxTu6Xc893GyK/dtrKoTPGTqLgLGaRyzCZWTP1T+htnqqVdq"
            + "BydSwuUaOFZTfSfwcoD15ibRU7jjxncCeRVhPijnBtafCJjHEaIU2FY02jTyizc9b7WsGAB+pN1"
            + "9j29AqCAq4cEizC8u39DRZ6vtbWMh13pgSMQgygzQjyXTdiS6WTP3L1nEgixiDQ4UVcg9ApMf9m"
            + "75ZMYKstAZ/BmL/zx8QJtyVaphMpUhmU2C9nOW3yw==";
    
    static final String SIGNATURE_RSA_SHA512 =
             "Uicu5O7vz47tvT1Jay6gXGLztIFSJPqleSyrBJ4ULq94NdXu4E0OC3gIbibjtendKN37SZmmyNse"
            + "T8rKrU4/LtBSMV8c7wqgKO2htWONWvX8rf0wyhQL+oh6GOzCQeQCZoyTaWozUizcgIPjt2cffz8"
            + "qJ+DSbCSBOvIY6HiinzqqH9zJ6eOOH4piAi2ochza1UaEBjW04fbGr3+7eEeNRfVTMD+Gtycv/f"
            + "cWoyvS3MoQJ6AHrFlsWbhOS2TBGW6dKINVoEIAK1ECyD45fVnNMPHNsQ5PZbUx5Q3z0XWdJXUT6"
            + "JotOEw2DBrmqdcqabXFq+c2WU3OkyVPlKemDenvYA==";
    
    static final String SIGNATURE_ECDSA_SHA1 =
            "H3d3d6LHOXoS2m6USmGRfjCT94GgiaMWdSy4DW1+lVKFhIJsdo83zh0kZFrt48UedxhrboOsmcqU\n" +
            "oQnIhr5JyQ==";
    
    static final String SIGNATURE_ECDSA_SHA256 =
            "HWReXCc1ssA8ayZupMWvD6O25oTfAX64o4Dcmu5NM4k1XA41fS09w3Lv9WjNPRMBjsNAPmSZhSqm\n" +
            "+HaNH/HDtg==";
    
    static final String SIGNATURE_ECDSA_SHA384 =
            "XZi2W4ZZFRTZ38G9FTZfwIN3PpBWjCcjrV3vTJ3PvBI9lcgumj9O74iM6vEpip0QNg2RYs5kBh73\n" +
            "1A4X90Hd1g==";
    
    static final String SIGNATURE_ECDSA_SHA512 =
            "5N31z35CpQhFbTSO+DvIdWfRBnjjej4olq8egpLYdhNexcX0DeJ+pfA1YKTd3176UL5t0p+lpSns\n" +
            "uSGUKJOa2g==";
    
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
    
    public static final String TESTXML_SHA384withECDSA =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
            +"    <SignatureValue>"+SIGNATURE_ECDSA_SHA384+"</SignatureValue>"
            +"    <KeyInfo>"
            +"        <X509Data>"
            +"        <X509Certificate>"+CERT_XMLSIGNER_ECDSA+"</X509Certificate>"
            +"        <X509Certificate>"+CERT_ISSUER_ECDSA+"</X509Certificate>"
            +"        </X509Data>"
            +"    </KeyInfo>"
            +"</Signature ></root>";
    
    public static final String TESTXML_SHA512withECDSA =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            +"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
            +"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
            +"    <SignatureValue>"+SIGNATURE_ECDSA_SHA512+"</SignatureValue>"
            +"    <KeyInfo>"
            +"        <X509Data>"
            +"        <X509Certificate>"+CERT_XMLSIGNER_ECDSA+"</X509Certificate>"
            +"        <X509Certificate>"+CERT_ISSUER_ECDSA+"</X509Certificate>"
            +"        </X509Data>"
            +"    </KeyInfo>"
            +"</Signature ></root>";
}
