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
package org.signserver.testutils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;
import javax.naming.NamingException;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.ejbca.util.Base64;
import org.signserver.admin.cli.AdminCLI;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.RequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.statusrepo.IStatusRepositorySession;

/**
 * Base class for test cases.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ModulesTestCase extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ModulesTestCase.class);

    private static final int DUMMY1_SIGNER_ID = 5676;
    private static final String DUMMY1_SIGNER_NAME = "TestXMLSigner";
    
    private static final int CMSSIGNER1_ID = 5677;
    private static final String CMSSIGNER1_NAME = "TestCMSSigner";
    
    private static final int PDFSIGNER1_ID = 5678;
    private static final String PDFSIGNER1_NAME = "TestPDFSigner";
    
    private static final int TIMESTAMPSIGNER1_SIGNER_ID = 5879;
    private static final String TIMESTAMPSIGNER1_SIGNER_NAME = "TestTimeStampSigner";
    
    private static final int SODSIGNER1_SIGNER_ID = 5880;
    private static final String SODSIGNER1_SIGNER_NAME = "TestSODSigner";
    
    private static final int VALIDATION_SERVICE_WORKER_ID = 5881;
    private static final String VALIDATION_SERVICE_WORKER_NAME = "TestValidationWorker";
    
    private static final int XML_VALIDATOR_WORKER_ID = 5882;
    private static final String XML_VALIDATOR_WORKER_NAME = "TestXMLValidator";

    //Value created by calling org.signserver.server.cryptotokens.CryptoTokenUtils.CreateKeyDataForSoftCryptoToken using the dss10_signer1.p12
    private static final String KEYDATA1 = "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";
    // Value created by calling org.signserver.server.cryptotokens.CryptoTokenUtils.CreateSignerCertificateChainForSoftCryptoToken using the dss10_signer1.p12 and removing extra back-slashes
    private static final String CERTCHAIN1 = "MIIElTCCAn2gAwIBAgIIQZNa2mLuDoowDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTE1MDYwMTE0MDQ0MVoXDTI1MDYwMTE0MDQ0MVowRzERMA8GA1UEAwwIU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy0GX45lzDRhUU/jhCCeqKKZcFWlOQiDxUcd6JOq38drUalL9u2+gr+dcBFKRBOGmFxjMGVJ4nDO8uI3dl+BOrFbykUAnf1Yk/t8E2ZmgdQMP4Cz6iXwlgWj8YRnQ6wEk2gcAp45SARfyEYdtArYvbTxOFoxb9KOjwji89yxCR/pbRHz/q3RoXgq6E/g8mTmIt4CAgvD5VVFiNP7XWKd4Ptw4bjQY8RW5k8291o1ErHbDZvvqvps4E9cIu35v1LtXjlFkwVJ4xc0L61Ak+cjcwAUcGqTHQ7P9KdjcOLztsw0X3jTZi5nLg3y4FukeOzkjxk5nh0Jr3/F3M7wuY2BS6wIDAQABo38wfTAdBgNVHQ4EFgQUDsECWxG3XbAJooXiXmQrIz/d0l4wDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQAr2nSyOwkDWPWiIqomXHsBHXwr35kvwqNSqM5Lh9if0XUDj0HudXH+nenyH9FAMkX1rfOm+SjQWmw5mgwgvpDyaI8J6NBSf0Kve9Qxn8Yh224oVZogHS7LYFULd9FE3UdLv0ZrD2i+0aXEZXaCEJBxNY+iVOpGdBdBgY6c7MD6Ib1Py7bQeslSOjmHNs7OnE5aZaLfmUQ30EprvX0Zzx0mhjm8BU41+m7Yg4W94mbZX0AGjEKL8v4NRQkNdv2/wgKNGKK+OvIIE/a3g8i68Jy5xbEI5sVcp6Z6qIa+6+5li33Gblwr86DnQFmm0IrCmgVyT2RuzNeXFcgenbHJO/udOchn1b65wwzfIuqo5SpJmzsS9HvbsdJOCvXbRRJibjC0TN73BmagH0wv4t9TawbRH/8M3JvWIAV7DIuyiosC6F9jN319zWkzPllesNsjmWzE05fwcZky4RSsS+eYmHxn9oEi1nS4igv0o/4lpz8WZ9KQSNTWP89wXPMW7bT1XUqMehSXk5Q13Ao/AXPF+4ZP4QJZMa2OHdDaNPMBinK0fZzoV/RFx5mzQm+XJCcdZBHbB+JEw14VBQHSf/Icgab1tANxgQSk8IOhZ0/OQ6LdfoTmRVsrxz58tzvA8Fw+FcyyIni8p6ve2oETepx5f5yVfLJzAdcgTXwo6R52yBgw2w\\=\\=;MIIFfzCCA2egAwIBAgIIMk1BOK8CwTwwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA4MTQyN1oXDTM2MDUyNzA4MTQyN1owTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgblgjTTkMp1QAhgWDprhvqE9zX1Ux/A/RTOu4G4f6CTkd6JEEkbdKZv+CKv4cRoVCtfO3wnOokFRw/1JMmHHiQ1Z//uDoDjo8jk8nek0ArFE9R5NT02wMJCQa/mP1wU9ZSl1tx3jQRUFB+rTNeCcPTft+1FL7UjYMdkRzl261IOlmXzDMA+EYIGJ2c2wYhOv2DqfQygNz5GOf0EFqlQZIt/pzopSS+0K8mNb53ROhg9GJujwzugSH5Z+r0fsVHbCV0QUkZBfkRo9KMcdaDEPa8xpYTjsFPqU6RcnGkVABhn8OS8SIWw2re1f+htj6p9EGbk1m0I9pWGBA9ktWnrqlqDXV+tEhhh1O4f+LHieoxiscrF7RXxlYqyam6oabfXsX3VAC0M1UkwIciE8wA1Sj/+dgoSMqvEDNDfwpEYt6l8Z8czDTWDi7MM2u5VY0nP3+A+PepKrOtrdaGSP396f4a7A3un1o6nQWHsyWQ7kc8GIn8zN5nykQaghGyYlHHYe1XUSPtHmxjbdsyztrkIis3cfjFne0XgPAiQuYx3T/B+po9BhGIUwCV0Qi/gWVN6NkydsbzMeRXELQYyK+lHgIGiEaBzQRRtXbnB+wQXi2IacJNdKqICwDsl/PvvcZI9ZV6pB/KIzB+8IJm0CLY24K0OXJs3Bqij8gmpvbI+o0wUCAwEAAaNjMGEwHQYDVR0OBBYEFCB6Id7orbsCqPtxWKQJYrnYWAWiMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUIHoh3uituwKo+3FYpAliudhYBaIwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQAxFvpOZF6Kol48cQeKWQ48VAe+h5dmyKMfDLDZX51IRzfKKsHLpFPxzGNw4t9Uv4YOR0CD9z81dR+c93t1lwwIpKbx9Qmq8jViHEHKYD9FXThM+cVpsT25pg35m3ONeUX/b++l2d+2QNNTWMvdsCtaQdybZqbYFIk0IjPwLLqdsA8Io60kuES4JnQahPdLkfm70rgAdmRDozOfSDaaWHY20DovkfvKUYjPR6MGAPD5w9dEb4wp/ZjATblyZnH+LTflwfftUAonmAw46E0Zgg143sO6RfOOnbwjXEc+KXd/KQ6kTQ560mlyRd6q7EIDYRfD4n4agKV2R5gvVPhMD0+IK7kagqKNfWa9z8Ue2N3MedyWnb9wv4wC69qFndGaIfYADkUykoOyLsVVteJ70PVJPXO7s66LucfD2R0wo2MpuOYCsTOm7HHS+uZ9VjHl2qQ0ZQG89Xn+AXnzPbk1INe2z0lq3hzCW5DTYBKsJEexErzMpLwiEqUYJUfR9EeCM8UPMtLSqz1utdPoIYhULGzt5lSJEpMHMbquYfWJxQiKCbvfxQsP5dLUMEIqTgjNdo98OlM7Z7zjYH9Kimz3wgAKSAIoQZr7Oy1dMHO5GK4jBtZ8wgsyyQ6DzQQ7R68XFVKarIW8SATeyubAP+WjdMwk/ZXzsDjMZEtENaBXzAefYA==";
    //Value created by calling org.signserver.server.cryptotokens.CryptoTokenUtils.CreateKeyDataForSoftCryptoToken using the dss10_tssigner1.p12
    private static final String CERTCHAIN2 = "MIIEkTCCAnmgAwIBAgIIeCvAS5OwAJswDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzEyMTU1NVoXDTIxMDUyNDEyMTU1NVowSjEUMBIGA1UEAwwLVFMgU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnT38GG8i/bGnuFMwnOdg+caHMkdPBacRdBaIggwMPfE50SOZ2TLrDEHJotxYda7HS0+tX5dIcalmEYCls/ptHzO5TQpqdRTuTqxp5cMA379yhD0OqTVNAmHrvPj9IytktoAtB/xcjwkRTHagaCmg5SWNcLKyVUct7nbeRA5yDSJQsCAEGHNZbJ50vATg1DQEyKT87GKfSBsclA0WIIIHMt8/SRhpsUZxESayU6YA4KCxVtexF5x+COLB6CzzlRG9JA8WpX9yKgIMsMDAscsJLiLPjhET5hwAFm5ZRfQQG9LI06QNTGqukuTlDbYrQGAUR5ZXW00WNHfgS00CjUCu0QIDAQABo3gwdjAdBgNVHQ4EFgQUOF0FflO2G+IN6c92pCNlPoorGVwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADELkeIO9aiKjS/GaBUUhMr+k5UbVeK69WapU+7gTsWwa9D2vAOhAkfQ1OcUJoZaminv8pcNfo1Ey5qLtxBCmUy1fVomVWOPl6u1w8B6uYgE608hi2bfx28uIeksqpdqUX0Qf6ReUyl+FOh4xNrsyaF81TrIKt8ekq0iD+YAtT/jqgv4bUvs5fgIms4QOXgMUzNAP7cPU44KxcmR5I5Uy/Ag82hGIz64hZmeIDT0X59kbQvlZqFaiZvYOikoZSFvdM5kSVfItMgp7qmyLxuM/WaXqJWp6Mm+8ZZmcECugd4AEpE7xIiB7M/KEe+X4ItBNTKdAoaxWa+yeuYS7ol9rHt+Nogelj/06ZRQ0x03UqC7uKpgYAICjQEXIjcZofWSTh9KzKNfS1sQyIQ6yNTT2VMdYW9JC2OLKPV4AEJuBw30X8HOciJRRXOq9KRrIA2RSiaC5/3oAYscWuo31Fmj8CWQknXAIb39gPuZRwGOJbi1tUu2zmRsUNJfAe3hnvk+uxhnyp2vKB2KN5/VQgisx+8doEK/+Nbj/PPG/zASKimWG++5m0JNY4chIfR43gDDcF+4INof/8V84wbvUF+TpvP/mYM8wC9OkUyRvzqv9vjWOncCdbdjCuqPxDItwm9hhr+PbxsMaBes9rAiV9YT1FnpA++YpCufveFCQPDbCTgJ;MIIFfzCCA2egAwIBAgIIMk1BOK8CwTwwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA4MTQyN1oXDTM2MDUyNzA4MTQyN1owTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgblgjTTkMp1QAhgWDprhvqE9zX1Ux/A/RTOu4G4f6CTkd6JEEkbdKZv+CKv4cRoVCtfO3wnOokFRw/1JMmHHiQ1Z//uDoDjo8jk8nek0ArFE9R5NT02wMJCQa/mP1wU9ZSl1tx3jQRUFB+rTNeCcPTft+1FL7UjYMdkRzl261IOlmXzDMA+EYIGJ2c2wYhOv2DqfQygNz5GOf0EFqlQZIt/pzopSS+0K8mNb53ROhg9GJujwzugSH5Z+r0fsVHbCV0QUkZBfkRo9KMcdaDEPa8xpYTjsFPqU6RcnGkVABhn8OS8SIWw2re1f+htj6p9EGbk1m0I9pWGBA9ktWnrqlqDXV+tEhhh1O4f+LHieoxiscrF7RXxlYqyam6oabfXsX3VAC0M1UkwIciE8wA1Sj/+dgoSMqvEDNDfwpEYt6l8Z8czDTWDi7MM2u5VY0nP3+A+PepKrOtrdaGSP396f4a7A3un1o6nQWHsyWQ7kc8GIn8zN5nykQaghGyYlHHYe1XUSPtHmxjbdsyztrkIis3cfjFne0XgPAiQuYx3T/B+po9BhGIUwCV0Qi/gWVN6NkydsbzMeRXELQYyK+lHgIGiEaBzQRRtXbnB+wQXi2IacJNdKqICwDsl/PvvcZI9ZV6pB/KIzB+8IJm0CLY24K0OXJs3Bqij8gmpvbI+o0wUCAwEAAaNjMGEwHQYDVR0OBBYEFCB6Id7orbsCqPtxWKQJYrnYWAWiMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUIHoh3uituwKo+3FYpAliudhYBaIwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQAxFvpOZF6Kol48cQeKWQ48VAe+h5dmyKMfDLDZX51IRzfKKsHLpFPxzGNw4t9Uv4YOR0CD9z81dR+c93t1lwwIpKbx9Qmq8jViHEHKYD9FXThM+cVpsT25pg35m3ONeUX/b++l2d+2QNNTWMvdsCtaQdybZqbYFIk0IjPwLLqdsA8Io60kuES4JnQahPdLkfm70rgAdmRDozOfSDaaWHY20DovkfvKUYjPR6MGAPD5w9dEb4wp/ZjATblyZnH+LTflwfftUAonmAw46E0Zgg143sO6RfOOnbwjXEc+KXd/KQ6kTQ560mlyRd6q7EIDYRfD4n4agKV2R5gvVPhMD0+IK7kagqKNfWa9z8Ue2N3MedyWnb9wv4wC69qFndGaIfYADkUykoOyLsVVteJ70PVJPXO7s66LucfD2R0wo2MpuOYCsTOm7HHS+uZ9VjHl2qQ0ZQG89Xn+AXnzPbk1INe2z0lq3hzCW5DTYBKsJEexErzMpLwiEqUYJUfR9EeCM8UPMtLSqz1utdPoIYhULGzt5lSJEpMHMbquYfWJxQiKCbvfxQsP5dLUMEIqTgjNdo98OlM7Z7zjYH9Kimz3wgAKSAIoQZr7Oy1dMHO5GK4jBtZ8wgsyyQ6DzQQ7R68XFVKarIW8SATeyubAP+WjdMwk/ZXzsDjMZEtENaBXzAefYA==";
    //Value created by calling org.signserver.server.cryptotokens.CryptoTokenUtils.CreateKeyDataForSoftCryptoToken using the dss10_tssigner1.p12
    private static final String KEYDATA2 = "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";
    
    private static final String KEYSTORE_SIGNER1_FILE = "res/test/dss10/dss10_signer1.p12";
    private static final String KEYSTORE_SIGNER1_ALIAS = "Signer 1";
    private static final String KEYSTORE_TSSIGNER1_FILE = "res/test/dss10/dss10_tssigner1.p12";
    private static final String KEYSTORE_TSSIGNER1_ALIAS = "TS Signer 1";
    private static final String KEYSTORE_AUTHCODESIGNER1_FILE = "res/test/dss10/dss10_authcodesigner1.p12";
    private static final String KEYSTORE_AUTHCODESIGNER1_ALIAS = "Auth Code Signer 1";
    public static final String KEYSTORE_PASSWORD = "foo123";

    /**
     * SerialNumber: 32:4d:41:38:af:02:c1:3c
     * IssuerDN: CN=DSS Root CA 10, OU=Testing, O=SignServer, C=SE
     * Not Before: May 27 08:14:27 2011 GMT
     * Not After : May 27 08:14:27 2036 GMT
     *  SubjectDN: CN=DSS Root CA 10, OU=Testing, O=SignServer, C=SE
     */
   private static final String VALIDATOR_CERT_ISSUER =
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
   private static final String VALIDATOR_CERT_ISSUER4 =
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
   
    private IWorkerSession workerSession;
    private IGlobalConfigurationSession globalSession;
    private IStatusRepositorySession statusSession;

    private static File signServerHome;

    private Properties config;
    
    private CLITestHelper adminCLI;
    private CLITestHelper clientCLI;
    private TestUtils testUtils = new TestUtils();
    protected static Random random = new Random(1234);

    public ModulesTestCase() {
        final Properties defaultConfig = new Properties();
        InputStream in = null;
        try {
            defaultConfig.load(getClass().getResourceAsStream("/org/signserver/testutils/default-test-config.properties"));
            config = new Properties(defaultConfig);
            final File configFile = new File(getSignServerHome(),
                    "test-config.properties");
            if (configFile.exists()) {
                in = new FileInputStream(configFile);
                config.load(in);
                setupSSLKeystores();
            }
        } catch (Exception ex) {
            fail("Could not load test configuration: " + ex.getMessage());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOG.error("Could not close config file", ex);
                }
            }
        }
    }

    public CLITestHelper getAdminCLI() {
        if (adminCLI == null) {
            adminCLI = new CLITestHelper(AdminCLI.class);
        }
        return adminCLI;
    }

    public CLITestHelper getClientCLI() {
        if (clientCLI == null) {
            clientCLI = new CLITestHelper(ClientCLI.class);
        }
        return clientCLI;
    }
    
    

    public IWorkerSession getWorkerSession() {
        if (workerSession == null) {
            try {
                workerSession = ServiceLocator.getInstance().lookupRemote(
                    IWorkerSession.IRemote.class);
            } catch (NamingException ex) {
                fail("Could not lookup IWorkerSession: " + ex.getMessage());
            }
        }
        return workerSession;
    }

    public IGlobalConfigurationSession getGlobalSession() {
        if (globalSession == null) {
            try {
                globalSession = ServiceLocator.getInstance().lookupRemote(
                    IGlobalConfigurationSession.IRemote.class);
            } catch (NamingException ex) {
                fail("Could not lookup IGlobalConfigurationSession: "
                        + ex.getMessage());
            }
        }
        return globalSession;
    }

    public IStatusRepositorySession getStatusSession() {
        if (statusSession == null) {
            try {
                statusSession = ServiceLocator.getInstance().lookupRemote(
                IStatusRepositorySession.IRemote.class);
            } catch (NamingException ex) {
                fail("Could not lookup IStatusRepositorySession: "
                        + ex.getMessage());
            }
        }
        return statusSession;
    }

    public void addDummySigner1() throws CertificateException {
        addSoftDummySigner(getSignerIdDummy1(), getSignerNameDummy1());
    }

    public int getSignerIdDummy1() {
        return DUMMY1_SIGNER_ID;
    }

    public String getSignerNameDummy1() {
        return DUMMY1_SIGNER_NAME;
    }
    
    public int getSignerIdTimeStampSigner1() {
        return TIMESTAMPSIGNER1_SIGNER_ID;
    }

    public String getSignerNameTimeStampSigner1() {
        return TIMESTAMPSIGNER1_SIGNER_NAME;
    }
    
    public int getSignerIdSODSigner1() {
        return SODSIGNER1_SIGNER_ID;
    }

    public String getSignerNameSODSigner1() {
        return SODSIGNER1_SIGNER_NAME;
    }
    
    public void addCMSSigner1() throws CertificateException {
        addSoftDummySigner("org.signserver.module.cmssigner.CMSSigner",
                getSignerIdCMSSigner1(), getSignerNameCMSSigner1(), KEYDATA1, CERTCHAIN1);
    }
    
    public void addPDFSigner1() throws CertificateException {
    	addSoftDummySigner("org.signserver.module.pdfsigner.PDFSigner",
                getSignerIdPDFSigner1(), getSignerNamePDFSigner1(), KEYDATA1, CERTCHAIN1);
    }
    
    public int getSignerIdCMSSigner1() {
        return CMSSIGNER1_ID;
    }
    
    public String getSignerNameCMSSigner1() {
        return CMSSIGNER1_NAME;
    }
    
    public int getSignerIdPDFSigner1() {
    	return PDFSIGNER1_ID;
    }
    
    public String getSignerNamePDFSigner1() {
    	return PDFSIGNER1_NAME;
    }

    public void addSigner(final String className) 
            throws CertificateException {
        addSigner(className, DUMMY1_SIGNER_ID, DUMMY1_SIGNER_NAME);
    }
    
    public void addSigner(final String className,
            final int signerId, final String signerName)
        throws CertificateException {
        addSoftDummySigner(className, signerId, signerName,
                KEYDATA1, CERTCHAIN1);
    }

    /**
     * Load worker/global properties from file. This is not a complete 
     * implementation as the one used by the "setproperties" CLI command but 
     * enough to load the junittest-part-config.properties files used by the 
     * tests.
     * @param file The properties file to load
     * @throws IOException
     * @throws CertificateException in case a certificate could not be decoded 
     */
    public void setProperties(final File file) throws IOException, CertificateException {
        InputStream in = null;
        try {
            in = new FileInputStream(file);
            Properties properties = new Properties();
            properties.load(in);
            setProperties(properties);
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }
    
    /**
     * Load worker/global properties from file. This is not a complete 
     * implementation as the one used by the "setproperties" CLI command but 
     * enough to load the junittest-part-config.properties files used by the 
     * tests.
     * @param in The inputstream to read properties from
     * @throws IOException
     * @throws CertificateException in case a certificate could not be decoded 
     */
    public void setProperties(final InputStream in) throws IOException, CertificateException {
        try {
            Properties properties = new Properties();
            properties.load(in);
            setProperties(properties);
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }
    
    /**
     * Load worker/global properties. This is not a complete 
     * implementation as the one used by the "setproperties" CLI command but 
     * enough to load the junittest-part-config.properties files used by the 
     * tests.
     * @param file The properties file to load
     * @throws CertificateException in case a certificate could not be decoded
     */
    public void setProperties(final Properties properties) throws CertificateException {
        for (Object o : properties.keySet()) {
            if (o instanceof String) {
                String key = (String) o;
                String value = properties.getProperty(key);
                if (key.startsWith("GLOB.")) {
                    key = key.substring("GLOB.".length());
                    getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, key, value);
                } else if (key.startsWith("WORKER") && key.contains(".") && key.indexOf(".") + 1 < key.length()) {
                    int id = Integer.parseInt(key.substring("WORKER".length(), key.indexOf(".")));
                    key = key.substring(key.indexOf(".") + 1);

                    if (key.startsWith("SIGNERCERTCHAIN")) {
                        String certs[] = value.split(";");
                        ArrayList<byte[]> chain = new ArrayList<byte[]>();
                        for (String base64cert : certs) {
                            byte[] cert = Base64.decode(base64cert.getBytes());
                            chain.add(cert);
                        }
                        getWorkerSession().uploadSignerCertificateChain(id, chain, GlobalConfiguration.SCOPE_GLOBAL);
                    } else {
                        getWorkerSession().setWorkerProperty(id, key, value);
                    }

                } else {
                    throw new RuntimeException("Unknown format for property: " + key);
                }
            }
        }
    }

    public void addP12DummySigner(final int signerId, final String signerName, final File keystore, final String password, final String alias) {
        addP12DummySigner("org.signserver.module.xmlsigner.XMLSigner",
                signerId, signerName, keystore, password, alias);
    }

    public void addP12DummySigner(final String className, final int signerId, final String signerName, final File keystore, final String password, final String alias) {
        addDummySigner(className, "org.signserver.server.cryptotokens.P12CryptoToken", signerId, signerName, keystore, password, alias);
    }

    public void addSoftDummySigner(final int signerId, final String signerName, final String keyData, final String certChain) throws CertificateException {
        addSoftDummySigner("org.signserver.module.xmlsigner.XMLSigner",
                signerId, signerName, keyData, certChain);
    }
    
    public void addDummySigner(final String className, final String cryptoTokenClassName, final int signerId, final String signerName, final File keystore, final String password, final String alias) {
        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".CLASSPATH", className);
        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".SIGNERTOKEN.CLASSPATH",
            cryptoTokenClassName);
        getWorkerSession().setWorkerProperty(signerId, "NAME", signerName);
        getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE", "NOAUTH");
        getWorkerSession().setWorkerProperty(signerId, "KEYSTOREPATH", keystore.getAbsolutePath());
        if (alias != null) {
            getWorkerSession().setWorkerProperty(signerId, "DEFAULTKEY", alias);
        }
        if (password != null) {
            getWorkerSession().setWorkerProperty(signerId, "KEYSTOREPASSWORD", password);
        }

        getWorkerSession().reloadConfiguration(signerId);
        try {
            assertNotNull("Check signer available",
                    getWorkerSession().getStatus(signerId));
        } catch (InvalidWorkerIdException ex) {
            fail("Worker was not added succefully: " + ex.getMessage());
        }
    }

    public void addP12DummySigner(final int signerId, final String signerName, final File keystore, final String password) {
        addP12DummySigner("org.signserver.module.xmlsigner.XMLSigner",
                signerId, signerName, keystore, password);
    }
    
    protected void addSoftTimeStampSigner(final int signerId, final String signerName, final String keyData, final String certChain) throws CertificateException {
        addSoftDummySigner("org.signserver.module.tsa.TimeStampSigner",
                signerId, signerName, keyData, certChain);
    }
    
    protected void addSoftSODSigner(final int signerId, final String signerName, final String keyData, final String certChain) throws CertificateException {
        addSoftDummySigner("org.signserver.module.mrtdsodsigner.MRTDSODSigner",
                signerId, signerName, keyData, certChain);
    }

    protected void addSoftDummySigner(final String className, final int signerId, final String signerName, final String keyData, final String certChain) throws CertificateException {
        // Worker using SoftCryptoToken and RSA
        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".CLASSPATH", className);
        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".SIGNERTOKEN.CLASSPATH",
            "org.signserver.server.cryptotokens.SoftCryptoToken");
        getWorkerSession().setWorkerProperty(signerId, "NAME", signerName);
        getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE", "NOAUTH");
        getWorkerSession().setWorkerProperty(signerId, "KEYDATA", keyData);

        getWorkerSession().uploadSignerCertificate(signerId, Base64.decode(getFirstCert(certChain).getBytes()),GlobalConfiguration.SCOPE_GLOBAL);
        String certs[] = certChain.split(";");
        ArrayList<byte[]> chain = new ArrayList<byte[]>();
        for(String base64cert : certs){
            chain.add(Base64.decode(base64cert.getBytes()));
        }
        getWorkerSession().uploadSignerCertificateChain(signerId, chain, GlobalConfiguration.SCOPE_GLOBAL);

        getWorkerSession().reloadConfiguration(signerId);
        try {
            assertNotNull("Check signer available",
                    getWorkerSession().getStatus(signerId));
        } catch (InvalidWorkerIdException ex) {
            fail("Worker was not added succefully: " + ex.getMessage());
        }
    }
    
    protected void addP12DummySigner(final String className, final int signerId, final String signerName, final File keystore, final String password) {
        addDummySigner(className, "org.signserver.server.cryptotokens.P12CryptoToken", signerId, signerName, keystore, password);
    }
    
    protected void addJKSDummySigner(final String className, final int signerId, final String signerName, final File keystore, final String password) {
        addDummySigner(className, "org.signserver.server.cryptotokens.JKSCryptoToken", signerId, signerName, keystore, password);
    }
    
    protected void addDummySigner(final String className, final String cryptoTokenClassName, final int signerId, final String signerName, final File keystore, final String password) {
        // Worker using SoftCryptoToken and RSA
        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".CLASSPATH", className);
        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".SIGNERTOKEN.CLASSPATH",
            cryptoTokenClassName);
        getWorkerSession().setWorkerProperty(signerId, "NAME", signerName);
        getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE", "NOAUTH");
        getWorkerSession().setWorkerProperty(signerId, "KEYSTOREPATH", keystore.getAbsolutePath());
        if (password != null) {
            getWorkerSession().setWorkerProperty(signerId, "KEYSTOREPASSWORD", password);
        }

        getWorkerSession().reloadConfiguration(signerId);
        try {
            assertNotNull("Check signer available",
                    getWorkerSession().getStatus(signerId));
        } catch (InvalidWorkerIdException ex) {
            fail("Worker was not added succefully: " + ex.getMessage());
        }
    }

    protected void addSoftDummySigner(final int signerId, final String signerName) throws CertificateException {
        addSoftDummySigner(signerId, signerName, KEYDATA1, CERTCHAIN1);
    }
    
    protected void addSoftTimeStampSigner(final int signerId, final String signerName) throws CertificateException {
        addSoftTimeStampSigner(signerId, signerName, KEYDATA2, CERTCHAIN2);
    }
    
    protected void addSoftSODSigner(final int signerId, final String signerName) throws CertificateException {
        addSoftSODSigner(signerId, signerName, KEYDATA1, CERTCHAIN1);
    }
    
    public void addMSTimeStampSigner(final int signerId, final String signerName, final boolean autoActivate) throws CertificateException, FileNotFoundException {
        addP12DummySigner("org.signserver.module.tsa.MSAuthCodeTimeStampSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_TSSIGNER1_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_TSSIGNER1_ALIAS);
    }
    
    public void addMSAuthCodeSigner(final int signerId, final String signerName, final boolean autoActivate) throws CertificateException, FileNotFoundException {
        addP12DummySigner("org.signserver.module.msauthcode.signer.MSAuthCodeSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_AUTHCODESIGNER1_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_AUTHCODESIGNER1_ALIAS);
    }
    
    
    public void addXMLValidator() throws Exception {
        // VALIDATION SERVICE
        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + VALIDATION_SERVICE_WORKER_ID + ".CLASSPATH", "org.signserver.validationservice.server.ValidationServiceWorker");
        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + VALIDATION_SERVICE_WORKER_ID + ".SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.HardCodedCryptoToken");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, "AUTHTYPE", "NOAUTH");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, "NAME", VALIDATION_SERVICE_WORKER_NAME);
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, "VAL1.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, "VAL1.ISSUER1.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\n" + VALIDATOR_CERT_ISSUER + "\n-----END CERTIFICATE-----\n");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, "VAL1.ISSUER2.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\n" + VALIDATOR_CERT_ISSUER4 + "\n-----END CERTIFICATE-----\n");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, "VAL1.TESTPROP", "TEST");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, "VAL1.REVOKED", "");
        getWorkerSession().reloadConfiguration(VALIDATION_SERVICE_WORKER_ID);

        // XMLVALIDATOR
        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + XML_VALIDATOR_WORKER_ID + ".CLASSPATH", "org.signserver.module.xmlvalidator.XMLValidator");
        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + XML_VALIDATOR_WORKER_ID + ".SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.SoftCryptoToken");
        getWorkerSession().setWorkerProperty(XML_VALIDATOR_WORKER_ID, "NAME", XML_VALIDATOR_WORKER_NAME);
        getWorkerSession().setWorkerProperty(XML_VALIDATOR_WORKER_ID, "AUTHTYPE", "NOAUTH");
        getWorkerSession().setWorkerProperty(XML_VALIDATOR_WORKER_ID, "VALIDATIONSERVICEWORKER", VALIDATION_SERVICE_WORKER_NAME);
        getWorkerSession().reloadConfiguration(XML_VALIDATOR_WORKER_ID);
    }
    
    public int getWorkerIdXmlValidator() {
        return XML_VALIDATOR_WORKER_ID;
    }
    
    public String getWorkerNameXmlValidator() {
        return XML_VALIDATOR_WORKER_NAME;
    }
    
    public int getWorkerIdValidationService() {
        return VALIDATION_SERVICE_WORKER_ID;
    }

    private void removeGlobalProperties(int workerid) {
        final GlobalConfiguration gc = getGlobalSession().getGlobalConfiguration();
        final Enumeration<String> en = gc.getKeyEnumeration();
        while (en.hasMoreElements()) {
            String key = en.nextElement();
            if (key.toUpperCase(Locale.ENGLISH)
                    .startsWith("GLOB.WORKER" + workerid)) {
                key = key.substring("GLOB.".length());
                getGlobalSession().removeProperty(GlobalConfiguration.SCOPE_GLOBAL, key);
            }
        }
    }

    public void removeWorker(final int workerId) throws Exception {
        removeGlobalProperties(workerId);
        WorkerConfig wc = getWorkerSession().getCurrentWorkerConfig(workerId);
        LOG.info("Got current config: " + wc.getProperties());
        final Iterator<Object> iter = wc.getProperties().keySet().iterator();
        while (iter.hasNext()) {
            final String key = (String) iter.next();
            getWorkerSession().removeWorkerProperty(workerId, key);
        }
        getWorkerSession().reloadConfiguration(workerId);  
        wc = getWorkerSession().getCurrentWorkerConfig(workerId);
        LOG.info("Got current config after: " + wc.getProperties());
    }

    public File getSignServerHome() throws FileNotFoundException {
        if (signServerHome == null) {
            final String home = System.getenv("SIGNSERVER_HOME");
            assertNotNull("SIGNSERVER_HOME", home);
            signServerHome = new File(home);
            assertTrue("SIGNSERVER_HOME exists", signServerHome.exists());
        }
        return signServerHome;
    }

    public Properties getConfig() {
        return config;
    }

    public int getPublicHTTPPort() {
        return Integer.parseInt(config.getProperty("httpserver.pubhttp"));
    }

    public int getPublicHTTPSPort() {
        return Integer.parseInt(config.getProperty("httpserver.pubhttps"));
    }

    public int getPrivateHTTPSPort() {
        return Integer.parseInt(config.getProperty("httpserver.privhttps"));
    }
    
    public String getHTTPHost() {
        return config.getProperty("httpserver.hostname", "localhost");
    }
    
    public String getPreferredHTTPProtocol() {
        return config.getProperty("httpserver.prefproto", "http://");
    }
    
    public int getPreferredHTTPPort() {
        return Integer.parseInt(config.getProperty("httpserver.prefport", config.getProperty("httpserver.pubhttp")));
    }
    
    /** @return IP used by JUnit tests to access SignServer through the HTTPHost. */
    public String getClientIP() {
        return config.getProperty("httpclient.ipaddress", "127.0.0.1");
    }

    /** Setup keystores for SSL. **/
    public void setupSSLKeystores() throws KeyStoreException, IOException, FileNotFoundException, NoSuchAlgorithmException, CertificateException, KeyManagementException, UnrecoverableKeyException {
        testUtils.setupSSLTruststore();
    }
    
    public TestUtils getTestUtils() {
        return testUtils;
    }

    /**
     * Make a GenericSignRequest.
     */
    public GenericSignResponse signGenericDocument(final int workerId, final byte[] data) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        final int requestId = random.nextInt();
        final GenericSignRequest request = new GenericSignRequest(requestId, data);
        final GenericSignResponse response = (GenericSignResponse) getWorkerSession().process(workerId, request, new RequestContext());
        assertEquals("requestId", requestId, response.getRequestID());
        Certificate signercert = response.getSignerCertificate();
        assertNotNull(signercert);
        return response;
    }

    /**
     * @return First certificate in semicolon separated list of base64 encoded certificate
     */
    private String getFirstCert(String certChain) {
        final String result; 
        if (certChain.contains(";")) {
            result = certChain.split(";")[0];
        } else {
            result = certChain;
        }
        return result;
    }
}
