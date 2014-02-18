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
package org.signserver.common.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.util.PropertiesParser;
import org.signserver.common.util.PropertiesParser.GlobalProperty;
import org.signserver.common.util.PropertiesParser.WorkerProperty;

import junit.framework.TestCase;

/**
 * Unit tests for the properties parser.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class PropertiesParserTest extends TestCase {
    
    private static String SIGNER_CERT =
            "MIIEkTCCAnmgAwIBAgIIeCvAS5OwAJswDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzEyMTU1NVoXDTIxMDUyNDEyMTU1NVowSjEUMBIGA1UEAwwLVFMgU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnT38GG8i/bGnuFMwnOdg+caHMkdPBacRdBaIggwMPfE50SOZ2TLrDEHJotxYda7HS0+tX5dIcalmEYCls/ptHzO5TQpqdRTuTqxp5cMA379yhD0OqTVNAmHrvPj9IytktoAtB/xcjwkRTHagaCmg5SWNcLKyVUct7nbeRA5yDSJQsCAEGHNZbJ50vATg1DQEyKT87GKfSBsclA0WIIIHMt8/SRhpsUZxESayU6YA4KCxVtexF5x+COLB6CzzlRG9JA8WpX9yKgIMsMDAscsJLiLPjhET5hwAFm5ZRfQQG9LI06QNTGqukuTlDbYrQGAUR5ZXW00WNHfgS00CjUCu0QIDAQABo3gwdjAdBgNVHQ4EFgQUOF0FflO2G+IN6c92pCNlPoorGVwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADELkeIO9aiKjS/GaBUUhMr+k5UbVeK69WapU+7gTsWwa9D2vAOhAkfQ1OcUJoZaminv8pcNfo1Ey5qLtxBCmUy1fVomVWOPl6u1w8B6uYgE608hi2bfx28uIeksqpdqUX0Qf6ReUyl+FOh4xNrsyaF81TrIKt8ekq0iD+YAtT/jqgv4bUvs5fgIms4QOXgMUzNAP7cPU44KxcmR5I5Uy/Ag82hGIz64hZmeIDT0X59kbQvlZqFaiZvYOikoZSFvdM5kSVfItMgp7qmyLxuM/WaXqJWp6Mm+8ZZmcECugd4AEpE7xIiB7M/KEe+X4ItBNTKdAoaxWa+yeuYS7ol9rHt+Nogelj/06ZRQ0x03UqC7uKpgYAICjQEXIjcZofWSTh9KzKNfS1sQyIQ6yNTT2VMdYW9JC2OLKPV4AEJuBw30X8HOciJRRXOq9KRrIA2RSiaC5/3oAYscWuo31Fmj8CWQknXAIb39gPuZRwGOJbi1tUu2zmRsUNJfAe3hnvk+uxhnyp2vKB2KN5/VQgisx+8doEK/+Nbj/PPG/zASKimWG++5m0JNY4chIfR43gDDcF+4INof/8V84wbvUF+TpvP/mYM8wC9OkUyRvzqv9vjWOncCdbdjCuqPxDItwm9hhr+PbxsMaBes9rAiV9YT1FnpA++YpCufveFCQPDbCTgJ";
    
    private static String SIGNER_CERT_CHAIN =
            "MIIEkTCCAnmgAwIBAgIIeCvAS5OwAJswDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzEyMTU1NVoXDTIxMDUyNDEyMTU1NVowSjEUMBIGA1UEAwwLVFMgU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnT38GG8i/bGnuFMwnOdg+caHMkdPBacRdBaIggwMPfE50SOZ2TLrDEHJotxYda7HS0+tX5dIcalmEYCls/ptHzO5TQpqdRTuTqxp5cMA379yhD0OqTVNAmHrvPj9IytktoAtB/xcjwkRTHagaCmg5SWNcLKyVUct7nbeRA5yDSJQsCAEGHNZbJ50vATg1DQEyKT87GKfSBsclA0WIIIHMt8/SRhpsUZxESayU6YA4KCxVtexF5x+COLB6CzzlRG9JA8WpX9yKgIMsMDAscsJLiLPjhET5hwAFm5ZRfQQG9LI06QNTGqukuTlDbYrQGAUR5ZXW00WNHfgS00CjUCu0QIDAQABo3gwdjAdBgNVHQ4EFgQUOF0FflO2G+IN6c92pCNlPoorGVwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADELkeIO9aiKjS/GaBUUhMr+k5UbVeK69WapU+7gTsWwa9D2vAOhAkfQ1OcUJoZaminv8pcNfo1Ey5qLtxBCmUy1fVomVWOPl6u1w8B6uYgE608hi2bfx28uIeksqpdqUX0Qf6ReUyl+FOh4xNrsyaF81TrIKt8ekq0iD+YAtT/jqgv4bUvs5fgIms4QOXgMUzNAP7cPU44KxcmR5I5Uy/Ag82hGIz64hZmeIDT0X59kbQvlZqFaiZvYOikoZSFvdM5kSVfItMgp7qmyLxuM/WaXqJWp6Mm+8ZZmcECugd4AEpE7xIiB7M/KEe+X4ItBNTKdAoaxWa+yeuYS7ol9rHt+Nogelj/06ZRQ0x03UqC7uKpgYAICjQEXIjcZofWSTh9KzKNfS1sQyIQ6yNTT2VMdYW9JC2OLKPV4AEJuBw30X8HOciJRRXOq9KRrIA2RSiaC5/3oAYscWuo31Fmj8CWQknXAIb39gPuZRwGOJbi1tUu2zmRsUNJfAe3hnvk+uxhnyp2vKB2KN5/VQgisx+8doEK/+Nbj/PPG/zASKimWG++5m0JNY4chIfR43gDDcF+4INof/8V84wbvUF+TpvP/mYM8wC9OkUyRvzqv9vjWOncCdbdjCuqPxDItwm9hhr+PbxsMaBes9rAiV9YT1FnpA++YpCufveFCQPDbCTgJ;MIIFfzCCA2egAwIBAgIIMk1BOK8CwTwwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA4MTQyN1oXDTM2MDUyNzA4MTQyN1owTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgblgjTTkMp1QAhgWDprhvqE9zX1Ux/A/RTOu4G4f6CTkd6JEEkbdKZv+CKv4cRoVCtfO3wnOokFRw/1JMmHHiQ1Z//uDoDjo8jk8nek0ArFE9R5NT02wMJCQa/mP1wU9ZSl1tx3jQRUFB+rTNeCcPTft+1FL7UjYMdkRzl261IOlmXzDMA+EYIGJ2c2wYhOv2DqfQygNz5GOf0EFqlQZIt/pzopSS+0K8mNb53ROhg9GJujwzugSH5Z+r0fsVHbCV0QUkZBfkRo9KMcdaDEPa8xpYTjsFPqU6RcnGkVABhn8OS8SIWw2re1f+htj6p9EGbk1m0I9pWGBA9ktWnrqlqDXV+tEhhh1O4f+LHieoxiscrF7RXxlYqyam6oabfXsX3VAC0M1UkwIciE8wA1Sj/+dgoSMqvEDNDfwpEYt6l8Z8czDTWDi7MM2u5VY0nP3+A+PepKrOtrdaGSP396f4a7A3un1o6nQWHsyWQ7kc8GIn8zN5nykQaghGyYlHHYe1XUSPtHmxjbdsyztrkIis3cfjFne0XgPAiQuYx3T/B+po9BhGIUwCV0Qi/gWVN6NkydsbzMeRXELQYyK+lHgIGiEaBzQRRtXbnB+wQXi2IacJNdKqICwDsl/PvvcZI9ZV6pB/KIzB+8IJm0CLY24K0OXJs3Bqij8gmpvbI+o0wUCAwEAAaNjMGEwHQYDVR0OBBYEFCB6Id7orbsCqPtxWKQJYrnYWAWiMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUIHoh3uituwKo+3FYpAliudhYBaIwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQAxFvpOZF6Kol48cQeKWQ48VAe+h5dmyKMfDLDZX51IRzfKKsHLpFPxzGNw4t9Uv4YOR0CD9z81dR+c93t1lwwIpKbx9Qmq8jViHEHKYD9FXThM+cVpsT25pg35m3ONeUX/b++l2d+2QNNTWMvdsCtaQdybZqbYFIk0IjPwLLqdsA8Io60kuES4JnQahPdLkfm70rgAdmRDozOfSDaaWHY20DovkfvKUYjPR6MGAPD5w9dEb4wp/ZjATblyZnH+LTflwfftUAonmAw46E0Zgg143sO6RfOOnbwjXEc+KXd/KQ6kTQ560mlyRd6q7EIDYRfD4n4agKV2R5gvVPhMD0+IK7kagqKNfWa9z8Ue2N3MedyWnb9wv4wC69qFndGaIfYADkUykoOyLsVVteJ70PVJPXO7s66LucfD2R0wo2MpuOYCsTOm7HHS+uZ9VjHl2qQ0ZQG89Xn+AXnzPbk1INe2z0lq3hzCW5DTYBKsJEexErzMpLwiEqUYJUfR9EeCM8UPMtLSqz1utdPoIYhULGzt5lSJEpMHMbquYfWJxQiKCbvfxQsP5dLUMEIqTgjNdo98OlM7Z7zjYH9Kimz3wgAKSAIoQZr7Oy1dMHO5GK4jBtZ8wgsyyQ6DzQQ7R68XFVKarIW8SATeyubAP+WjdMwk/ZXzsDjMZEtENaBXzAefYA==";
    
    /**
     * A correct properties file that should pass the properties parser.
     */
    private static String correctConfig =
            "# some comments...\n" +
            "\n" + // an empty line
            "GLOB.WORKER42.CLASSPATH = foo.bar.Worker\n" +
            "GLOB.WORKER42.SIGNERTOKEN.CLASSPATH = foo.bar.Token\n" +
            "WORKER42.FOOBAR = Some value\n" +
            "WORKERFOO.BAR = VALUE\n" +
            "-WORKER42.REMOVED = REMOVEDVALUE\n" +
            "SIGNER4711.OLDKEY = OLDVALUE\n" +
            "WORKER42.AUTHCLIENT1 = 12345678;CN=Authorized\n" +
            "WORKER42.AUTHCLIENT2 = 23456789;CN=Authorized2\n" +
            "WORKER42.SIGNERCERTIFICATE = " + SIGNER_CERT + "\n" +
            "WORKER42.SIGNERCERTCHAIN = " + SIGNER_CERT_CHAIN + "\n" +
            "-WORKER42.AUTHCLIENT = 987654321;CN=Denied\n" +
            "NODE.NODE1.KEY = VALUE\n" +
            "-GLOB.REMOVED_GLOB = REMOVEDVALUE";
            
    
    /**
     * A properties file that should generate parser errors.
     */
    private static String incorrectConfig =
            "FOO.BAR = FOOBAR\n" +
            "VALUE\n";

    /**
     * Check if a given global property is included in the result map, as returned by the parser.
     * 
     * @param scope
     * @param key
     * @param value
     * @param props Property map returned by a PropertiesParser
     * @return True if the property was found
     */
    private boolean containsGlobalProperty(final String scope, final String key,
            final String value, final Map<GlobalProperty, String> props) {
        final String foundValue = props.get(new GlobalProperty(scope, key));
        
        return foundValue != null && foundValue.equals(value);
    }
    
    /**
     * Check if a given global property is included in the result list, as returned by the parser.
     * 
     * @param scope
     * @param key
     * @param props
     * @return True if the given property was found
     */
    private boolean containsGlobalProperty(final String scope, final String key,
            final List<GlobalProperty> props) {
        return props.contains(new GlobalProperty(scope, key));
    }
    
    /**
     * Check if a given worker property is included in the result map, as returned by the parser.
     * 
     * @param workerIdOrName
     * @param key
     * @param value
     * @param props Property map returned by a PropertiesParser
     * @return True if the property was found in the map
     */
    private boolean containsWorkerProperty(final String workerIdOrName,
            final String key, final String value, final Map<WorkerProperty, String> props) {
        final String foundValue = props.get(new WorkerProperty(workerIdOrName, key));
        
        return foundValue != null && foundValue.equals(value);
    }
    
    /**
     * Check if a given worker property is included in a list of removed properties, as returned by the parser.
     * @param workerIdOrName
     * @param key
     * @param props Property list as returned by a PropertiesParser
     * @return True if the property is found in the list
     */
    private boolean containsWorkerProperty(final String workerIdOrName, final String key,
            final List<WorkerProperty> props) {
        return props.contains(new WorkerProperty(workerIdOrName, key));
    }
    
    /**
     * Check if a given auth client is included in the mapping given a worker ID or name, as given by the parser.
     * 
     * @param workerIdOrName
     * @param authClient Auth client to match
     * @param authClients Map of worker ID or name to list of authclients
     * @return True if the authclient is found for the given worker
     */
    private boolean containsAuthClientForWorker(final String workerIdOrName,
            final AuthorizedClient authClient,
            final Map<String, List<AuthorizedClient>> authClients) {
        final List<AuthorizedClient> acs = authClients.get(workerIdOrName);
        
        if (acs != null) {
            return acs.contains(authClient);
        }
        return false;
    }
            
    
    public void testParsingCorrect() throws Exception {
        final Properties prop = new Properties();
        final PropertiesParser parser = new PropertiesParser();
        
        try {
            prop.load(new ByteArrayInputStream(correctConfig.getBytes()));
            parser.process(prop);
            
            final Map<GlobalProperty, String> setGlobalProps = parser.getSetGlobalProperties();
            final List<GlobalProperty> removeGlobalProps = parser.getRemoveGlobalProperties();
            final Map<WorkerProperty, String> setWorkerProps = parser.getSetWorkerProperties();
            final List<WorkerProperty> removeWorkerProps = parser.getRemoveWorkerProperties();
            final Map<String, List<AuthorizedClient>> addAuthClients = parser.getAddAuthorizedClients();
            final Map<String, List<AuthorizedClient>> removeAuthClients = parser.getRemoveAuthorizedClients();
            
            final Map<String, byte[]> certs = parser.getSignerCertificates();
            final Map<String, List<byte[]>> certChains = parser.getSignerCertificateChains();
            
            assertFalse("Has no errors", parser.hasErrors());
            
            assertEquals("Number of global properties", 3, setGlobalProps.size());
            assertEquals("Number of removed global properties", 1, removeGlobalProps.size());
            assertEquals("Number of worker properties", 3, setWorkerProps.size());
            assertEquals("Number of removed worker properties", 1, removeWorkerProps.size());
            
            assertTrue("Should contain global property",
                    containsGlobalProperty("GLOB.", "WORKER42.CLASSPATH",
                            "foo.bar.Worker", setGlobalProps));
            assertTrue("Should contain global property",
                    containsGlobalProperty("GLOB.", "WORKER42.SIGNERTOKEN.CLASSPATH",
                            "foo.bar.Token", setGlobalProps));
            assertTrue("Should contain worker property",
                    containsWorkerProperty("42", "FOOBAR", "Some value",
                            setWorkerProps));
            assertTrue("Should contain worker property",
                    containsWorkerProperty("FOO", "BAR", "VALUE", setWorkerProps));
            assertTrue("Should contain worker property",
                    containsWorkerProperty("42", "REMOVED", removeWorkerProps));
            assertTrue("Should contain worker property",
                    containsWorkerProperty("4711", "OLDKEY", "OLDVALUE", setWorkerProps));
            assertEquals("Workers with added auth clients", 1, addAuthClients.size());
            assertTrue("Should contain auth client",
                    containsAuthClientForWorker("42", new AuthorizedClient("12345678", "CN=Authorized"), addAuthClients));
            assertTrue("Should contain auth client",
                    containsAuthClientForWorker("42", new AuthorizedClient("23456789", "CN=Authorized2"), addAuthClients));
            assertEquals("Workers with removed auth clients", 1, removeAuthClients.size());
            assertTrue("Should contain auth client",
                    containsAuthClientForWorker("42", new AuthorizedClient("987654321", "CN=Denied"), removeAuthClients));
            assertTrue("Should contain global property with NODE prefix",
                    containsGlobalProperty("NODE.", "NODE1.KEY", "VALUE", setGlobalProps));
            assertTrue("Should contain removed global property",
                    containsGlobalProperty("GLOB.", "REMOVED_GLOB", removeGlobalProps));
            
            assertEquals("Number of signer certificates", 1, certs.size());
            assertTrue("Cert data match", Arrays.equals(Base64.decode(SIGNER_CERT.getBytes()), certs.get("42")));
            
            final List<byte[]> certChain = certChains.get("42");
            assertEquals("Number of certificates in chain", 2, certChain.size());
            
        } catch (IOException e) {
            fail("Failed to parse properties");
        }
    }
    
    public void testParsingIncorrect() {
        final Properties prop = new Properties();
        final PropertiesParser parser = new PropertiesParser();
        
        try {
            prop.load(new ByteArrayInputStream(incorrectConfig.getBytes()));
            parser.process(prop);
            
            final List<String> errorMessages = parser.getErrors();
            assertTrue("Has errors", parser.hasErrors());
            assertEquals("Number of parser errors", 2, errorMessages.size());
            assertTrue("Error message", errorMessages.contains("Error in propertyfile syntax, check : FOO.BAR"));
            assertTrue("Error message", errorMessages.contains("Error in propertyfile syntax, check : VALUE"));
            
        } catch (IOException e) {
            fail("Failed to parse properties");
        }
    }

}
