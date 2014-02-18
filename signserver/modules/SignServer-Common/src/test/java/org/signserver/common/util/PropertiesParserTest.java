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
import java.util.List;
import java.util.Map;
import java.util.Properties;

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
            assertEquals("Number of parser errors", 2, errorMessages.size());
            assertTrue("Error message", errorMessages.contains("Error in propertyfile syntax, check : FOO.BAR"));
            assertTrue("Error message", errorMessages.contains("Error in propertyfile syntax, check : VALUE"));
            
        } catch (IOException e) {
            fail("Failed to parse properties");
        }
    }

}
