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
    
    private static String correctConfig =
            "# some comments...\n" +
            "\n" + // an empty line
            "GLOB.WORKER42.CLASSPATH = foo.bar.Worker\n" +
            "GLOB.WORKER42.SIGNERTOKEN.CLASSPATH = foo.bar.Token\n" +
            "WORKER42.FOOBAR = Some value\n" +
            "WORKERFOO.BAR = VALUE\n" +
            "-WORKER42.REMOVED = REMOVEDVALUE\n" +
            "SIGNER4711.OLDKEY = OLDVALUE\n" +
            "WORKER42.AUTHCLIENT = 12345678;CN=Authorized";
            
    
    private static String incorrectConfig =
            "FOO.BAR = FOOBAR\n" +
            "VALUE\n";

    private boolean containsGlobalProperty(final String scope, final String key,
                                            final String value,
                                            final Map<GlobalProperty, String> props) {
        final String foundValue = props.get(new GlobalProperty(scope, key));
        
        return foundValue != null && foundValue.equals(value);
    }
    
    private boolean containsWorkerProperty(final String workerIdOrName,
            final String key, final String value, final Map<WorkerProperty, String> props) {
        final String foundValue = props.get(new WorkerProperty(workerIdOrName, key));
        
        return foundValue != null && foundValue.equals(value);
    }
    
    private boolean containsWorkerProperty(final String workerIdOrName, final String key,
            final List<WorkerProperty> props) {
        return props.contains(new WorkerProperty(workerIdOrName, key));
    }
    
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
            
            final Map<GlobalProperty, String> globalProps = parser.getSetGlobalProperties();
            final Map<WorkerProperty, String> setWorkerProps = parser.getSetWorkerProperties();
            final List<WorkerProperty> removeWorkerProps = parser.getRemoveWorkerProperties();
            final Map<String, List<AuthorizedClient>> addAuthClients = parser.getAddAuthorizedClients();
            
            assertEquals("Number of global properties", 2, globalProps.size());
            assertEquals("Number of worker properties", 3, setWorkerProps.size());
            assertEquals("Number of removed worker properties", 1, removeWorkerProps.size());
            
            assertTrue("Should contain global property",
                    containsGlobalProperty("GLOB.", "WORKER42.CLASSPATH",
                            "foo.bar.Worker", globalProps));
            assertTrue("Should contain global property",
                    containsGlobalProperty("GLOB.", "WORKER42.SIGNERTOKEN.CLASSPATH",
                            "foo.bar.Token", globalProps));
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
