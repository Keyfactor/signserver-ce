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
package org.signserver.server;

import org.apache.log4j.Logger;
import org.junit.Test;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.NotGrantedException;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.server.archive.test1archiver.Test1Signer;
import org.signserver.testutils.ModulesTestCase;

/**
 * Test cases for the Accounter feature.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AccounterTest extends ModulesTestCase {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AccounterTest.class);
    
    
    /**
     * Test the NoAccounter.
     * Basically only checks that it can be used.
     * @throws Exception 
     */
    @Test
    public void testNoAccounter() throws Exception {
        LOG.info("testNoAccounter");
        try {
            addSigner(Test1Signer.class.getName());
            
            // Setup Accounter
            getWorkerSession().setWorkerProperty(getSignerIdDummy1(), "ACCOUNTER", NoAccounter.class.getName());
            getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
            // Process
            signSomething(true, null);
            
        } finally {
            removeWorker(getSignerIdDummy1());
        }
    }
    
    /**
     * Test GlobalConfigSampleAccounter.
     * First checks that it gives not granted one no user accounts are available
     * and then tests using an account with a balance of 2 checks that it gets
     * not granted after 2 purchased requests.
     * @throws Exception 
     */
    @Test
    public void testGlobalConfigSampleAccounter() throws Exception {
        LOG.info("testGlobalConfigSampleAccounter");
        try {
            addSigner(Test1Signer.class.getName());
            
            // Setup Accounter
            getWorkerSession().setWorkerProperty(getSignerIdDummy1(), "ACCOUNTER", GlobalConfigSampleAccounter.class.getName());
            getWorkerSession().reloadConfiguration(getSignerIdDummy1());
            
            getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, "GLOBALCONFIGSAMPLEACCOUNTER_USERS", "");
            getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, "GLOBALCONFIGSAMPLEACCOUNTER_ACCOUNTS", "");
            getGlobalSession().reload();
            
            // Process
            try {
                signSomething(true, null);
                fail("Should have thrown NotGrantedException as no user exist");
            } catch (NotGrantedException expected) { // NOPMD
                // OK
            }
            
            LOG.info("Now with user account");
            getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, "GLOBALCONFIGSAMPLEACCOUNTER_USERS", "markus,foo123:account1");
            getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, "GLOBALCONFIGSAMPLEACCOUNTER_ACCOUNTS", "account1:2");
            getGlobalSession().reload();
            
            // Process
            try {
                signSomething(true, new UsernamePasswordClientCredential("markus", "foo123"));
            } catch (NotGrantedException ex) {
                fail("Purchase should have been granted but was: " + ex.getMessage());
            }
            
            // Process
            LOG.info("One more purchase");
            try {
                signSomething(true, new UsernamePasswordClientCredential("markus", "foo123"));
            } catch (NotGrantedException expected) {
                fail("Purchase should have been granted but was: " + expected.getMessage());
            }
            
            // Process
            LOG.info("Now no more credits");
            try {
                signSomething(true, new UsernamePasswordClientCredential("markus", "foo123"));
                fail("Should have thrown NotGrantedException as no more credits");
            } catch (NotGrantedException expected) { // NOPMD
                // OK
            }
            
        } finally {
            removeWorker(getSignerIdDummy1());
        }
    }
    
    /**
     * Request a signing.
     * @param success If the signer should set its WorkerFullfilledRequest flag
     * @param credential to use or null
     * @return the response
     * @throws Exception 
     */
    private ProcessResponse signSomething(final boolean success, IClientCredential credential) throws Exception {
        final String testDocument = "<document/>";
        RequestContext context = new RequestContext();
        if (!success) {
            RequestMetadata.getInstance(context).put(Test1Signer.METADATA_FAILREQUEST, "true");
        }
        if (credential != null) {
            context.put(RequestContext.CLIENT_CREDENTIAL, credential);
        }
        
        final GenericSignRequest signRequest =
                new GenericSignRequest(371, testDocument.getBytes());
        final ProcessResponse process = getWorkerSession().process(getSignerIdDummy1(),  signRequest, 
                context);
        
        return process;
    }
}
