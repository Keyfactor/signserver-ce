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
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests for the UsernameAuthorizer.
 *
 *
 * @author Markus Kilas
 * @version $Id$
 */
public class UsernameAuthorizerTest extends ModulesTestCase {

    private static final Logger LOG = Logger.getLogger(
            UsernameAuthorizerTest.class);

    @Override
    protected void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Override
    protected void tearDown() throws Exception {
    }

    public void test00SetupDatabase() throws Exception {
        addDummySigner1();

        // Set auth type
        workerSession.setWorkerProperty(getSignerIdDummy1(), "AUTHTYPE",
                "org.signserver.server.UsernameAuthorizer");

        workerSession.reloadConfiguration(getSignerIdDummy1());
    }

    /**
     * Tests that the worker throws an AuthorizationRequiredException if no
     * username is supplied.
     * @throws Exception in case of exception
     */
    public void test01AuthorizationRequired() throws Exception {

        final RequestContext context = new RequestContext();

        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        // Without username password
        try {
            workerSession.process(getSignerIdDummy1(), request, context);
            fail("No AuthorizationRequiredException thrown");
        } catch (AuthorizationRequiredException ok) {
            // OK
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With other type of credentials

        context.put(RequestContext.CLIENT_CREDENTIAL, new DummyCredential());
        try {
            workerSession.process(getSignerIdDummy1(), request, context);
            fail("No AuthorizationRequiredException thrown");
        } catch (AuthorizationRequiredException ok) {
            // OK
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With wrong username
        context.put(RequestContext.CLIENT_CREDENTIAL,
                new UsernamePasswordClientCredential("non-extising-username",
                ""));
        try {
            workerSession.process(getSignerIdDummy1(), request, context);
            fail("No AuthorizationRequiredException thrown");
        } catch (AuthorizationRequiredException ok) {
            // OK
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }
    }

    /**
     * Tests that the worker accepts a correct user/password.
     * @throws Exception in case of exception
     */
    public void test02AcceptUsernames() throws Exception {

        // Add users
        workerSession.setWorkerProperty(getSignerIdDummy1(), "ACCEPT_USERNAMES", "user1;user2;user3");
        workerSession.reloadConfiguration(getSignerIdDummy1());


        final RequestContext context = new RequestContext();
        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        // With correct username user1
        context.put(RequestContext.CLIENT_CREDENTIAL,
                new UsernamePasswordClientCredential("user1", ""));
        try {
            workerSession.process(getSignerIdDummy1(), request, context);
        } catch (AuthorizationRequiredException ex) {
            fail("Username not accepted!");
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With wrong username
        context.put(RequestContext.CLIENT_CREDENTIAL,
                new UsernamePasswordClientCredential("non-extising-username2",
                ""));
        try {
            workerSession.process(getSignerIdDummy1(), request, context);
            fail("No AuthorizationRequiredException thrown");
        } catch (AuthorizationRequiredException ok) {
            // OK
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With correct username user2
        context.put(RequestContext.CLIENT_CREDENTIAL,
                new UsernamePasswordClientCredential("user2", ""));
        try {
            workerSession.process(getSignerIdDummy1(), request, context);
        } catch (AuthorizationRequiredException ex) {
            fail("Username not accepted!");
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With correct username user3
        context.put(RequestContext.CLIENT_CREDENTIAL,
                new UsernamePasswordClientCredential("user3", ""));
        try {
            workerSession.process(getSignerIdDummy1(), request, context);
        } catch (AuthorizationRequiredException ex) {
            fail("Username not accepted!");
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With wrong username
        context.put(RequestContext.CLIENT_CREDENTIAL,
                new UsernamePasswordClientCredential("",
                ""));
        try {
            workerSession.process(getSignerIdDummy1(), request, context);
            fail("No AuthorizationRequiredException thrown");
        } catch (AuthorizationRequiredException ok) {
            // OK
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With wrong username
        context.put(RequestContext.CLIENT_CREDENTIAL,
                new UsernamePasswordClientCredential(null,
                ""));
        try {
            workerSession.process(getSignerIdDummy1(), request, context);
            fail("No AuthorizationRequiredException thrown");
        } catch (AuthorizationRequiredException ok) {
            // OK
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }
    }

    /**
     * Tests that the worker accepts any username.
     * @throws Exception in case of exception
     */
    public void test03AcceptAll() throws Exception {

        // Add users
        workerSession.setWorkerProperty(getSignerIdDummy1(), "ACCEPT_ALL_USERNAMES", "true");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "ACCEPT_USERNAMES");
        workerSession.reloadConfiguration(getSignerIdDummy1());

        final RequestContext context = new RequestContext();
        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        // With correct username anything1
        context.put(RequestContext.CLIENT_CREDENTIAL,
                new UsernamePasswordClientCredential("anything1", ""));
        try {
            workerSession.process(getSignerIdDummy1(), request, context);
        } catch (AuthorizationRequiredException ex) {
            fail("Username not accepted!");
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With correct username anything2
        context.put(RequestContext.CLIENT_CREDENTIAL,
                new UsernamePasswordClientCredential("anything2", ""));
        try {
            workerSession.process(getSignerIdDummy1(), request, context);
        } catch (AuthorizationRequiredException ex) {
            fail("Username not accepted!");
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }
    }

    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
        workerSession.reloadConfiguration(getSignerIdDummy1());
    }
}
