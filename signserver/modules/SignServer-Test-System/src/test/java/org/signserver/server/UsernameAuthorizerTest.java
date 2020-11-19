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
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.SignServerUtil;
import org.signserver.testutils.ModulesTestCase;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSession;

import static org.junit.Assert.fail;

/**
 * Tests for the UsernameAuthorizer.
 *
 *
 * @author Markus Kilas
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class UsernameAuthorizerTest extends ModulesTestCase {

    private static final Logger LOG = Logger.getLogger(
            UsernameAuthorizerTest.class);

    private final WorkerSession workerSession = getWorkerSession();
    private final ProcessSessionRemote processSession = getProcessSession();

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        addDummySigner1(true);

        // Set auth type
        workerSession.setWorkerProperty(getSignerIdDummy1(), "AUTHTYPE",
                "org.signserver.server.UsernameAuthorizer");

        workerSession.reloadConfiguration(getSignerIdDummy1());
    }

    /**
     * Tests that the worker throws an AuthorizationRequiredException if no
     * username is supplied.
     */
    @Test
    public void test01AuthorizationRequired() {
        final RemoteRequestContext context = new RemoteRequestContext();

        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        // Without username password
        try {
            processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, context);
            fail("No AuthorizationRequiredException thrown");
        } catch (AuthorizationRequiredException ok) {
            // OK
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With wrong username
        context.setUsername("non-existing-username");
        context.setPassword("");
        try {
            processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, context);
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
     */
    @Test
    public void test02AcceptUsernames() {
        // Add users
        workerSession.setWorkerProperty(getSignerIdDummy1(), "ACCEPT_USERNAMES", "user1;user2;user3");
        workerSession.reloadConfiguration(getSignerIdDummy1());

        final RemoteRequestContext context = new RemoteRequestContext();
        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        // With correct username user1
        context.setUsername("user1");
        context.setPassword("");
        try {
            processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, context);
        } catch (AuthorizationRequiredException ex) {
            fail("Username not accepted!");
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With wrong username
        context.setUsername("non-extising-username2");
        context.setPassword("");
        try {
            processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, context);
            fail("No AuthorizationRequiredException thrown");
        } catch (AuthorizationRequiredException ok) {
            // OK
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With correct username user2
        context.setUsername("user2");
        context.setPassword("");
        try {
            processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, context);
        } catch (AuthorizationRequiredException ex) {
            fail("Username not accepted!");
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With correct username user3
        context.setUsername("user3");
        context.setPassword(null);
        try {
            processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, context);
        } catch (AuthorizationRequiredException ex) {
            fail("Username not accepted!");
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With wrong username
        context.setUsername("");
        context.setPassword("");
        try {
            processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, context);
            fail("No AuthorizationRequiredException thrown");
        } catch (AuthorizationRequiredException ok) {
            // OK
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With wrong username
        context.setUsername(null);
        context.setPassword("");
        try {
            processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, context);
            fail("No AuthorizationRequiredException thrown");
        } catch (AuthorizationRequiredException ok) {
            // OK
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With wrong username
        context.setUsername(null);
        context.setPassword(null);
        try {
            processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, context);
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
     */
    @Test
    public void test03AcceptAll() {
        // Add users
        workerSession.setWorkerProperty(getSignerIdDummy1(), "ACCEPT_ALL_USERNAMES", "true");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "ACCEPT_USERNAMES");
        workerSession.reloadConfiguration(getSignerIdDummy1());

        final RemoteRequestContext context = new RemoteRequestContext();
        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        // With correct username anything1
        context.setUsername("anything1");
        context.setPassword("");
        try {
            processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, context);
        } catch (AuthorizationRequiredException ex) {
            fail("Username not accepted!");
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

        // With correct username anything2
        context.setUsername("anything2");
        context.setPassword("");
        try {
            processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, context);
        } catch (AuthorizationRequiredException ex) {
            fail("Username not accepted!");
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
        workerSession.reloadConfiguration(getSignerIdDummy1());
    }
}
