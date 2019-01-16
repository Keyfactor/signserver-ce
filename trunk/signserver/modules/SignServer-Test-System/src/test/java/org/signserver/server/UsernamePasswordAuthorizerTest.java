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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import org.apache.log4j.Logger;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.cli.spi.Command;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.client.cli.defaultimpl.SignDataGroupsCommand;
import org.signserver.client.cli.defaultimpl.SignDocumentCommand;
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

/**
 * Tests for the UsernamePasswordAuthorizer.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class UsernamePasswordAuthorizerTest extends ModulesTestCase {

    private static final Logger LOG = Logger.getLogger(
            UsernamePasswordAuthorizerTest.class);

    private final WorkerSession workerSession = getWorkerSession();
    private final ProcessSessionRemote processSession = getProcessSession();
    
    @Before
    @Override
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        // Dummy Signer
        addDummySigner1(true);

        // Set auth type
        workerSession.setWorkerProperty(getSignerIdDummy1(), "AUTHTYPE",
                "org.signserver.server.UsernamePasswordAuthorizer");

        // Add a user account: user1, foo123 (plain-text password)
        workerSession.setWorkerProperty(getSignerIdDummy1(), "USER.USER1",
                "foo123");
        
        // Add a user account: user2, foo123 (SHA1 hashed password) = SHA1(foo123)
        workerSession.setWorkerProperty(getSignerIdDummy1(), "USER.USER2",
                "3b303d8b0364d9265c06adc8584258376150c9b5:SHA1");

        // Add a user account: user3, foo123 (SHA1 hashed password and salted 
        // with "salt123") = SHA1(foo123salt123)
        workerSession.setWorkerProperty(getSignerIdDummy1(), "USER.USER3",
                "26c110963ad873c9b7db331e4c3130c266416d47:SHA1:salt123");
        
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        // MRTD SOD Signer
        addSigner("org.signserver.module.mrtdsodsigner.MRTDSODSigner", getSignerIdSODSigner1(), getSignerNameSODSigner1(), true);
        
        // Set auth type
        workerSession.setWorkerProperty(getSignerIdSODSigner1(), "AUTHTYPE",
                "org.signserver.server.UsernamePasswordAuthorizer");
        
        workerSession.setWorkerProperty(getSignerIdSODSigner1(), "USER.USER3",
                "26c110963ad873c9b7db331e4c3130c266416d47:SHA1:salt123");
        
        
        workerSession.reloadConfiguration(getSignerIdSODSigner1());
    }

    /**
     * Tests that the worker throws an AuthorizationRequiredException if no
     * username/password is supplied.
     * @throws Exception in case of exception
     */
    @Test
    public void test01AuthorizationRequired() throws Exception {
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

        // With wrong password
        context.setUsername("user1");
        context.setPassword("FOO1234");
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
     * @throws Exception in case of exception
     */
    @Test
    public void test02PlainTextPassword() throws Exception {
        final RemoteRequestContext context = new RemoteRequestContext();

        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        // With correct username password
        context.setUsername("user1");
        context.setPassword("foo123");
        try {
             processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, context);
        } catch (AuthorizationRequiredException ex) {
            fail("Username password not accepted!");
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }
    }

     /**
     * Tests that the worker accepts a correct user/password.
     * @throws Exception in case of exception
     */
    @Test
    public void test03HashedPassword() throws Exception {
        final RemoteRequestContext context = new RemoteRequestContext();

        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        // With correct username password
        context.setUsername("user2");
        context.setPassword("foo123");
        try {
             processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, context);
        } catch (AuthorizationRequiredException ex) {
            fail("Username password not accepted!");
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }
    }

    /**
     * Tests that the worker accepts a correct user/password.
     * @throws Exception in case of exception
     */
    @Test
    public void test04HashedAndSaltedPassword() throws Exception {
        final RemoteRequestContext context = new RemoteRequestContext();

        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        // With correct username password
        context.setUsername("user3");
        context.setPassword("foo123");
        try {
             processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, context);
        } catch (AuthorizationRequiredException ex) {
            fail("Username password not accepted!");
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }
    }
    
    @Test
    public void test04HashedAndSaltedPasswordOverClientWS() throws Exception {
        try {
            byte[] res = execute(new SignDocumentCommand(), "signdocument", "-workerid", 
                    String.valueOf(getSignerIdDummy1()), "-data", "<root/>",
                    "-username", "user3", "-password", "foo123", "-protocol", "CLIENTWS",
                    "-truststore", new File(getSignServerHome(), "p12/truststore.jks").getAbsolutePath(), "-truststorepwd", "changeit",
                    "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort()));
            assertNotNull("No result", res);
            assertNotSame("Empty result", 0, res.length);
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }
    
    @Test
    public void test04HashedAndSaltedPasswordSODOverClientWS() throws Exception {
        workerSession.setWorkerProperty(getSignerIdSODSigner1(), "DODATAGROUPHASHING", "true");
        workerSession.reloadConfiguration(getSignerIdSODSigner1());
        try {
            byte[] res = execute(new SignDataGroupsCommand(), "signdatagroups", "-workerid",
                    String.valueOf(getSignerIdSODSigner1()), "-data", "1=value1&2=value2&3=value3",
                    "-username", "user3", "-password", "foo123", "-protocol", "CLIENTWS",
                    "-truststore", new File(getSignServerHome(), "p12/truststore.jks").getAbsolutePath(), "-truststorepwd", "changeit",
                    "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort()));
            assertNotNull("No result", res);
            assertNotSame("Empty result", 0, res.length);
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        } finally {
            workerSession.setWorkerProperty(getSignerIdSODSigner1(), "DODATAGROUPHASHING", "false");
            workerSession.reloadConfiguration(getSignerIdSODSigner1());
        }
    }
    
    @Test
    public void test04HashedAndSaltedPasswordSODOverHTTP() throws Exception {
        workerSession.setWorkerProperty(getSignerIdSODSigner1(), "DODATAGROUPHASHING", "true");
        workerSession.reloadConfiguration(getSignerIdSODSigner1());
        try {
            byte[] res = execute(new SignDataGroupsCommand(), "signdatagroups", "-workerid",
                    String.valueOf(getSignerIdSODSigner1()), "-data", "1=value1&2=value2&3=value3",
                    "-username", "user3", "-password", "foo123", "-protocol", "HTTP",
                    "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPPort()));
            assertNotNull("No result", res);
            assertNotSame("Empty result", 0, res.length);
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        } finally {
            workerSession.setWorkerProperty(getSignerIdSODSigner1(), "DODATAGROUPHASHING", "false");
            workerSession.reloadConfiguration(getSignerIdSODSigner1());
        }
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
        workerSession.reloadConfiguration(getSignerIdDummy1());
        removeWorker(getSignerIdSODSigner1());
        workerSession.reloadConfiguration(getSignerIdSODSigner1());
    }
   
    private byte[] execute(Command command, String... args) throws IOException, IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        byte[] output;
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        try {
            command.execute(args);
        } finally {
            output = out.toByteArray();
            System.setOut(System.out);
            System.out.write(output);
        }
        return output;
    }
    
}
