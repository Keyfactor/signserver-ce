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

import java.io.File;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.InitialContext;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Tests for the UsernameAuthorizer.
 *
 *
 * @author Markus Kilas
 * @version $Id: TestUsernamePasswordAuthorizer.java 898 2010-03-21 10:38:56Z netmackan $
 */
public class TestUsernameAuthorizer extends TestCase {

    private static final Logger LOG = Logger.getLogger(
            TestUsernameAuthorizer.class);

    private static IGlobalConfigurationSession.IRemote confSession;
    private static IWorkerSession.IRemote workSession;
    private static File signServerHome;
    private static int moduleVersion;

    /**
     * WORKERID used in this test case as defined in
     * junittest-part-config.properties
     */
    private static final int WORKERID = 5676;

    @Override
    protected void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        final Context context = getInitialContext();
        confSession = (IGlobalConfigurationSession.IRemote) context.lookup(
                IGlobalConfigurationSession.IRemote.JNDI_NAME);
        workSession = (IWorkerSession.IRemote) context.lookup(
                IWorkerSession.IRemote.JNDI_NAME);
        TestUtils.redirectToTempOut();
        TestUtils.redirectToTempErr();
        CommonAdminInterface.BUILDMODE = "SIGNSERVER";
    }

    @Override
    protected void tearDown() throws Exception {
    }

    public void test00SetupDatabase() throws Exception {

        System.out.println("File: " + getSignServerHome()
                + "/dist-server/xmlsigner.mar");

        final MARFileParser marFileParser = new MARFileParser(getSignServerHome()
                + "/dist-server/xmlsigner.mar");
        moduleVersion = marFileParser.getVersionFromMARFile();

        TestUtils.assertSuccessfulExecution(new String[] {
                "module",
                "add",
                getSignServerHome() + "/dist-server/xmlsigner.mar",
                "junittest"
            });
        assertTrue("Loading module",
                TestUtils.grepTempOut("Loading module XMLSIGNER"));
        assertTrue("Module loaded",
                TestUtils.grepTempOut("Module loaded successfully."));

        // Set auth type
        workSession.setWorkerProperty(WORKERID, "AUTHTYPE",
                "org.signserver.server.UsernameAuthorizer");

        workSession.reloadConfiguration(WORKERID);
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

        GenericSignResponse res;

        // Without username password
        try {
             res = (GenericSignResponse) workSession.process(WORKERID,
                    request, context);
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
             res = (GenericSignResponse) workSession.process(WORKERID,
                    request, context);
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
             res = (GenericSignResponse) workSession.process(WORKERID,
                    request, context);
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
        workSession.setWorkerProperty(WORKERID, "ACCEPT_USERNAMES", "user1;user2;user3");
        workSession.reloadConfiguration(WORKERID);


        final RequestContext context = new RequestContext();
        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        GenericSignResponse res;

        // With correct username user1
        context.put(RequestContext.CLIENT_CREDENTIAL,
                new UsernamePasswordClientCredential("user1", ""));
        try {
             res = (GenericSignResponse) workSession.process(WORKERID,
                    request, context);
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
             res = (GenericSignResponse) workSession.process(WORKERID,
                    request, context);
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
             res = (GenericSignResponse) workSession.process(WORKERID,
                    request, context);
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
             res = (GenericSignResponse) workSession.process(WORKERID,
                    request, context);
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
             res = (GenericSignResponse) workSession.process(WORKERID,
                    request, context);
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
             res = (GenericSignResponse) workSession.process(WORKERID,
                    request, context);
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
        workSession.setWorkerProperty(WORKERID, "ACCEPT_ALL_USERNAMES", "true");
        workSession.removeWorkerProperty(WORKERID, "ACCEPT_USERNAMES");
        workSession.reloadConfiguration(WORKERID);

        final RequestContext context = new RequestContext();
        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        // With correct username anything1
        context.put(RequestContext.CLIENT_CREDENTIAL,
                new UsernamePasswordClientCredential("anything1", ""));
        try {
             GenericSignResponse res = (GenericSignResponse) workSession.process(WORKERID,
                    request, context);
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
             GenericSignResponse res = (GenericSignResponse) workSession.process(WORKERID,
                    request, context);
        } catch (AuthorizationRequiredException ex) {
            fail("Username not accepted!");
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }

    }

    public void test99TearDownDatabase() throws Exception {
        TestUtils.assertSuccessfulExecution(new String[] {
            "removeworker",
            String.valueOf(WORKERID)
        });

        TestUtils.assertSuccessfulExecution(new String[] {
            "module",
            "remove",
            "XMLSIGNER",
            String.valueOf(moduleVersion)
        });
        assertTrue("module remove",
                TestUtils.grepTempOut("Removal of module successful."));
        workSession.reloadConfiguration(WORKERID);
    }

    private File getSignServerHome() throws Exception {
        if (signServerHome == null) {
            final String home = System.getenv("SIGNSERVER_HOME");
            assertNotNull("SIGNSERVER_HOME", home);
            signServerHome = new File(home);
            assertTrue("SIGNSERVER_HOME exists", signServerHome.exists());
        }
        return signServerHome;
    }

    /**
     * Get the initial naming context
     */
    protected Context getInitialContext() throws Exception {
        Hashtable<String, String> props = new Hashtable<String, String>();
        props.put(
                Context.INITIAL_CONTEXT_FACTORY,
                "org.jnp.interfaces.NamingContextFactory");
        props.put(
                Context.URL_PKG_PREFIXES,
                "org.jboss.naming:org.jnp.interfaces");
        props.put(Context.PROVIDER_URL, "jnp://localhost:1099");
        Context ctx = new InitialContext(props);
        return ctx;
    }

}
