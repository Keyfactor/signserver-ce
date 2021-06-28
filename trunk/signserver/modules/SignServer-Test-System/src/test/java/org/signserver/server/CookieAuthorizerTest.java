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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.naming.NamingException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionRemote;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.elems.Term;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.signserver.admin.common.query.AuditLogFields;
import org.signserver.admin.common.query.QueryUtil;
import org.signserver.common.CESeCoreModules;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.WebTestCase;

import static junit.framework.TestCase.fail;
import static org.junit.Assert.assertEquals;

/**
 * System tests for the CookieAuthorizer.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CookieAuthorizerTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CookieAuthorizerTest.class);

    /** Overridden to set Servlet URL and making it public. */
    private static final class MyWebTestCase extends WebTestCase {
        @Override
        public String getServletURL() {
            return getPreferredHTTPProtocol() + getHTTPHost() + ":" + getPreferredHTTPPort() + "/signserver/process";
        }
    }

    private final MyWebTestCase test = new MyWebTestCase();
    private final WorkerSessionRemote workerSession = test.getWorkerSession();
    private SecurityEventsAuditorSessionRemote auditorSession;


    @Before
    public void setUp() throws Exception {
        Assume.assumeFalse("Test does not run in NODB mode", "nodb".equalsIgnoreCase(test.getDeployConfig().getProperty("database.name")));
        SignServerUtil.installBCProvider();
    }

    // TODO: Test init

    /**
     * Tests logging of some cookies in the request.
     */
    @Test
    public void testLoggingOfCookies() throws Exception {
        try {
            // Add signer
            test.addDummySigner1(true);
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "AUTHTYPE", "org.signserver.server.CookieAuthorizer"); // Use our CookieAuthorizer
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "REQUEST_COOKIES_PREFIX", "ABC_"); // send Cookies with prefix
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "ALLOW_ANY", "TRUE"); // Allow all clients access DSS by default
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "WORKERLOGGER", "org.signserver.server.log.SecurityEventsWorkerLogger"); // Use logging to database so that we can query the log
            workerSession.reloadConfiguration(test.getSignerIdDummy1());
            test.getWorkerSession().activateSigner(new WorkerIdentifier(test.getSignerIdDummy1()), ModulesTestCase.KEYSTORE_PASSWORD);

            // Cookie values
            Map<String, String> cookies = new HashMap<>();
            cookies.put("DSS_ENV_SERVER_REQUEST", "/");
            cookies.put("DSS_ENV_REMOTE_ADDR", "93.184.216.34");
            cookies.put("DSS_ENV_SERVER_ADDR", "x.x.x.x");

            // Send request
            sendRequestWithCookie(test.getSignerNameDummy1(), cookies);

            // Query last log
            Map<String, Object> logFields = queryLastLogFields();

            // Check log values
            assertEquals("DSS_ENV_SERVER_REQUEST", "/", logFields.get("ABC_DSS_ENV_SERVER_REQUEST"));
            assertEquals("DSS_ENV_REMOTE_ADDR", "93.184.216.34", logFields.get("ABC_DSS_ENV_REMOTE_ADDR"));
            assertEquals("DSS_ENV_SERVER_ADDR", "x.x.x.x", logFields.get("ABC_DSS_ENV_SERVER_ADDR"));
        } finally {
            test.removeWorker(test.getSignerIdDummy1());
            workerSession.reloadConfiguration(test.getSignerIdDummy1());
        }
    }

    /**
     * Tests logging of some cookies in the request and characters that are allowed but might cause issues in some environments.
     * - For WildFly 8 cookie value might get cut off if there are equal signs: https://developer.jboss.org/thread/239388
     * - For JBoss EAP 6.4 it seems all of '=', '(', ')' and '@' are cutting it off
     */
    @Test
    public void testLoggingOfCookiesWithProblematicCharacters() throws Exception {
        try {
            // Add signer
            test.addDummySigner1(true);
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "AUTHTYPE", "org.signserver.server.CookieAuthorizer"); // Use our CookieAuthorizer
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "REQUEST_COOKIES_PREFIX", "ABC_"); // send Cookies with prefix
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "ALLOW_ANY", "TRUE"); // Allow all clients access DSS by default
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "WORKERLOGGER", "org.signserver.server.log.SecurityEventsWorkerLogger"); // Use logging to database so that we can query the log
            workerSession.reloadConfiguration(test.getSignerIdDummy1());
            test.getWorkerSession().activateSigner(new WorkerIdentifier(test.getSignerIdDummy1()), ModulesTestCase.KEYSTORE_PASSWORD);

            // Cookie values
            Map<String, String> cookies = new HashMap<>();
            cookies.put("DSS_SIMPLEST", "simplestValue");
            cookies.put("DSS_SIMPLE", "A simple value");
            cookies.put("DSS_EQUALS1", "=");
            cookies.put("DSS_EQUALS2", "==");
            cookies.put("DSS_PARANTHESIS", "Within (paranthesis) that was");
            cookies.put("DSS_EMAILS", "user1@example.com, user2@example.com");
            cookies.put("DSS_ENV_SSL_CLIENT_S_DN", "CN=Client User (Authentication),emailAddress=client.user@example.com,serialNumber=1234-5678-9012-3456");
            cookies.put("DSS_24Oct", "NewLine 1\nNewLine 2\nLine3");

            // Send request
            sendRequestWithCookie(test.getSignerNameDummy1(), cookies);

            // Query last log
            Map<String, Object> logFields = queryLastLogFields();

            // Check log values
            assertEquals("DSS_SIMPLEST", "simplestValue", logFields.get("ABC_DSS_SIMPLEST"));
            assertEquals("DSS_SIMPLE", "A simple value", logFields.get("ABC_DSS_SIMPLE"));

            // Check with equals sign
            assertEquals("DSS_EQUALS1", "=", logFields.get("ABC_DSS_EQUALS1"));
            assertEquals("DSS_EQUALS2", "==", logFields.get("ABC_DSS_EQUALS2"));

            // Check with paranthesis
            assertEquals("DSS_PARANTHESIS", "Within (paranthesis) that was", logFields.get("ABC_DSS_PARANTHESIS"));

            // Check with AT-sign
            assertEquals("DSS_EMAILS", "user1@example.com, user2@example.com", logFields.get("ABC_DSS_EMAILS"));

            // Check complex one
            assertEquals("DSS_ENV_SSL_CLIENT_S_DN", "CN=Client User (Authentication),emailAddress=client.user@example.com,serialNumber=1234-5678-9012-3456", logFields.get("ABC_DSS_ENV_SSL_CLIENT_S_DN"));
        } finally {
            test.removeWorker(test.getSignerIdDummy1());
            workerSession.reloadConfiguration(test.getSignerIdDummy1());
        }
    }

    /**
     * Tests that you can not send request to misconfigured Authorizer.
     */
    @Test
    public void testMisconfiguredAuthorizer() throws Exception {
        try {
            // Add signer
            test.addDummySigner1(true);
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "AUTHTYPE", "org.signserver.server.CookieAuthorizer"); // Use our CookieAuthorizer
            // we do not configure required properties ALLOW_ANY and REQUEST_COOKIES_PREFIX and Authorizer should return Error 500
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "WORKERLOGGER", "org.signserver.server.log.SecurityEventsWorkerLogger"); // Use logging to database so that we can query the log
            workerSession.reloadConfiguration(test.getSignerIdDummy1());
            test.getWorkerSession().activateSigner(new WorkerIdentifier(test.getSignerIdDummy1()), ModulesTestCase.KEYSTORE_PASSWORD);

            // Cookie values
            Map<String, String> cookies = new HashMap<>();
            cookies.put("DSS_ENV_SERVER_REQUEST", "/");
            cookies.put("DSS_ENV_REMOTE_ADDR", "93.184.216.34");
            cookies.put("DSS_ENV_SERVER_ADDR", "x.x.x.x");

            // Send request
            sendRequestWithCookie(test.getSignerNameDummy1(), cookies, 500);

            // Query last log
            Map<String, Object> logFields = queryLastLogFields();

            // Check log values
            assertEquals("EXCEPTION", "Worker is misconfigured", logFields.get("EXCEPTION"));
        } finally {
            test.removeWorker(test.getSignerIdDummy1());
            workerSession.reloadConfiguration(test.getSignerIdDummy1());
        }
    }

     /**
     * Tests logging of some cookies in the request with custom prefix.
     */
    @Test
    public void testLoggingWithPrefix() throws Exception {
        try {
            // Add signer
            test.addDummySigner1(true);
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "AUTHTYPE", "org.signserver.server.CookieAuthorizer"); // Use our CookieAuthorizer
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "WORKERLOGGER", "org.signserver.server.log.SecurityEventsWorkerLogger"); // Use logging to database so that we can query the log
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "REQUEST_COOKIES_PREFIX", "ABC_"); // Use our CookieAuthorizer
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "ALLOW_ANY", "TRUE"); // Allow any client access
            workerSession.reloadConfiguration(test.getSignerIdDummy1());
            test.getWorkerSession().activateSigner(new WorkerIdentifier(test.getSignerIdDummy1()), ModulesTestCase.KEYSTORE_PASSWORD);

            // Cookie values
            Map<String, String> cookies = new HashMap<>();
            cookies.put("DSS_ENV_SERVER_REQUEST", "/");
            cookies.put("DSS_ENV_REMOTE_ADDR", "93.184.216.34");
            cookies.put("DSS_ENV_SERVER_ADDR", "x.x.x.x");

            // Send request
            sendRequestWithCookie(test.getSignerNameDummy1(), cookies);

            // Query last log
            Map<String, Object> logFields = queryLastLogFields();

            // Check log values
            assertEquals("DSS_ENV_SERVER_REQUEST", "/", logFields.get("ABC_DSS_ENV_SERVER_REQUEST"));
            assertEquals("DSS_ENV_REMOTE_ADDR", "93.184.216.34", logFields.get("ABC_DSS_ENV_REMOTE_ADDR"));
            assertEquals("DSS_ENV_SERVER_ADDR", "x.x.x.x", logFields.get("ABC_DSS_ENV_SERVER_ADDR"));
        } finally {
            test.removeWorker(test.getSignerIdDummy1());
            workerSession.reloadConfiguration(test.getSignerIdDummy1());
        }
    }


    /**
     * Query the last log field of event type PROCESS.
     *
     * @return additional details map
     */
    private Map<String, Object> queryLastLogFields() throws Exception {
        Term t = QueryUtil.parseCriteria("eventType EQ PROCESS", AuditLogFields.ALLOWED_FIELDS, AuditLogFields.NO_ARG_OPS, Collections.emptySet(), AuditLogFields.LONG_FIELDS, AuditLogFields.DATE_FIELDS);
        QueryCriteria qc = QueryCriteria.create().add(t).add(Criteria.orderDesc(AuditRecordData.FIELD_TIMESTAMP));

        Set<String> devices = getAuditorSession().getQuerySupportingLogDevices();
        if (devices.isEmpty()) {
            throw new Exception("No log devices available for querying");
        }
        final String device = devices.iterator().next();

        List<? extends AuditLogEntry> logs = workerSession.selectAuditLogs(0, 1, qc, device);
        assertEquals("new log rows", 1, logs.size());

        AuditLogEntry row = logs.get(0);

        return row.getMapAdditionalDetails();
    }

    private SecurityEventsAuditorSessionRemote getAuditorSession() throws RemoteException {
        if (auditorSession == null) {
            try {
                auditorSession = ServiceLocator.getInstance().lookupRemote(
                        SecurityEventsAuditorSessionRemote.class, CESeCoreModules.CORE);
            } catch (NamingException e) {
                LOG.error("Error instantiating the SecurityEventsAuditorSession.", e);
                throw new RemoteException("Error instantiating the SecurityEventsAuditorSession", e);
            }
        }
        return auditorSession;
    }

    private String toCookieOctet(String value) {
        // TODO: See https://tools.ietf.org/html/rfc6265 Section 4.1.1 for cookie-octet syntax
        return value;
    }

    private String fromCookieOctet(String cookieOctet) {
        // TODO: See https://tools.ietf.org/html/rfc6265 Section 4.1.1 for cookie-octet syntax
        return cookieOctet;
    }

    private void sendRequestWithCookie(String signerName, Map<String, String> cookies, int expResponseCode) {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", signerName);
        fields.put("data", "<root/>");

        Map<String, String> headers = new HashMap<>();

        // Adding cookie header
        final ArrayList<String> cookiePairs = new ArrayList<>();
        for (Map.Entry<String, String> cookie : cookies.entrySet()) {
            cookiePairs.add(CookieUtils.toCookiePair(cookie.getKey(), cookie.getValue()));
        }
        headers.put("Cookie", StringUtils.join(cookiePairs, "; "));
        LOG.info("Cookie: " + StringUtils.join(cookiePairs, "; "));

        // POST (url-encoded)
        try {
            HttpURLConnection con = WebTestCase.sendPostFormUrlencoded(
                    test.getServletURL(), fields, headers);

            int response = con.getResponseCode();
            String message = con.getResponseMessage();
            LOG.info("Returned " + response + " " + message);
            assertEquals("POST url-encoded: status response: " + message, expResponseCode , response);
            con.disconnect();
        } catch (IOException ex) {
            LOG.error("IOException", ex);
            fail(ex.getMessage());
        }
    }

    private void sendRequestWithCookie(String signerName, Map<String, String> cookies) {
        sendRequestWithCookie(signerName, cookies, 200);
    }

     /**
     * Tests logging request cookies with prefix as well as with prefix that already exist
     * using overloaded method with extra parameter
     */
    @Test
    public void testLoggingWithPrefixExist() throws Exception {
        try {
            // Add signer
            test.addDummySigner1(true);
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "AUTHTYPE", "org.signserver.server.CookieAuthorizer"); // Use our CookieAuthorizer
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "WORKERLOGGER", "org.signserver.server.log.SecurityEventsWorkerLogger"); // Use logging to database so that we can query the log
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "REQUEST_COOKIES_PREFIX", "ABC_"); // Use our CookieAuthorizer
            workerSession.setWorkerProperty(test.getSignerIdDummy1(), "ALLOW_ANY", "TRUE"); // Allow any client access
            workerSession.reloadConfiguration(test.getSignerIdDummy1());
            test.getWorkerSession().activateSigner(new WorkerIdentifier(test.getSignerIdDummy1()), ModulesTestCase.KEYSTORE_PASSWORD);

            // Cookies with ABC_ prefix
            Map<String, String> cookies = new HashMap<>();
            cookies.put("ABC_DSS_ENV_SERVER_REQUEST", "/");
            cookies.put("ABC_DSS_ENV_REMOTE_ADDR", "93.184.216.34");
            cookies.put("ABC_DSS_ENV_SERVER_ADDR", "x.x.x.x");
            //cookies.put("DSS_ENV_SERVER_ADDR", "x.x.x.x");
            cookies.put("DSS_IP_ADDR", "212.97.132.147");

            // Send request
            sendRequestWithCookie(test.getSignerNameDummy1(), cookies);

            // Query last log
            Map<String, Object> logFields = queryLastLogFields();

            // Check log values
            assertEquals("DSS_ENV_SERVER_REQUEST", "/", logFields.get("ABC_DSS_ENV_SERVER_REQUEST"));
            assertEquals("DSS_ENV_REMOTE_ADDR", "93.184.216.34", logFields.get("ABC_DSS_ENV_REMOTE_ADDR"));
            //assertEquals("DSS_ENV_SERVER_ADDR", "x.x.x.x", logFields.get("ABC_DSS_ENV_SERVER_ADDR"));
            assertEquals("DSS_ENV_SERVER_ADDR", "x.x.x.x", logFields.get("ABC_DSS_ENV_SERVER_ADDR"));
            assertEquals("DSS_IP_ADDR", "212.97.132.147", logFields.get("ABC_DSS_IP_ADDR"));
        } finally {
            test.removeWorker(test.getSignerIdDummy1());
            workerSession.reloadConfiguration(test.getSignerIdDummy1());
        }
    }
}
