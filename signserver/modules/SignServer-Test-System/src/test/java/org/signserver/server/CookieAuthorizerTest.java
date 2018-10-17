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
import java.net.MalformedURLException;
import java.net.URISyntaxException;
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
import org.junit.Test;
import org.signserver.admin.common.query.AuditLogFields;
import org.signserver.admin.common.query.QueryUtil;
import org.signserver.common.CESeCoreModules;
import org.signserver.common.ServiceLocator;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.WebTestCase;

/**
 * System tests for the CookieAuthorizer.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CookieAuthorizerTest extends WebTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CookieAuthorizerTest.class);

    private final WorkerSessionRemote workerSession = getWorkerSession();
    private SecurityEventsAuditorSessionRemote auditorSession;

    @Override
    protected String getServletURL() {
        return getPreferredHTTPProtocol() + getHTTPHost() + ":" + getPreferredHTTPPort() + "/signserver/process";
    }

    // TODO: Test init

    /**
     * Tests logging of some cookies in the request.
     *
     * @throws Exception
     */
    @Test
    public void testLoggingOfCookies() throws Exception {
        try {
            // Add signer
            addDummySigner1(true);
            workerSession.setWorkerProperty(getSignerIdDummy1(), "AUTHTYPE", "org.signserver.server.CookieAuthorizer"); // Use our CookieAuthorizer
            workerSession.setWorkerProperty(getSignerIdDummy1(), "WORKERLOGGER", "org.signserver.server.log.SecurityEventsWorkerLogger"); // Use logging to database so that we can query the log
            workerSession.reloadConfiguration(getSignerIdDummy1());
            getWorkerSession().activateSigner(new WorkerIdentifier(getSignerIdDummy1()), ModulesTestCase.KEYSTORE_PASSWORD);

            // Cookie values
            Map<String, String> cookies = new HashMap<>();
            cookies.put("DSS_ENV_SERVER_REQUEST", "/");
            cookies.put("DSS_ENV_REMOTE_ADDR", "93.184.216.34");
            cookies.put("DSS_ENV_SERVER_ADDR", "x.x.x.x");
            
            // Send request
            sendRequestWithCookie(getSignerNameDummy1(), cookies);

            // Query last log
            Map<String, Object> logFields = queryLastLogFields();
            
            // Check log values
            assertEquals("DSS_ENV_SERVER_REQUEST", "/", logFields.get("DSS_ENV_SERVER_REQUEST"));
            assertEquals("DSS_ENV_REMOTE_ADDR", "93.184.216.34", logFields.get("DSS_ENV_REMOTE_ADDR"));
            assertEquals("DSS_ENV_SERVER_ADDR", "x.x.x.x", logFields.get("DSS_ENV_SERVER_ADDR"));
        } finally {
            removeWorker(getSignerIdDummy1());
            workerSession.reloadConfiguration(getSignerIdDummy1());
        }
    }
    
    /**
     * Query the last log field of event type PROCESS.
     *
     * @return additional details map
     * @throws Exception 
     */
    private Map<String, Object> queryLastLogFields() throws Exception {
        Term t = QueryUtil.parseCriteria("eventType EQ PROCESS", AuditLogFields.ALLOWED_FIELDS, AuditLogFields.NO_ARG_OPS, Collections.<String>emptySet(), AuditLogFields.LONG_FIELDS, AuditLogFields.DATE_FIELDS);
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
    
    private void sendRequestWithCookie(String signerName, Map<String, String> cookies) throws MalformedURLException, URISyntaxException {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", signerName);
        fields.put("data", "<root/>");
        
        Map<String, String> headers = new HashMap<>();
        
        // Adding cookie header
        final ArrayList<String> cookiePairs = new ArrayList<>();
        for (Map.Entry<String, String> cookie : cookies.entrySet()) {
            cookiePairs.add(cookie.getKey() + "=" + toCookieOctet(cookie.getValue()));
        }
        headers.put("Cookie", StringUtils.join(cookiePairs, "; "));
        
        // POST (url-encoded)
        try {
            HttpURLConnection con = WebTestCase.sendPostFormUrlencoded(
                    getServletURL(), fields, headers);

            int response = con.getResponseCode();
            String message = con.getResponseMessage();
            LOG.info("Returned " + response + " " + message);
            assertEquals("POST url-encoded: status response: " + message, 200, response);
            con.disconnect();
        } catch (IOException ex) {
            LOG.error("IOException", ex);
            fail(ex.getMessage());
        }
    }

}
