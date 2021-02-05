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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.security.cert.X509Certificate;
import java.util.Collection;
import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.Part;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.common.RequestContext;
import org.bouncycastle.util.encoders.Base64;

/**
 * Unit tests for the CredentialUtils helper class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CredentialUtilsTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CredentialUtils.class);

    /**
     * subject=/CN=Signer 1/OU=Testing/O=SignServer/C=SE
     * issuer=/CN=DSS Root CA 10/OU=Testing/O=SignServer/C=SE
     * valid until=2025-06-01
     * Taken from res/test/dss10/dss10_signer1.pem
     */
    private static final String CERT =
            "MIIElTCCAn2gAwIBAgIIQZNa2mLuDoowDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UE"
          +  "AwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNp"
          +  "Z25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTE1MDYwMTE0MDQ0MVoXDTI1MDYwMTE0"
          +  "MDQ0MVowRzERMA8GA1UEAwwIU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzAR"
          +  "BgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEF"
          +  "AAOCAQ8AMIIBCgKCAQEAy0GX45lzDRhUU/jhCCeqKKZcFWlOQiDxUcd6JOq38drU"
          +  "alL9u2+gr+dcBFKRBOGmFxjMGVJ4nDO8uI3dl+BOrFbykUAnf1Yk/t8E2ZmgdQMP"
          +  "4Cz6iXwlgWj8YRnQ6wEk2gcAp45SARfyEYdtArYvbTxOFoxb9KOjwji89yxCR/pb"
          +  "RHz/q3RoXgq6E/g8mTmIt4CAgvD5VVFiNP7XWKd4Ptw4bjQY8RW5k8291o1ErHbD"
          +  "Zvvqvps4E9cIu35v1LtXjlFkwVJ4xc0L61Ak+cjcwAUcGqTHQ7P9KdjcOLztsw0X"
          +  "3jTZi5nLg3y4FukeOzkjxk5nh0Jr3/F3M7wuY2BS6wIDAQABo38wfTAdBgNVHQ4E"
          +  "FgQUDsECWxG3XbAJooXiXmQrIz/d0l4wDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAW"
          +  "gBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYw"
          +  "FAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQAr2nSyOwkD"
          +  "WPWiIqomXHsBHXwr35kvwqNSqM5Lh9if0XUDj0HudXH+nenyH9FAMkX1rfOm+SjQ"
          +  "Wmw5mgwgvpDyaI8J6NBSf0Kve9Qxn8Yh224oVZogHS7LYFULd9FE3UdLv0ZrD2i+"
          +  "0aXEZXaCEJBxNY+iVOpGdBdBgY6c7MD6Ib1Py7bQeslSOjmHNs7OnE5aZaLfmUQ3"
          +  "0EprvX0Zzx0mhjm8BU41+m7Yg4W94mbZX0AGjEKL8v4NRQkNdv2/wgKNGKK+OvII"
          +  "E/a3g8i68Jy5xbEI5sVcp6Z6qIa+6+5li33Gblwr86DnQFmm0IrCmgVyT2RuzNeX"
          +  "FcgenbHJO/udOchn1b65wwzfIuqo5SpJmzsS9HvbsdJOCvXbRRJibjC0TN73Bmag"
          +  "H0wv4t9TawbRH/8M3JvWIAV7DIuyiosC6F9jN319zWkzPllesNsjmWzE05fwcZky"
          +  "4RSsS+eYmHxn9oEi1nS4igv0o/4lpz8WZ9KQSNTWP89wXPMW7bT1XUqMehSXk5Q1"
          +  "3Ao/AXPF+4ZP4QJZMa2OHdDaNPMBinK0fZzoV/RFx5mzQm+XJCcdZBHbB+JEw14V"
          +  "BQHSf/Icgab1tANxgQSk8IOhZ0/OQ6LdfoTmRVsrxz58tzvA8Fw+FcyyIni8p6ve"
          +  "2oETepx5f5yVfLJzAdcgTXwo6R52yBgw2w==";

    private static final String BEARER_TOKEN =
            "eyJraWQiOiJqd3Qua2V5IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdW"
          + "IiOiJ1c3VhbCIsInVwbiI6ImR1a2UiLCJhdXRoX3RpbWUiOjE1ODMzMTIyMTYsIml"
          + "zcyI6ImFpcmhhY2tzMiIsImdyb3VwcyI6WyJtYWxsb3J5IiwiaGFja2VyIl0sImV4"
          + "cCI6MTU4MzMxMzIxNiwiaWF0IjoxNTgzMzEyMjE2LCJqdGkiOiI0MiJ9.hPVExBJj"
          + "oRHMgHUW6x5BL369gGtkZ0orfa0Y0TXJtY9ej6UhDMnyAKoVVylBQlUxLZLqEayhd"
          + "tsgrE8f_7PlFhDLUDLW20CV5oh8WFv3QMvf05yIbvD8zt09f_JaP3ZSXQPO9GmIhO"
          + "IA5AjK939yQlBLz56kGoXEfMrN_Z8KFWIPzUtDd5vxT8-MUC1vUbcjwxSLaSVM9sw"
          + "gauBYVgsF0JHfX0c-HMVyhgSAGTIs-I3ocx6WsKsof64jnEIwHeUqWh8NDBmiJrZ_"
          + "keNhj4SlGeD_SXKjuIlaPWjppIeT8-5QlT8jcAQ8k5k6tT9ra0hNAuy44ObLE74Fz"
          + "RHAtZBuZw";

    public CredentialUtilsTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Tests that the provided certificate is available in both fields.
     * @throws java.lang.Exception
     */
    @Test
    public void testAddToRequestContext_certOnly() throws Exception {
        LOG.info("testAddToRequestContext_certOnly");

        // Only a certificate
        RequestContext context = new RequestContext();
        HttpServletRequest req = new MockedHttpServletRequest(Collections.<String, String>emptyMap());
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(Base64.decode(CERT)));

        CredentialUtils.addToRequestContext(context, req, cert);
        CertificateClientCredential credNew = (CertificateClientCredential) context.get(RequestContext.CLIENT_CREDENTIAL_CERTIFICATE);
        CertificateClientCredential credLegacy = (CertificateClientCredential) context.get(RequestContext.CLIENT_CREDENTIAL);

        assertNotNull("has put the certificate in new field", credNew);
        assertNotNull("has put the certificate in legacy field", credLegacy);
        assertEquals("serial number", cert.getSerialNumber().toString(16), credNew.getSerialNumber());
        assertEquals("issuer DN", cert.getIssuerDN().getName(), credNew.getIssuerDN()); // XXX getIssuerDN is implementation specific but that is what we use at the moment
        assertEquals("same value in both fields", credNew, credLegacy);
    }

    /**
     * Tests that the certificate is available in the cert field and the
     * password in the password field as well as the certificate in the
     * legacy field to be backwards compatible.
     * @throws java.lang.Exception
     */
    @Test
    public void testAddToRequestContext_certAndPassword() throws Exception {
        LOG.info("testAddToRequestContext_certAndPassword");

        // Certificate and user1:foo456
        String username = "user1";
        String password = "foo456";
        RequestContext context = new RequestContext();
        HashMap<String, String> headers = new HashMap<>();
        headers.put("Authorization", "basic " + Base64.toBase64String((username + ":" + password).getBytes(StandardCharsets.UTF_8)));
        HttpServletRequest req = new MockedHttpServletRequest(headers);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(Base64.decode(CERT)));

        CredentialUtils.addToRequestContext(context, req, cert);
        CertificateClientCredential credNew = (CertificateClientCredential) context.get(RequestContext.CLIENT_CREDENTIAL_CERTIFICATE);
        CertificateClientCredential credLegacy = (CertificateClientCredential) context.get(RequestContext.CLIENT_CREDENTIAL);

        UsernamePasswordClientCredential credNewPassword = (UsernamePasswordClientCredential) context.get(RequestContext.CLIENT_CREDENTIAL_PASSWORD);
        assertNotNull("has put password in new field", credNewPassword);
        assertEquals("username", username, credNewPassword.getUsername());
        assertEquals("password", password, credNewPassword.getPassword());

        assertNotNull("has put the certificate in new field", credNew);
        assertNotNull("has put the certificate in legacy field", credLegacy);
        assertEquals("serial number", cert.getSerialNumber().toString(16), credNew.getSerialNumber());
        assertEquals("issuer DN", cert.getIssuerDN().getName(), credNew.getIssuerDN()); // XXX getIssuerDN is implementation specific but that is what we use at the moment
        assertEquals("same value in both fields", credNew, credLegacy);
    }

    /**
     * Tests that the provided username/password is available in both fields.
     * @throws java.lang.Exception
     */
    @Test
    public void testAddToRequestContext_onlyPassword() throws Exception {
        LOG.info("testAddToRequestContext_onlyPassword");

        // Certificate and user1:foo456
        String username = "user1";
        String password = "foo456";
        RequestContext context = new RequestContext();
        HashMap<String, String> headers = new HashMap<>();
        headers.put("Authorization", "basic " + Base64.toBase64String((username + ":" + password).getBytes(StandardCharsets.UTF_8)));
        HttpServletRequest req = new MockedHttpServletRequest(headers);

        CredentialUtils.addToRequestContext(context, req, null);
        UsernamePasswordClientCredential credNew = (UsernamePasswordClientCredential) context.get(RequestContext.CLIENT_CREDENTIAL_PASSWORD);
        UsernamePasswordClientCredential credLegacy = (UsernamePasswordClientCredential) context.get(RequestContext.CLIENT_CREDENTIAL);

        assertNotNull("has put password in new field", credNew);
        assertNotNull("has put password in legacy field", credLegacy);
        assertEquals("username", username, credNew.getUsername());
        assertEquals("password", password, credNew.getPassword());
        assertEquals("same value in both fields", credNew, credLegacy);
    }

    /**
     * Tests that the provided bearer token is available in the request
     * context.
     * 
     * @throws Exception 
     */
    @Test
    public void testAddToRequestContext_bearer() throws Exception {
        LOG.info("testAddToRequestContext_bearer");

        final RequestContext context = new RequestContext();
        final HashMap<String, String> headers = new HashMap<>();

        headers.put("Authorization", "Bearer " + BEARER_TOKEN);

        final HttpServletRequest req = new MockedHttpServletRequest(headers);

        CredentialUtils.addToRequestContext(context, req, null);

        final String token = (String) context.get(RequestContext.CLIENT_CREDENTIAL_BEARER);

        assertEquals("Found bearer token in request context", BEARER_TOKEN,
                     token);
    }

    /**
     * Tests that the provided bearer token is available in the request
     * context, also with the the token containing lower-case "bearer", as the
     * RFC stipulates this is case-insensitive.
     * 
     * @throws Exception 
     */
    @Test
    public void testAddToRequestContext_bearerLowerCase() throws Exception {
        LOG.info("testAddToRequestContext_bearer");

        final RequestContext context = new RequestContext();
        final HashMap<String, String> headers = new HashMap<>();

        headers.put("Authorization", "bearer " + BEARER_TOKEN);

        final HttpServletRequest req = new MockedHttpServletRequest(headers);

        CredentialUtils.addToRequestContext(context, req, null);

        final String token = (String) context.get(RequestContext.CLIENT_CREDENTIAL_BEARER);

        assertEquals("Found bearer token in request context", BEARER_TOKEN,
                     token);
    }

    /**
     * Tests some syntactically incorrect headers.
     * @throws Exception
     */
    @Test
    public void testAddToRequestContext_incorrectSyntax() throws Exception {
        LOG.info("testAddToRequestContext_incorrectSyntax");

        // Missing colon is not correct
        assertNotAddedToContext("no colon", "Authorization", "basic " + Base64.toBase64String("NoColon".getBytes(StandardCharsets.UTF_8)));

        // Empty data in base64 is not correct
        assertNotAddedToContext("empty user+pass", "Authorization", "basic " + Base64.toBase64String("".getBytes(StandardCharsets.UTF_8)));

        // Missing base64 is not correct
        assertNotAddedToContext("empty after basic 1", "Authorization", "basic ");

        // Missing base64 is not correct
        assertNotAddedToContext("empty after basic 2", "Authorization", "basic");

        // Only basic supported
        assertNotAddedToContext("not basic", "Authorization", "other ");

        // No header should not add anything
        assertNotAddedToContext("no header", null, null);
    }

    /**
     * Asserts that no credentials are added to the request context.
     * @param message to print in case of JUnit assertion failure
     * @param headerKey to add or null if the header should not be added
     * @param headerValue the value
     * @throws UnsupportedEncodingException
     */
    private void assertNotAddedToContext(String message, String headerKey, String headerValue) throws UnsupportedEncodingException{
        RequestContext context = new RequestContext();
        HashMap<String, String> headers = new HashMap<>();
        if (headerKey != null) {
            headers.put(headerKey, headerValue);
        }
        HttpServletRequest req = new MockedHttpServletRequest(headers);

        CredentialUtils.addToRequestContext(context, req, null);

        assertNull("has not put password in new field for " + message,
                context.get(RequestContext.CLIENT_CREDENTIAL_PASSWORD));
        assertNull("has not put password in legacy field for " + message,
                context.get(RequestContext.CLIENT_CREDENTIAL));
    }

    private static class MockedHttpServletRequest implements HttpServletRequest {

        private final Map<String, String> headers;

        public MockedHttpServletRequest(Map<String, String> headers) {
            this.headers = headers;
        }

        @Override
        public String getAuthType() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Cookie[] getCookies() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public long getDateHeader(String string) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getHeader(String string) {
            return headers.get(string);
        }

        @Override
        public Enumeration getHeaders(String string) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Enumeration getHeaderNames() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public int getIntHeader(String string) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getMethod() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getPathInfo() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getPathTranslated() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getContextPath() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getQueryString() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getRemoteUser() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public boolean isUserInRole(String string) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Principal getUserPrincipal() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getRequestedSessionId() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getRequestURI() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public StringBuffer getRequestURL() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getServletPath() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public HttpSession getSession(boolean bln) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public HttpSession getSession() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public boolean isRequestedSessionIdValid() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public boolean isRequestedSessionIdFromCookie() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public boolean isRequestedSessionIdFromURL() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        @SuppressWarnings("deprecation")
        public boolean isRequestedSessionIdFromUrl() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Object getAttribute(String string) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Enumeration getAttributeNames() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getCharacterEncoding() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void setCharacterEncoding(String string) throws UnsupportedEncodingException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public int getContentLength() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getContentType() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getParameter(String string) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Enumeration getParameterNames() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String[] getParameterValues(String string) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Map getParameterMap() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getProtocol() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getScheme() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getServerName() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public int getServerPort() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public BufferedReader getReader() throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getRemoteAddr() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getRemoteHost() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void setAttribute(String string, Object o) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void removeAttribute(String string) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Locale getLocale() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Enumeration getLocales() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public boolean isSecure() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public RequestDispatcher getRequestDispatcher(String string) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        @SuppressWarnings("deprecation")
        public String getRealPath(String string) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public boolean authenticate(HttpServletResponse response) throws IOException, ServletException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Part getPart(String name) throws IOException, ServletException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Collection<Part> getParts() throws IOException, ServletException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void login(String username, String password) throws ServletException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void logout() throws ServletException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public AsyncContext getAsyncContext() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public DispatcherType getDispatcherType() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getLocalAddr() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getLocalName() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public int getLocalPort() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public int getRemotePort() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public ServletContext getServletContext() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public boolean isAsyncStarted() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public boolean isAsyncSupported() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public AsyncContext startAsync() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public AsyncContext startAsync(ServletRequest request, ServletResponse response) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String changeSessionId() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public <T extends HttpUpgradeHandler> T upgrade(Class<T> type) throws IOException, ServletException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public long getContentLengthLong() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

    };

    private static class MockedCertificate extends Certificate {

        private final int id;

        public MockedCertificate(int id) {
            super("MockedCert");
            this.id = id;
        }

        @Override
        public byte[] getEncoded() throws CertificateEncodingException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String toString() {
            return "MockedCertificate-" + hashCode();
        }

        @Override
        public PublicKey getPublicKey() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final MockedCertificate other = (MockedCertificate) obj;
            if (this.id != other.id) {
                return false;
            }
            return true;
        }

        @Override
        public int hashCode() {
            int hash = 7;
            hash = 19 * hash + this.id;
            return hash;
        }

    };

}
