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
package org.signserver.admin.web.auth;

import jakarta.faces.context.ExternalContext;
import jakarta.faces.context.FacesContext;
import jakarta.servlet.http.HttpSession;
import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.signserver.admin.web.auth.LoginFilter.LOGGEDIN_ATTRIBUTE;

/**
 * Unit tests for LoginBean
 */
public class LoginBeanUnitTest {
    private static final Logger LOG = Logger.getLogger(LoginBeanUnitTest.class);
    private FacesContext facesContext;
    private ExternalContext externalContext;
    private HttpSession session;

    @Before
    public void setup() {
        facesContext = mock(FacesContext.class);
        externalContext = mock(ExternalContext.class);
        session = mock(HttpSession.class);
    }

    /**
     * Ensures that error code "1" maps to the OIDC misconfiguration message.
     */
    @Test
    public void testErrorDisplayMessageCode1() {
        LOG.info("testErrorDisplayMessageCode1");
        LoginBean bean = new LoginBean();
        bean.setErrorCode("1");
        assertEquals("OIDC is misconfigured. Check the application logs for details.", bean.errorDisplayMessage());
    }

    /**
     * Ensures that error code "2" maps to the OIDC authentication failure message.
     */
    @Test
    public void testErrorDisplayMessageCode2() {
        LOG.info("testErrorDisplayMessageCode2");
        LoginBean bean = new LoginBean();
        bean.setErrorCode("2");
        assertEquals("OIDC authentication failed. This could be temporarily failure or a configuration error. Check the application logs for details.", bean.errorDisplayMessage());
    }

    /**
     * Ensures that error code "3" maps to the invalid audience message.
     */
    @Test
    public void testErrorDisplayMessageCode3() {
        LOG.info("testErrorDisplayMessageCode3");
        LoginBean bean = new LoginBean();
        bean.setErrorCode("3");
        assertEquals("Audience is not valid. Check the application logs for details.", bean.errorDisplayMessage());
    }

    /**
     * Ensures that unknown error codes map to the default message.
     */
    @Test
    public void testErrorDisplayMessageDefault() {
        LOG.info("testErrorDisplayMessageDefault");
        LoginBean bean = new LoginBean();
        bean.setErrorCode("unknown");
        assertEquals("Something went wrong. Check the application logs for details.", bean.errorDisplayMessage());
    }

    /**
     * Verifies that LoginBean.getLoginType() reads the LoginType from the JSF HttpSession.
     */
    @Test
    public void testGetLoginType() {
        LOG.info("testGetLoginType");

        LoginBean bean = spy(new LoginBean());
        doReturn(true).when(bean).isOidcAuthenticated();
        doReturn(false).when(bean).isAudienceValidOrNotUsed();

        try (MockedStatic<FacesContext> mocked = Mockito.mockStatic(FacesContext.class)) {
            mocked.when(FacesContext::getCurrentInstance).thenReturn(facesContext);
            when(facesContext.getExternalContext()).thenReturn(externalContext);
            when(externalContext.getSession(false)).thenReturn(session);
            when(session.getAttribute(Mockito.anyString())).thenReturn(LoginType.CLIENT_CERT);
            LoginType type = bean.getLoginType();
            assertEquals(LoginType.CLIENT_CERT, type);
            verify(session).getAttribute(LOGGEDIN_ATTRIBUTE);
        }
    }

    /**
     * Verifies that if Client Certificate is not authenticated, the user is redirected to the login page.
     */
    @Test
    public void testValidateLoginClientCertNotAuthenticated() {
        LOG.info("testValidateLoginClientCertNotAuthenticated");

        LoginBean bean = spy(new LoginBean());
        doReturn(false).when(bean).isClientCertificateAuthenticated();
        String result = bean.validateLogin(true);
        assertEquals("login.xhtml?faces-redirect=true&amp;includeViewParams=true", result);
        verify(session, never()).setAttribute(eq(LOGGEDIN_ATTRIBUTE), any());
    }

    /**
     * Verifies that if Client Certificate is authenticated, the user is redirected to the worker's page.
     */
    @Test
    public void testValidateLoginClientCertAuthenticated() {
        LOG.info("testValidateLoginClientCertAuthenticated");

        LoginBean bean = spy(new LoginBean());
        doReturn(true).when(bean).isClientCertificateAuthenticated();
        try (MockedStatic<FacesContext> mocked = Mockito.mockStatic(FacesContext.class)) {
            mocked.when(FacesContext::getCurrentInstance).thenReturn(facesContext);
            when(facesContext.getExternalContext()).thenReturn(externalContext);
            when(externalContext.getSession(false)).thenReturn(session);
            when(session.getAttribute(Mockito.anyString())).thenReturn(LoginType.CLIENT_CERT);
            String result = bean.validateLogin(true);
            assertEquals("workers.xhtml?faces-redirect=true&amp;includeViewParams=true", result);
            verify(session).setAttribute(LOGGEDIN_ATTRIBUTE, LoginType.CLIENT_CERT);
        }
    }

    /**
     * Verifies that if OIDC is not authenticated, the user is redirected to the login page.
     */
    @Test
    public void testValidateLoginOidcNotAuthenticated() {
        LOG.info("testValidateLoginOidcNotAuthenticated");

        LoginBean bean = spy(new LoginBean());
        doReturn(false).when(bean).isOidcAuthenticated();
        String result = bean.validateLogin(false);
        assertEquals("login.xhtml?faces-redirect=true&amp;includeViewParams=true", result);
        verify(session, never()).setAttribute(eq(LOGGEDIN_ATTRIBUTE), any());
    }

    /**
     * Verifies that if OIDC is authenticated but the audience is invalid, the user is redirected to the login page.
     */
    @Test
    public void testValidateLoginOidcAuthenticatedAudienceInvalidAddsError3() {
        LOG.info("testValidateLoginOidcAuthenticatedAudienceInvalidAddsError3");

        LoginBean bean = spy(new LoginBean());
        doReturn(true).when(bean).isOidcAuthenticated();
        doReturn(false).when(bean).isAudienceValidOrNotUsed();
        String result = bean.validateLogin(false);
        assertEquals("login.xhtml?faces-redirect=true&amp;includeViewParams=true&amp;error=3", result);
        verify(session, never()).setAttribute(eq(LOGGEDIN_ATTRIBUTE), any());
    }

    /**
     * Verifies that if OIDC is authenticated and the audience is valid, the user is redirected to the worker's page.
     */
    @Test
    public void testValidateLoginOidcAuthenticatedAudienceValid() {
        LOG.info("testValidateLoginOidcAuthenticatedAudienceValid");

        LoginBean bean = spy(new LoginBean());
        doReturn(true).when(bean).isOidcAuthenticated();
        doReturn(true).when(bean).isAudienceValidOrNotUsed();

        try (MockedStatic<FacesContext> mocked = Mockito.mockStatic(FacesContext.class)) {
            mocked.when(FacesContext::getCurrentInstance).thenReturn(facesContext);
            when(facesContext.getExternalContext()).thenReturn(externalContext);
            when(externalContext.getSession(false)).thenReturn(session);
            String result = bean.validateLogin(false);
            assertEquals("workers.xhtml?faces-redirect=true&amp;includeViewParams=true", result);
            verify(session).setAttribute(LOGGEDIN_ATTRIBUTE, LoginType.OIDC);
        }
    }
}
