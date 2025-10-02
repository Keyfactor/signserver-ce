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

import org.junit.Before;
import org.junit.Test;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.security.cert.X509Certificate;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

/**
 * Verifies redirect/forward behavior based on login state, request URI,
 * transport security, and client certificate presence.
 */
public class LoginFilterTest {

    private LoginFilter filter;

    @Before
    public void setup() {
        filter = new LoginFilter();
    }

    /**
     * Requests to protected pages without a session should be redirected to the login.xhtml.
     */
    @Test
    public void testProtectedRequestWithNoSessionRedirectsToLogin() throws IOException, ServletException {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        HttpSession session = null;
        FilterChain chain = mock(FilterChain.class);

        when(req.getRequestURI()).thenReturn("/signserver/adminweb/workers.xhtml");
        when(req.getContextPath()).thenReturn("/signserver/adminweb");
        when(req.isSecure()).thenReturn(true);
        when(req.getSession(false)).thenReturn(session);
        when(req.getSession()).thenReturn(mock(HttpSession.class));

        filter.doFilter(req, resp, chain);

        verify(resp).sendRedirect("/signserver/adminweb/login.xhtml");
    }

    /**
     * Requests to the login.xhtml when already logged in should redirect to the logout.xhtml.
     */
    @Test
    public void testLoginPageWhenLoggedInRedirectsToLogout() throws IOException, ServletException {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        HttpSession session = mock(HttpSession.class);
        FilterChain chain = mock(FilterChain.class);

        when(req.getRequestURI()).thenReturn("/signserver/adminweb/login.xhtml");
        when(req.getContextPath()).thenReturn("/signserver/adminweb");
        when(req.isSecure()).thenReturn(true);
        when(req.getSession(false)).thenReturn(session);
        when(req.getSession()).thenReturn(session);
        when(session.getAttribute("LOGGEDIN")).thenReturn(LoginType.OIDC);

        filter.doFilter(req, resp, chain);

        verify(resp).sendRedirect("/signserver/adminweb/logout.xhtml");
    }

    /**
     * Requests to the login.xhtml when not logged in should pass through.
     */
    @Test
    public void testLoginPageWhenNotLoggedInPassesThrough() throws IOException, ServletException {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        when(req.getRequestURI()).thenReturn("/signserver/adminweb/login.xhtml");
        when(req.getContextPath()).thenReturn("/signserver/adminweb");
        when(req.isSecure()).thenReturn(true);
        when(req.getSession(false)).thenReturn(null);
        when(req.getSession()).thenReturn(mock(HttpSession.class));

        filter.doFilter(req, resp, chain);

        verify(chain).doFilter(req, resp);
    }

    /**
     * For CLIENT_CERT login type, a certificate must be present; otherwise redirect to the login.
     */
    @Test
    public void testClientCertLoginTypeWithoutCertRedirectsToLogin() throws IOException, ServletException {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        HttpSession session = mock(HttpSession.class);
        FilterChain chain = mock(FilterChain.class);

        when(req.getRequestURI()).thenReturn("/signserver/adminweb/workers.xhtml");
        when(req.getContextPath()).thenReturn("/signserver/adminweb");
        when(req.isSecure()).thenReturn(true);
        when(req.getSession(false)).thenReturn(session);
        when(req.getSession()).thenReturn(session);
        when(session.getAttribute("LOGGEDIN")).thenReturn(LoginType.CLIENT_CERT);
        when(req.getAttribute("jakarta.servlet.request.X509Certificate")).thenReturn(null);

        filter.doFilter(req, resp, chain);

        verify(resp).sendRedirect("/signserver/adminweb/login.xhtml");
    }

    /**
     * For CLIENT_CERT login type, having a certificate should allow request pass through.
     */
    @Test
    public void testClientCertLoginTypeWithCertPassesThrough() throws IOException, ServletException {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        HttpSession session = mock(HttpSession.class);
        FilterChain chain = mock(FilterChain.class);

        X509Certificate[] chainCerts = new X509Certificate[] { mock(X509Certificate.class) };

        when(req.getRequestURI()).thenReturn("/signserver/adminweb/workers.xhtml");
        when(req.getContextPath()).thenReturn("/signserver/adminweb");
        when(req.isSecure()).thenReturn(true);
        when(req.getSession(false)).thenReturn(session);
        when(req.getSession()).thenReturn(session);
        when(session.getAttribute("LOGGEDIN")).thenReturn(LoginType.CLIENT_CERT);
        when(req.getAttribute("jakarta.servlet.request.X509Certificate")).thenReturn(chainCerts);

        filter.doFilter(req, resp, chain);

        verify(chain).doFilter(req, resp);
        verify(resp, never()).sendRedirect(anyString());
    }

    /**
     * Insecure requests should invalidate the session before proceeding with logic.
     */
    @Test
    public void testInsecureRequestInvalidatesSession() throws IOException, ServletException {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        HttpSession session = mock(HttpSession.class);
        FilterChain chain = mock(FilterChain.class);

        when(req.getRequestURI()).thenReturn("/signserver/adminweb/login.xhtml");
        when(req.getContextPath()).thenReturn("/signserver/adminweb");
        when(req.isSecure()).thenReturn(false);
        when(req.getSession()).thenReturn(session);
        when(req.getSession(false)).thenReturn(session);

        filter.doFilter(req, resp, chain);

        verify(session).removeAttribute("LOGGEDIN");
        verify(session).invalidate();
        verify(chain).doFilter(req, resp);
    }
}
