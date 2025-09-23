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

import java.io.IOException;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.security.cert.X509Certificate;

/**
 * Web filter responsible for redirecting to the login/logout pages depending on the
 * login state.
 */
public class LoginFilter implements Filter {

    /** Session attribute for the logged in state. */
    protected static final String LOGGEDIN_ATTRIBUTE = "LOGGEDIN";

    public LoginFilter() {
    }

    @Override
    public void init(final FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {

        final HttpServletRequest req = (HttpServletRequest) request;
        final HttpServletResponse resp = (HttpServletResponse) response;
        final String reqURI = req.getRequestURI();

        // Clear session is cookie sent in clear
        if (!req.isSecure()) {
            req.getSession().removeAttribute(LOGGEDIN_ATTRIBUTE);
            req.getSession().invalidate();
        }

        if (reqURI.contains("/login.xhtml") && isLoggedIn(req)) { // Already logged in, instead go to logout page
            resp.sendRedirect(req.getContextPath() + "/logout.xhtml");
        } else if (reqURI.contains("/login.xhtml") || reqURI.contains("/logout.xhtml") || isLoggedIn(req) || reqURI.contains("jakarta.faces.resource")) { // Going for login, or already logged in or a resource then proceed
            chain.doFilter(request, response);
        } else { // Otherwise go to login page
            resp.sendRedirect(req.getContextPath() + "/login.xhtml");
        }
    }

    @Override
    public void destroy() {
    }
    
    private boolean isLoggedIn(final HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        if (session == null) {
            return false;
        } else {
            LoginType loginType = (LoginType) req.getSession().getAttribute(LOGGEDIN_ATTRIBUTE);

            // For CLIENT_CERT we also need the certificate to be present
            final X509Certificate[] certificates = (X509Certificate[]) req.getAttribute("jakarta.servlet.request.X509Certificate");
            return loginType != null && (loginType != LoginType.CLIENT_CERT || (certificates != null && certificates.length > 0));
        }
    }

}
