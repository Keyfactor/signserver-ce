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
package org.signserver.web.common.filters;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.signserver.server.IServices;

/**
 * Interface for an ExtensionFilter implementation that modules can provide
 * implementations for.
 *
 * This is similar interface as Filter but provides SignServer services in the
 * init method.
 *
 * @author Markus Kilås
 * @version $Id$
 * @see Filter
 */
public interface ExtensionFilterImpl {
    
    /**
     * Called when the filter should be initialized.
     * @param filterConfig for the Filter
     * @param services provided SignServer services
     * @throws ServletException in case of any Exception
     * @see Filter#init(javax.servlet.FilterConfig) 
     */
    void init(FilterConfig filterConfig, IServices services) throws ServletException;

    /**
     * Called when the filter should be used.
     * @param request the request
     * @param response the response
     * @param chain access to next filter in chain
     * @throws IOException in case of I/O error
     * @throws ServletException process failure for any other reason
     * @see Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain) 
     */
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException;

    /**
     * Called when filter is being taken out of service.
     * @see Filter#destroy() 
     */
    void destroy();
    
}
