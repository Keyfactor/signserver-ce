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
import java.util.Iterator;
import java.util.ServiceLoader;
import javax.ejb.EJB;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import org.apache.log4j.Logger;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.server.ServicesImpl;

/**
 * Web filter providing possibility for extensions to provide a filter
 * implementation.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@WebFilter(asyncSupported = true)
public class ExtensionFilter implements Filter {

    private static final Logger LOG = Logger.getLogger(ExtensionFilter.class);

    @EJB
    private GlobalConfigurationSessionLocal globalSession;

    @EJB
    private WorkerSessionLocal workerSession;

    private ExtensionFilterImpl delegate;

    @Override
    public void init(FilterConfig fc) throws ServletException {
        // Inject services that could be needed by the implementation
        // Future: In case we need all services to be available consider
        // changing this to use the AllServicesImpl instead.
        final ServicesImpl services = new ServicesImpl();
        services.put(WorkerSessionLocal.class, workerSession);
        services.put(GlobalConfigurationSessionLocal.class, globalSession);

        // Load and initialize the extension implementation (if any)
        delegate = loadExtensionFilterImpl();
        if (delegate == null) {
            LOG.info("No extension filter loaded");
        } else {
            LOG.info("Loaded extension filter");
            delegate.init(fc, services);
        }
    }

    private ExtensionFilterImpl loadExtensionFilterImpl() {
        final ExtensionFilterImpl result;
        Iterator<ExtensionFilterImpl> iterator = ServiceLoader.load(ExtensionFilterImpl.class).iterator();
        if (iterator.hasNext()) {
            result = iterator.next();
        } else {
            result = null;
        }
        return result;
    }

    @Override
    public void doFilter(ServletRequest sr, ServletResponse sr1, FilterChain fc) throws IOException, ServletException {
        if (delegate == null) {
            fc.doFilter(sr, sr1);
        } else {
            delegate.doFilter(sr, sr1, fc);
        }
    }

    @Override
    public void destroy() {
        if (delegate != null) {
            delegate.destroy();
        }
    }

}
