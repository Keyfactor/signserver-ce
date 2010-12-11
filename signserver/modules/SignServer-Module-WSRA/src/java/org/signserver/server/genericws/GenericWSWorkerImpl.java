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
package org.signserver.server.genericws;

import com.sun.xml.ws.api.server.BoundEndpoint;
import com.sun.xml.ws.api.server.Container;
import com.sun.xml.ws.resources.WsservletMessages;
import com.sun.xml.ws.transport.http.DeploymentDescriptorParser;
import com.sun.xml.ws.transport.http.ResourceLoader;
import com.sun.xml.ws.transport.http.servlet.ServletAdapter;
import com.sun.xml.ws.transport.http.servlet.ServletAdapterList;
import com.sun.xml.ws.transport.http.servlet.ServletModule;
import com.sun.xml.ws.transport.http.servlet.WSServletDelegate;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.persistence.EntityManager;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.xml.ws.WebServiceException;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.common.genericws.GenericWSConstants;
import org.signserver.common.genericws.GenericWSRequest;
import org.signserver.common.genericws.GenericWSResponse;
import org.signserver.common.genericws.GenericWSStatus;
import org.signserver.server.BaseProcessable;
import org.signserver.server.WorkerContext;
import org.signserver.server.WorkerFactory;

/**
 * Class managing a custom JAX-WS web service. It's made so it is possible
 * to develop your own JAX-WS web service and just deploy it included in
 * SignServer or as a module.
 *
 * @version $Id$
 */
public class GenericWSWorkerImpl extends BaseProcessable {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(GenericWSWorkerImpl.class);

    /**
     * Setting used to have a custom implementation checking
     * if a generic WS service is functioning properly.
     *
     * If set it should be set to the class path to a class
     * implementing org.signserver.server.genericws.IStatusChecker
     */
    public static final String STATUSCHECKER = "STATUSCHECKER";
	
    /**
     * Setting used to give a non default location of the
     * sun-jaxws.xml file, such as a location on the file system
     * (used primarily for tests).
     */
    public static final String SUNJAXWSLOCATION = "SUNJAXWSLOCATION";

    private static final String WS_CONFIG = "/WEB-INF/sun-jaxws.xml";
    private static final String WS_CONFIG_ALT = "/sun-jaxws.xml";

    private static final String REPLACETAG_WORKERNAME = "WORKERNAME";
    private static final String REPLACETAG_WORKERID = "WORKERID";

    private String wsConfig;
    private String wsConfigData;

    private IStatusChecker statusChecker;

    private WSServletDelegate delegate;

    private final boolean runningAsModule;

    /**
     * Creates a new instance of GenericWSWorkerImpl.
     * @param runningAsModule False if SignServer is compiled with
     * includemodulesinbuild=true
     */
    public GenericWSWorkerImpl(boolean runningAsModule) {
        this.runningAsModule = runningAsModule;
    }

    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        if (LOG.isDebugEnabled()) {
            LOG.debug("WebServiceWorker[" + workerId + "]: " + ">init: "
                    + toString());
        }

        // Worker name
        final String workerName = config.getProperty(ProcessableConfig.NAME);
        if (workerName == null) {
            LOG.warn("WebServiceWorker[" + workerId + "]: "
                    + "Null workerName.");
        }

        // Find, read and process *jaxws.xml
        wsConfig = config.getProperty(SUNJAXWSLOCATION);
        if (wsConfig == null) {
            if (WorkerFactory.getInstance().getClassLoader(em, workerId, config)
                    .getResourceAsStream(WS_CONFIG_ALT) != null) {
                wsConfig = WS_CONFIG_ALT;
            } else if (WorkerFactory.getInstance()
                        .getClassLoader(em, workerId, config)
                        .getResourceAsStream(WS_CONFIG) != null) {
                wsConfig = WS_CONFIG;
            }
        }
        if (wsConfig == null) {
            LOG.warn("WebServiceWorker[" + workerId + "]: "
                    + "No jaxws XML file found. Property " + SUNJAXWSLOCATION
                    + " not configured correctly for this worker.");
        } else {
            BufferedReader in = null;
            try {
                final InputStream inStream = WorkerFactory.getInstance()
                        .getClassLoader(em, workerId, config)
                        .getResourceAsStream(wsConfig);
                if (inStream == null) {
                    LOG.error("WebServiceWorker[" + workerId + "]: "
                    + "The jaxws XML file could not be read: " + wsConfig);
                } else {
                    in = new BufferedReader(new InputStreamReader(inStream));
                    final StringBuilder strBuilder = new StringBuilder();
                    String line;
                    while ((line = in.readLine()) != null) {
                        strBuilder.append(line);
                    }

                    // Insert workername/workerid
                    wsConfigData = strBuilder.toString();
                    wsConfigData = wsConfigData.replaceAll(REPLACETAG_WORKERID,
                            String.valueOf(workerId));
                    if (workerName != null) {
                        wsConfigData = wsConfigData
                                .replaceAll(REPLACETAG_WORKERNAME,
                                workerName.toLowerCase());
                    }
                }
            } catch (IOException ex) {
                LOG.error("WebServiceWorker[" + workerId + "]: "
                    + "The jaxws XML file could not be read: "
                    + ex.getMessage(), ex);
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch (IOException ex) {
                        LOG.error("WebServiceWorker[" + workerId + "]: "
                        + "Exception closing file: " + ex.getMessage(), ex);
                    }
                }
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("JAX-WS config: \"" + wsConfigData + "\"");
        }
    }

    @Override
    public WorkerStatus getStatus() {
        if (statusChecker == null) {
            final String className =
                    config.getProperty(GenericWSConstants.STATUSCHECKER);
            if (className != null) {
                try {
                    statusChecker = (IStatusChecker) getClass()
                        .getClassLoader().loadClass(className).newInstance();
                } catch (ClassNotFoundException ex) {
                    LOG.error("WebServiceWorker[" + workerId + "]: "
                            + "Error instantiating StatusChecker: "
                            + ex.getMessage(), ex);
                } catch (InstantiationException ex) {
                    LOG.error("WebServiceWorker[" + workerId + "]: "
                            + "Error instantiating StatusChecker: "
                            + ex.getMessage(), ex);
                } catch (IllegalAccessException ex) {
                    LOG.error("WebServiceWorker[" + workerId + "]: "
                            + "Error instantiating StatusChecker: "
                            + ex.getMessage(), ex);
                }
            }

            if (statusChecker == null) {
                int cryptTokenStatus = SignerStatus.STATUS_OFFLINE;
                if (getCryptoToken() != null) {
                    cryptTokenStatus = getCryptoToken().getCryptoTokenStatus();
                }
                return new GenericWSStatus(workerId, cryptTokenStatus, config);
            }
        }
        return statusChecker.getStatus();
    }

    @Override
    public ProcessResponse processData(final ProcessRequest processRequest,
            final RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        
        final GenericWSRequest wsRequest;

        try {
            if (processRequest instanceof GenericWSRequest) {
                wsRequest = (GenericWSRequest) processRequest;

                //TODO is this needed/wanted?? context = wsRequest.getServletContext();

                // Inject worker variables
                if (wsRequest.getRequestType()
                        != GenericWSRequest.REQUESTTYPE_CONTEXT_DESTROYED
                        && wsRequest.getRequestType()
                        != GenericWSRequest.REQUESTTYPE_CONTEXT_INIT) {
                    populateRequest(wsRequest, requestContext);
                }

                // Save current class loader
                final ClassLoader origClassLoader
                        = Thread.currentThread().getContextClassLoader();
                try {
                    // Set the worker's class loader
                    if (runningAsModule) {
                        Thread.currentThread().setContextClassLoader(
                            WorkerFactory.getInstance()
                            .getClassLoader(em, workerId, config));
                    }

                    // Serve the request depending on type
                    switch (wsRequest.getRequestType()) {
                        case GenericWSRequest.REQUESTTYPE_POST:
                            doPost(wsRequest);
                            break;
                        case GenericWSRequest.REQUESTTYPE_GET:
                            doGet(wsRequest);
                            break;
                        case GenericWSRequest.REQUESTTYPE_PUT:
                            doPut(wsRequest);
                            break;
                        case GenericWSRequest.REQUESTTYPE_DEL:
                            doDelete(wsRequest);
                            break;
                        case GenericWSRequest.REQUESTTYPE_CONTEXT_DESTROYED:
                            contextDestroyed();
                            break;
                        case GenericWSRequest.REQUESTTYPE_CONTEXT_INIT:
                            contextInitialized(wsRequest);
                            break;
                    }
                } finally {
                    // Restore original class loader
                    if (runningAsModule) {
                        Thread.currentThread().setContextClassLoader(
                            origClassLoader);
                    }
                }
            } else {
                throw new IllegalRequestException(
                        "WebServiceWorker[" + workerId + "]: "
                        + "Unsupported request type");
            }


        } catch (ServletException e) {
            LOG.error(e);
            throw new SignServerException("WebServiceWorker[" + workerId + "]: "
                    + "Error processing request.", e);
        }

        // Return response
        return genResponse(wsRequest);
    }

    private void doPost(final GenericWSRequest request)
            throws ServletException {
        if (getDelegate(request.getServletConfig(),
                request.getServletContext()) != null) {
            delegate.doPost(request.getHttpServletRequest(),
                    request.getHttpServletResponse(),
                    request.getServletContext());
        }
    }

    private void doGet(final GenericWSRequest request)
            throws ServletException {
        if (getDelegate(request.getServletConfig(),
                request.getServletContext()) != null) {
            delegate.doGet(request.getHttpServletRequest(),
                    request.getHttpServletResponse(),
                    request.getServletContext());
        }
    }

    private void doPut(final GenericWSRequest request)
            throws ServletException {

        if (getDelegate(request.getServletConfig(),
                request.getServletContext()) != null) {
            delegate.doPut(request.getHttpServletRequest(),
                    request.getHttpServletResponse(),
                    request.getServletContext());
        }
    }

    private void doDelete(final GenericWSRequest request)
            throws ServletException {
        if (getDelegate(request.getServletConfig(),
                request.getServletContext()) != null) {
            delegate.doDelete(request.getHttpServletRequest(),
                    request.getHttpServletResponse(),
                    request.getServletContext());
        }
    }

    public void contextDestroyed() {
        LOG.debug(">contextDestroyed");
        if (delegate != null) {
            delegate.destroy();
        }
        LOG.info(WsservletMessages.LISTENER_INFO_DESTROY());
    }

    public void contextInitialized(final GenericWSRequest request) {
        LOG.debug(">contextInitialized");
    }

    /**
     * @return The delegate to forward the request to.
     */
    protected  WSServletDelegate getDelegate(
            final ServletConfig servletConfig,
            final ServletContext servletContext) {
        LOG.debug(">getDelegate");

        if (delegate == null) {
            LOG.debug("loadDelegate");

            // Get class loader
            ClassLoader classLoader = WorkerFactory.getInstance()
                    .getClassLoader(em, workerId, config);
            if (classLoader == null) {
                classLoader = getClass().getClassLoader();
            }

            try {
                // Parse the descriptor file and build endpoint infos
                final DeploymentDescriptorParser<ServletAdapter> parser
                        = new DeploymentDescriptorParser<ServletAdapter>(
                        classLoader, new ServletResourceLoader(servletContext),
                        new ServletContainer(servletContext),
                        new ServletAdapterList());

                if (wsConfigData == null) {
                    throw new WebServiceException(
                            "No JAX-WS XML file configured for this worker");
                }

                final List<ServletAdapter> adapters = parser.parse(wsConfigData,
                        new ByteArrayInputStream(wsConfigData.getBytes()));

                delegate = new WSServletDelegate(adapters, servletContext);

            } catch (Throwable e) {
                LOG.error(WsservletMessages.LISTENER_PARSING_FAILED(e), e);
                LOG.error("Parsing of sun-jaxws.xml failed ", e);
            }
        }
        return delegate;
    }

    private void populateRequest(final GenericWSRequest genwsreq,
            final RequestContext requestContext) {
        final HttpServletRequest req = genwsreq.getHttpServletRequest();
        req.setAttribute(BaseWS.WORKERID, workerId);
        req.setAttribute(BaseWS.GLOBALENTITYMANAGER, em);
        req.setAttribute(BaseWS.WORKERENTITYMANAGER, workerEM);
        req.setAttribute(BaseWS.WORKERCONFIG, config);
        req.setAttribute(BaseWS.REQUESTCONTEXT, requestContext);
        req.setAttribute(BaseWS.CRYPTOTOKEN, getCryptoToken());
        try {
            req.setAttribute(BaseWS.WORKERCERTIFICATE, getSigningCertificate());
            req.setAttribute(BaseWS.WORKERCERTIFICATECHAIN,
                    getSigningCertificateChain());
        } catch (CryptoTokenOfflineException e) {
            LOG.error("WebServiceWorker[" + workerId + "]: "
                + "Error fetching worker certificate when initializing web service : ", e);
        }
    }

    private ProcessResponse genResponse(final GenericWSRequest request)
            throws CryptoTokenOfflineException {
        // TODO support Archiving
        return new GenericWSResponse(request.getRequestID(),
                getSigningCertificate(), null, null);
    }

    class ServletResourceLoader implements ResourceLoader {

        private final ServletContext context;

        public ServletResourceLoader(ServletContext context) {
            this.context = context;
        }

        public URL getResource(String path) throws MalformedURLException {
            return WorkerFactory.getInstance()
                    .getClassLoader(em, workerId, config).getResource(path);
        }

        public URL getCatalogFile() throws MalformedURLException {
            final URL resource = getResource("jax-ws-catalog.xml");
            if (resource != null) {
                return resource;
            }
            return getResource("/WEB-INF/jax-ws-catalog.xml");
        }

        @SuppressWarnings("unchecked")
        public Set<String> getResourcePaths(String path) {
            return context.getResourcePaths(path);
        }
    }

    class ServletContainer extends Container {
        private final ServletContext servletContext;

        private final ServletModule module = new ServletModule() {
            private final List<BoundEndpoint> endpoints
                    = new ArrayList<BoundEndpoint>();

            @Override
            public List<BoundEndpoint> getBoundEndpoints() {
                return endpoints;
            }

            @Override
            public String getContextPath() {
                throw new WebServiceException("Container "
                        + ServletContainer.class.getName()
                        + " doesn't support getContextPath().");
            }
        };

        private final com.sun.xml.ws.api.ResourceLoader loader
                = new com.sun.xml.ws.api.ResourceLoader() {

            public URL getResource(String resource) throws MalformedURLException {
                URL retval = WorkerFactory.getInstance()
                        .getClassLoader(em, workerId, config)
                        .getResource(resource);
                if(retval == null){
                    retval = WorkerFactory.getInstance()
                            .getClassLoader(em, workerId, config)
                            .getResource("/WEB-INF/"+resource);
                }
                if(retval == null){
                    retval = servletContext.getResource("/WEB-INF/"+resource);
                }
                return retval;
            }
        };

        public ServletContainer(ServletContext servletContext) {
            this.servletContext = servletContext;
        }

        @Override
        public <T> T getSPI(Class<T> type) {
            if (type == ServletContext.class) {
                return type.cast(servletContext);
            }
            if (type.isAssignableFrom(ServletModule.class)) {
                return type.cast(module);
            }
            if (type == ResourceLoader.class) {
                return type.cast(loader);
            }
            return null;
        }
    }

    @Override
    public void destroy() {
        try {
            contextDestroyed();
        } finally {
            super.destroy();
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            contextDestroyed();
        } finally {
            super.finalize();
        }
    }
}
