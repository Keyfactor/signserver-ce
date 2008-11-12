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

/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 * 
 * Copyright 1997-2007 Sun Microsystems, Inc. All rights reserved.
 * 
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License. You can obtain
 * a copy of the License at https://glassfish.dev.java.net/public/CDDL+GPL.html
 * or glassfish/bootstrap/legal/LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 * 
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at glassfish/bootstrap/legal/LICENSE.txt.
 * Sun designates this particular file as subject to the "Classpath" exception
 * as provided by Sun in the GPL Version 2 section of the License file that
 * accompanied this code.  If applicable, add the following below the License
 * Header, with the fields enclosed by brackets [] replaced by your own
 * identifying information: "Portions Copyrighted [year]
 * [name of copyright owner]"
 * 
 * Contributor(s):
 * 
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
 */

package org.signserver.server.genericws;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
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

import com.sun.istack.NotNull;
import com.sun.xml.ws.api.server.BoundEndpoint;
import com.sun.xml.ws.api.server.Container;
import com.sun.xml.ws.resources.WsservletMessages;
import com.sun.xml.ws.transport.http.DeploymentDescriptorParser;
import com.sun.xml.ws.transport.http.ResourceLoader;
import com.sun.xml.ws.transport.http.servlet.ServletAdapter;
import com.sun.xml.ws.transport.http.servlet.ServletAdapterList;
import com.sun.xml.ws.transport.http.servlet.ServletModule;
import com.sun.xml.ws.transport.http.servlet.WSServletDelegate;

/**
 * Class managing a custom JAX-WS web service. It'made so it is possible
 * to develop your own Jax-ws web service and just deploy it as a MAR
 * module to a signserver.
 * 
 * Some of the code in this class is borrowed and customized from the
 * JAX-WS API and therefore is their license header included in this
 * file.
 * 
 * @author Philip Vendil 8 okt 2008
 *
 * @version $$
 */

public class GenericWSWorker extends BaseProcessable {
	
	private transient Logger log = Logger.getLogger(this.getClass());
	
	private static final String JAXWS_RI_RUNTIME = "/WEB-INF/sun-jaxws.xml";
	private static final String JAXWS_ALT_RI_RUNTIME = "/sun-jaxws.xml";

	private static final String REPLACETAG_WORKERNAME = "WORKERNAME";
	private static final String REPLACETAG_WORKERID = "WORKERID";
	
	private WSServletDelegate delegate = null;

	private ServletContext context;
	
	/**
	 * Initialization method creating the validation service
	 * @see org.signserver.server.BaseWorker#init(int, org.signserver.common.WorkerConfig, javax.persistence.EntityManager)
	 */
	@Override
	public void init(int workerId, WorkerConfig config, WorkerContext workerContext,EntityManager workerEntityManager) {		
		super.init(workerId, config, workerContext,workerEntityManager);
				
	}

	


    /**
     * Gets the {@link WSServletDelegate} that we will be forwarding the requests to.
     *
     * @return
     *      null if the deployment have failed and we don't have the delegate.
     */
    protected  WSServletDelegate getDelegate(ServletConfig servletConfig) {
    	if(delegate == null){
    	       log.info(WsservletMessages.LISTENER_INFO_INITIALIZE());
    	        ClassLoader classLoader = WorkerFactory.getInstance().getClassLoader(em, workerId, config);
    	        if (classLoader == null) {
    	            classLoader = getClass().getClassLoader();
    	        }
    	        try {
    	            // Parse the descriptor file and build endpoint infos
    	            DeploymentDescriptorParser<ServletAdapter> parser = new DeploymentDescriptorParser<ServletAdapter>(
    	                classLoader,new ServletResourceLoader(context), createContainer(context), new ServletAdapterList());
    	            
    	            String sunJaxWsXml = null;
    	            if(config.getProperty(GenericWSConstants.SUNJAXWSLOCATION) != null){    	            	
    	            	sunJaxWsXml =config.getProperty(GenericWSConstants.SUNJAXWSLOCATION);
    	            }
    	            if(sunJaxWsXml == null){
    	              if(WorkerFactory.getInstance().getClassLoader(em, workerId, config).getResourceAsStream(JAXWS_ALT_RI_RUNTIME)!= null){
    	            	  sunJaxWsXml = JAXWS_ALT_RI_RUNTIME;
    	              }
    	            }
    	            if(sunJaxWsXml==null){
    	            	if(WorkerFactory.getInstance().getClassLoader(em, workerId, config).getResourceAsStream(JAXWS_RI_RUNTIME)!= null){
      	            	  sunJaxWsXml = JAXWS_RI_RUNTIME;
      	              }
    	            }
    	            if(sunJaxWsXml==null){
    	                throw new WebServiceException(WsservletMessages.NO_SUNJAXWS_XML(JAXWS_ALT_RI_RUNTIME));
    	            }
    	            
    	            InputStream is = insertWorkerNameIntoJAXWSXML(WorkerFactory.getInstance().getClassLoader(em, workerId, config).getResourceAsStream(sunJaxWsXml));
    	            
    	            List<ServletAdapter> adapters = parser.parse(sunJaxWsXml,is);
    	            
    	            delegate = createDelegate(adapters, context);    	            
    	            
    	        } catch (Throwable e) {
    	            log.error(WsservletMessages.LISTENER_PARSING_FAILED(e),e);
    	            log.error("Parsing of sun-jaxws.xml failed ",e);
    	        }
    	}
    	return delegate;
    }

    /**
     * A Help method that replaces the text
     * WORKERNAME or WORKERID in the sun-jaxws.xml file.
     * @param resourceAsStream
     * @return an input stream with the values replaced.
     * @throws IOException 
     */
    private InputStream insertWorkerNameIntoJAXWSXML(
			InputStream in) throws IOException {		
		String workerName = this.config.getProperty(ProcessableConfig.NAME);

		
        StringBuilder out = new StringBuilder();
		byte[] b = new byte[4096];
		for (int n; (n = in.read(b)) != -1;) {
			out.append(new String(b, 0, n));
		}
		
		String jaxwsData = out.toString();
		jaxwsData = jaxwsData.replaceAll(REPLACETAG_WORKERID, ""+workerId);
		if(workerName != null){
			jaxwsData = jaxwsData.replaceAll(REPLACETAG_WORKERNAME, workerName.toLowerCase());
		}
		
		return new ByteArrayInputStream(jaxwsData.getBytes());
	}




	protected void doPost( GenericWSRequest request) throws ServletException {

        if (getDelegate(request.getServletConfig()) != null) {
            delegate.doPost(request.getHttpServletRequest(),request.getHttpServletResponse(),request.getServletContext());
        }
    }

    protected void doGet( GenericWSRequest request)
        throws ServletException {    		
    		if (getDelegate(request.getServletConfig()) != null) {
    			delegate.doGet(request.getHttpServletRequest(),request.getHttpServletResponse(),request.getServletContext());
    		}
    }
    
    protected void doPut( GenericWSRequest request)
        throws ServletException {

        if (getDelegate(request.getServletConfig()) != null) {
            delegate.doPut(request.getHttpServletRequest(),request.getHttpServletResponse(),request.getServletContext());
        }
    }
        
    protected void doDelete( GenericWSRequest request)
        throws ServletException {
    	if (getDelegate(request.getServletConfig()) != null) {
            delegate.doDelete(request.getHttpServletRequest(),request.getHttpServletResponse(),request.getServletContext());
        }
    }

    public void contextDestroyed() {
        if (delegate != null) { // the deployment might have failed.
            delegate.destroy();
        }
        
        log.info(WsservletMessages.LISTENER_INFO_DESTROY());

    }

    public void contextInitialized(GenericWSRequest request) {        
                
        context = request.getServletContext();
 
    }



    /**
     * Main method of the container calling the appropriate method
     * of the ValidationService depending on the type of request.
     * 
     * @see org.signserver.server.signers.IProcessable#processData(org.signserver.common.ProcessRequest, java.security.cert.X509Certificate)
     */
    public ProcessResponse processData(ProcessRequest processRequest,
    		RequestContext requestContext) throws IllegalRequestException,
    		CryptoTokenOfflineException, SignServerException {
    	try{			
    		if(processRequest instanceof GenericWSRequest){
    			GenericWSRequest genwsreq = (GenericWSRequest) processRequest;

    			context = genwsreq.getServletContext();

    			if(genwsreq.getRequestType() != GenericWSRequest.REQUESTTYPE_CONTEXT_DESTROYED && 
    					genwsreq.getRequestType() != GenericWSRequest.REQUESTTYPE_CONTEXT_INIT	){
    				populateRequest(genwsreq, requestContext);
    			}

    			ClassLoader orgContextClassLoader = Thread.currentThread().getContextClassLoader();
    			try{
    				Thread.currentThread().setContextClassLoader(WorkerFactory.getInstance().getClassLoader(em, workerId, config));
    				
    				switch(genwsreq.getRequestType()){
    				case GenericWSRequest.REQUESTTYPE_POST :
    					doPost(genwsreq);
    					break;
    				case GenericWSRequest.REQUESTTYPE_GET :
    					doGet(genwsreq);
    					break;
    				case GenericWSRequest.REQUESTTYPE_PUT :
    					doPut(genwsreq);
    					break;
    				case GenericWSRequest.REQUESTTYPE_DEL :
    					doDelete(genwsreq);
    					break;
    				case GenericWSRequest.REQUESTTYPE_CONTEXT_DESTROYED :
    					contextDestroyed();
    					break;
    				case GenericWSRequest.REQUESTTYPE_CONTEXT_INIT :
    					contextInitialized(genwsreq);
    					break;
    				}
    			}finally{
    				Thread.currentThread().setContextClassLoader(orgContextClassLoader);
    			}
    		}else{
    			throw new IllegalRequestException("The process request sent to generic WebService with id " + workerId + " isn't supported");
    		}


    	} catch (ServletException e) {
    		log.error(e);
    		throw new SignServerException("Error processing Generic WS request.", e);
    	}		

    	return genResponse((GenericWSRequest) processRequest);

    }

	
	private void populateRequest(GenericWSRequest genwsreq, RequestContext requestContext) {
		HttpServletRequest req = genwsreq.getHttpServletRequest();
		req.setAttribute(BaseWS.WORKERID, workerId);
		req.setAttribute(BaseWS.GLOBALENTITYMANAGER, em);
		req.setAttribute(BaseWS.WORKERENTITYMANAGER, workerEM);
		req.setAttribute(BaseWS.WORKERCONFIG, config);
		req.setAttribute(BaseWS.REQUESTCONTEXT, requestContext);
		req.setAttribute(BaseWS.CRYPTOTOKEN, getCryptoToken());
		try {
			req.setAttribute(BaseWS.WORKERCERTIFICATE, getSigningCertificate());
		    req.setAttribute(BaseWS.WORKERCERTIFICATECHAIN, getSigningCertificateChain());
		} catch (CryptoTokenOfflineException e) {
			log.error("Error fetching worker certificate when initializing web service : ",e);
		}
	}



	private ProcessResponse genResponse(GenericWSRequest request) throws CryptoTokenOfflineException {
		
		// TODO support Archiving
		return new GenericWSResponse(request.getRequestID(),getSigningCertificate(),null,null);
	}
	


	/**
     * Creates {@link Container} implementation that hosts the JAX-WS endpoint.
     */
    protected  Container createContainer(ServletContext context) {
        return new ServletContainer(context);
    }

    /**
     * Creates {@link WSServletDelegate} that does the real work.
     */
    protected WSServletDelegate createDelegate(List<ServletAdapter> adapters, ServletContext context) {
        return new WSServletDelegate(adapters,context);
    }



	@Override
	public WorkerStatus getStatus() {

		if(statusChecker == null){
			String classPath = config.getProperty(GenericWSConstants.STATUSCHECKER);
			if(classPath != null){
				try {
					statusChecker= (IStatusChecker) this.getClass().getClassLoader().loadClass(classPath).newInstance();
				} catch (ClassNotFoundException e) {
					log.error("Error creating instance of StatusChecker for Generic WebService with id " + workerId +" message : " +e.getMessage(),e);
				} catch (InstantiationException e) {
					log.error("Error creating instance of StatusChecker for Generic WebService with id " + workerId +" message : " +e.getMessage(),e);
				} catch (IllegalAccessException e) {
					log.error("Error creating instance of StatusChecker for Generic WebService with id " + workerId +" message : " +e.getMessage(),e);
				}
			}

			if(statusChecker == null){
				int cryptTokenStatus = SignerStatus.STATUS_OFFLINE;
				if(getCryptoToken() != null){
					cryptTokenStatus = getCryptoToken().getCryptoTokenStatus();
				}
				return new GenericWSStatus(workerId,cryptTokenStatus,config);
			}
		}
		
		
		return statusChecker.getStatus();
	}
	
	private IStatusChecker statusChecker = null;



	
	class ServletResourceLoader implements ResourceLoader {
	    private final ServletContext context;

	    public ServletResourceLoader(ServletContext context) {
	        this.context = context;
	    }

	    public URL getResource(String path) throws MalformedURLException {
	        return WorkerFactory.getInstance().getClassLoader(em, workerId, config).getResource(path);
	    }

	    public URL getCatalogFile() throws MalformedURLException {
	    	URL resource = getResource("jax-ws-catalog.xml");
	    	if(resource != null){
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
	        private final List<BoundEndpoint> endpoints = new ArrayList<BoundEndpoint>();

	        public @NotNull List<BoundEndpoint> getBoundEndpoints() {
	            return endpoints;
	        }

	        public @NotNull String getContextPath() {
	            // Cannot compute this since we don't know about hostname and port etc
	            throw new WebServiceException("Container "+ServletContainer.class.getName()+" doesn't support getContextPath()");
	        }
	    };

	    private final com.sun.xml.ws.api.ResourceLoader loader = new com.sun.xml.ws.api.ResourceLoader() {
	        public URL getResource(String resource) throws MalformedURLException {
	        	URL retval = WorkerFactory.getInstance().getClassLoader(em, workerId, config).getResource(resource);
	        	if(retval == null){
	        		retval = WorkerFactory.getInstance().getClassLoader(em, workerId, config).getResource("/WEB-INF/"+resource);      		
	        	}
	        	if(retval == null){
	        		retval = servletContext.getResource("/WEB-INF/"+resource);      		
	        	}
	            return retval;
	        }			
	    };

	    ServletContainer(ServletContext servletContext) {
	        this.servletContext = servletContext;
	    }

	    public <T> T getSPI(Class<T> spiType) {
	        if (spiType == ServletContext.class) {
	            return spiType.cast(servletContext);
	        }
	        if (spiType.isAssignableFrom(ServletModule.class)) {
	            return spiType.cast(module);
	        }
	        if (spiType == ResourceLoader.class) {
	            return spiType.cast(loader);
	        }
	        return null;
	    }
	    
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#finalize()
	 */
	@Override
	protected void finalize() throws Throwable {
		try{
		contextDestroyed();
		}finally{
		  super.finalize();
		}
	}

}
