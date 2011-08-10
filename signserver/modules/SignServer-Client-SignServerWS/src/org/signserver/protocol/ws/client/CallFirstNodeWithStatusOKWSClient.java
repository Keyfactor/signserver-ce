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
package org.signserver.protocol.ws.client;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import javax.net.ssl.HttpsURLConnection;

import javax.net.ssl.SSLSocketFactory;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;

import org.apache.log4j.Logger;
import org.signserver.protocol.ws.ProcessRequestWS;
import org.signserver.protocol.ws.ProcessResponseWS;
import org.signserver.protocol.ws.gen.CryptoTokenOfflineException_Exception;
import org.signserver.protocol.ws.gen.IllegalRequestException_Exception;
import org.signserver.protocol.ws.gen.InvalidWorkerIdException_Exception;
import org.signserver.protocol.ws.gen.SignServerException_Exception;
import org.signserver.protocol.ws.gen.SignServerWS;
import org.signserver.protocol.ws.gen.SignServerWSService;
import org.signserver.protocol.ws.gen.WorkerStatusWS;

//import com.sun.xml.ws.developer.JAXWSProperties;

/**
 * The main message client class that implements the 
 * high availability functionality and should be used
 * by clients to make reliable calls to a message api
 * server cluster.
 *
 * @author Philip Vendil 2007 feb 3
 * @version $Id$
 */
public class CallFirstNodeWithStatusOKWSClient implements ISignServerWSClient {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CallFirstNodeWithStatusOKWSClient.class);
    
    private String[] hosts;
    private int timeOut;
    private String fastestHost = null;
    private String protocol = SignServerWSClientFactory.PROTOCOL;
    private int port = 0;
    private String wSDLURL = null;
    private SSLSocketFactory sSLSocketFactory = null;
    private HashMap<String, SignServerWS> serviceMap = new HashMap<String, SignServerWS>();
    private IFaultCallback faultCallback;

    /**
     * Special constructor used from test scripts
     * 
     * @param host to connect to
     * @param port to connect to
     * @param securityLayer to use
     * @param transportLayer to use
     * @param timeOut in milliseconds
     * @param wSDLURL the URL to the WSDL of the service appended to the host and port.
     * @param useHTTPS if HTTPS should be used.  
     * @param sSLSocketFactory the SSLSocketFactory to use, null means that the Default 
     * SSLSocketFactory will be used if necessary. 
     */
    public void init(String[] hosts, int port, int timeOut,
            String wSDLURL, boolean useHTTPS,
            IFaultCallback faultCallback,
            SSLSocketFactory sSLSocketFactory) {

        this.hosts = hosts;
        this.timeOut = timeOut;
        if (useHTTPS) {
            protocol = SignServerWSClientFactory.SECURE_PROTOCOL;
        }
        this.port = port;
        this.wSDLURL = wSDLURL;
        this.faultCallback = faultCallback;

        this.sSLSocketFactory = sSLSocketFactory;
        if (sSLSocketFactory != null) {
            HttpsURLConnection.setDefaultSSLSocketFactory(sSLSocketFactory);
        }

        for (int i = 0; i < hosts.length; i++) {
            try {
                connectToHost(hosts[i]);
            } catch (Throwable e) {
                faultCallback.addCommunicationError(new GenericCommunicationFault("Error initializing connection : " + e.getMessage(), hosts[i], e));
            }


        }
    }

    private SignServerWS connectToHost(String host) {
        SignServerWS retval = null;
        retval = serviceMap.get(host);
        if (retval == null) {
            try {
                QName qname = new QName("gen.ws.protocol.signserver.org", "SignServerWSService");
                URL u = new URL(protocol + host + ":" + port + wSDLURL);
                SignServerWSService signServerWSService = new SignServerWSService(u, qname);
                retval = signServerWSService.getSignServerWSPort();
                if (retval instanceof BindingProvider) {
                    ((BindingProvider) retval).getRequestContext().put(
                            "com.sun.xml.ws.connect.timeout", timeOut);
                    ((BindingProvider) retval).getRequestContext().put(
                            "com.sun.xml.ws.request.timeout", timeOut);
                }
                serviceMap.put(host, retval);
            } catch (MalformedURLException e) {
                LOG.error("MalformedURLException :" + protocol + host + ":" + port + wSDLURL, e);
            }
        }

        return retval;
    }

    /**
     * @see org.signserver.protocol.ws.client.ISignServerWSClient#process(String, List, IFaultCallback)
     */
    public List<ProcessResponseWS> process(String workerId, List<ProcessRequestWS> requests) {
        List<ProcessResponseWS> resp = null;

        String fastestHost = getFastestHost(workerId, faultCallback);

        if (fastestHost != null) {
            SignServerWS service = connectToHost(fastestHost);

            try {
                List<org.signserver.protocol.ws.gen.ProcessResponseWS> response = service.process(workerId, WSClientUtil.convertProcessRequestWS(requests));
                if (response != null && response.size() != 0) {
                    resp = WSClientUtil.convertProcessResponseWS(response);
                }
            } catch (IllegalRequestException_Exception e) {
                faultCallback.addCommunicationError(new GenericCommunicationFault("IllegalRequestException : " + e.getMessage(), fastestHost, new org.signserver.common.IllegalRequestException(e.getMessage())));
            } catch (InvalidWorkerIdException_Exception e) {
                faultCallback.addCommunicationError(new GenericCommunicationFault("InvalidWorkerIdException : " + e.getMessage(), fastestHost, new org.signserver.common.InvalidWorkerIdException(e.getMessage())));
            } catch (SignServerException_Exception e) {
                faultCallback.addCommunicationError(new GenericCommunicationFault("SignServerException : " + e.getMessage(), fastestHost, new org.signserver.common.SignServerException(e.getMessage())));
            } catch (CryptoTokenOfflineException_Exception e) {
                faultCallback.addCommunicationError(new GenericCommunicationFault("CryptoTokenOfflineException : " + e.getMessage(), fastestHost, new org.signserver.common.CryptoTokenOfflineException(e.getMessage())));
            } catch (Throwable e) {
                faultCallback.addCommunicationError(new GenericCommunicationFault(e.getMessage(), fastestHost, e));
            }

        }

        return resp;
    }

    /**
     * Method that sends a status requests to all hosts
     * in the cluster and returns the host name of
     * the first to respond
     * 
     * If some error occurred of making a call to some
     * of the nodes the error callback will be called
     * 
     * @param errorCallback
     * @return the fastest host or null if no host responded within the timeout.
     */
    String getFastestHost(String workerId, IFaultCallback errorCallback) {
        this.fastestHost = null;

        Thread[] threads = new Thread[hosts.length];
        for (int i = 0; i < hosts.length; i++) {
            threads[i] = new Thread(new StatusChecker(workerId, "ID " + i, hosts[i], errorCallback));
            threads[i].start();
        }
        synchronized (this) {
            try {
                this.wait(timeOut);
            } catch (InterruptedException e) {
                throw new Error(e);
            }
        }

        return fastestHost;
    }

    /**
     * Inner class running a thread that sends
     * a status request to each of the servers
     * in the cluster.
     * 
     */
    private class StatusChecker implements Runnable {

        private Logger logStatusChecker = Logger.getLogger(StatusChecker.class);
        final private String host;
        final private IFaultCallback errorCallback;
        final private String id;
        final private String workerId;

        public StatusChecker(String workerId, String id, String host, IFaultCallback errorCallback) {
            super();
            this.workerId = workerId;
            this.id = id;
            this.host = host;
            this.errorCallback = errorCallback;
        }

        @SuppressWarnings("synthetic-access")
        public void run() {
            boolean statusOK = false;
            logStatusChecker.debug("Thread with id : " + id + " started.");

            try {
                if (connectToHost(host) != null) {
                    List<WorkerStatusWS> result = connectToHost(host).getStatus(workerId);
                    if (result != null && result.size() == 1) {
                        WorkerStatusWS status = result.get(0);
                        if (status.getOverallStatus().equals(org.signserver.protocol.ws.WorkerStatusWS.OVERALLSTATUS_ALLOK)) {
                            statusOK = true;
                        } else {
                            errorCallback.addCommunicationError(new GenericCommunicationFault("Error the node responded status ERROR :" + status.getErrormessage(), host));
                        }
                    }
                } else {
                    errorCallback.addCommunicationError(new GenericCommunicationFault("Error Couldn't connect to host : " + host, host));
                }
            } catch (InvalidWorkerIdException_Exception e) {
                errorCallback.addCommunicationError(new GenericCommunicationFault(host, new org.signserver.common.InvalidWorkerIdException(e.getMessage())));
            } catch (Throwable e) {
                errorCallback.addCommunicationError(new GenericCommunicationFault(host, e));
                serviceMap.remove(host);
            }
            logStatusChecker.debug("Thread with id : " + id + " finished.");
            synchronized (CallFirstNodeWithStatusOKWSClient.this) {
                if (fastestHost == null && statusOK) {
                    fastestHost = host;
                    CallFirstNodeWithStatusOKWSClient.this.notifyAll();
                }
            }
        }
    }
}
