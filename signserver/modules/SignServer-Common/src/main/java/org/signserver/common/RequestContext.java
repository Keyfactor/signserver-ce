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
package org.signserver.common;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.persistence.EntityManager;
import org.signserver.server.IServices;

/**
 * Object containing extra information about a request not sent by the client
 * this could be the client certificate used to authenticate to the web server,
 * remote IP of the client or other information that could be useful for the worker.
 *
 * @author Philip Vendil 1 dec 2007
 * @version $Id$
 */
public class RequestContext implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * The request metadata optionally supplied by the client.
     */
    public static final String REQUEST_METADATA = "REQUEST_METADATA";
    
    /**
     * The metadata property with the PDF password.
     */
    public static String METADATA_PDFPASSWORD = "pdfPassword";
    public static String ORIGINAL_WORKER_IDENTIFIER = "ORIGINAL_WORKER_IDENTIFIER";
    public static String WORKER_IDENTIFIER = "WORKER_IDENTIFIER";

    private HashMap<String, Object> context = new HashMap<>();
    
    /**
     * Used to fetch the client certificate used for the request if there exists any, otherwise is
     * 'null' returned.
     */
    public static final String CLIENT_CERTIFICATE = "CLIENT_CERTIFICATE";

    /**
     * Used to fetch the client cookies used for the request if there exists any, otherwise is
     * 'null' returned.
     */
    public static final String REQUEST_COOKIES = "REQUEST_COOKIES";
    
    /**
     * Allow all clients access to DSS via setting this Worker property to TRUE 
     */
    public static final String ALLOW_ANY = "ALLOW_ANY";
    
    /**
     * Used to fetch the remote IP address used by the client if there exists any, otherwise is
     * 'null' returned.
     */
    public static final String REMOTE_IP = "REMOTE_IP";
    
    /**
     * Constant for QoS priority level.
     */
    public static final String QOS_PRIORITY = "QOS_PRIORITY";
    
    public static final String QOS_PRIORITY_WORKER_ID_LIST = "QOS_PRIORITY_WORKER_ID_LIST";

    /**
     * Used to fetch the forwarded IP address header if it exists, otherwise 'null' is returned.
     */
    public static final String X_FORWARDED_FOR = "X-Forwarded-For";
    
    /**
     * Custom HTTP header that will be logged and that for instance could be
     * used to differentiate between different types of requests or requests
     * from different sources.
     */
    public static final String X_SIGNSERVER_CUSTOM_1 = "X-SignServer-Custom-1";
    
    /**
     * All requests called from a CLI interface should set this setting to Boolean true.
     */
    public static final String CALLED_FROM_CLI = "CALLED_FROM_CLI";

    /**
     * The transaction ID.
     * This value is set by the WorkerSessionBean but could be read by
     * different workers in order for them to include it in logs to
     * identify the current transaction.
     * This value should only be set by the WorkerSessionBean.
     */
    public static final String TRANSACTION_ID = "TRANSACTION_ID";
    
    /**
     * The worker ID (Integer).
     */
    public static final String WORKER_ID = "WORKER_ID";
    public static final String LOGMAP = "LOGMAP";
    
    /**
     * True if the worker has processed the request and is able to return
     * the requested result.
     * The Worker Session bean can now go on and charge the client for the
     * request.
     */
    public static final String WORKER_FULFILLED_REQUEST = "WORKER_GRANTED_REQUEST";
    
    /**
     * Holds one of client credentials provided such as client certificate or
     * username/password.
     * Note: Priority is given to client certificate so this property will
     * only contain that even if both were supplied by the client.
     * Authorizer implementations are instead recommended to use the 
     * <i>CLIENT_CREDENTIAL_CERTIFICATE</i> and
     * <i>CLIENT_CREDENTIAL_PASSWORD</i> to be able to read both types of
     * values.
     */
    public static final String CLIENT_CREDENTIAL = "CLIENT_CREDENTIAL";
    
    /**
     * Holds the client certificate, if provided.
     */
    public static final String CLIENT_CREDENTIAL_CERTIFICATE = "CLIENT_CREDENTIAL_CERTIFICATE";
    
    /**
     * Holds the username/password, if provided.
     */
    public static final String CLIENT_CREDENTIAL_PASSWORD = "CLIENT_CREDENTIAL_PASSWORD";

    /**
     * Bearer JWT token in RequestContext.
     */
    public static final String CLIENT_CREDENTIAL_BEARER = "CLIENT_CREDENTIAL_BEARER";
    
    /**
     * An identifier in RequestContext for JSON Web Token (JWT) Map<String, String>.
     */
    public static final String JWT_MAP = "JWT_MAP";

    /**
     * A prefix for a key of JWT claim.
     * @see #JWT_MAP
     */
    public static final String JWT_KEY_PREFIX = "JWT.";

    /**
     * Filename of file uploaded by client to the process servlet.
     */
    public static final String FILENAME = "FILENAME";
    
    /**
     * Filename to set when returning the signed file. Can be changed by the 
     * workers to suggest an other filename.
     */
    public static String RESPONSE_FILENAME = "RESPONSE_FILENAME";
    
    /**
     * A dispatcher such as the TSADispatcherServlet can set this value to
     * Boolean.TRUE to indicate that authorization has been checked. The
     * workers can be configured to use an IAuthorizer that only
     * accepts requests with this value set. This value has no meaning if
     * an other type of Authorizer is used.
     */
    public static final String DISPATCHER_AUTHORIZED_CLIENT =
            "DISPATCHER_AUTHORIZED_CLIENT";

    /**
     * SignServerJPA EntityManager injected by WorkerSessionBean.
     *
     * The purpose is to always inject an EntityManager instance in the right
     * transaction context to serve for decoupled classes such as Archiver and
     * Accounter. EntityManager references passed through the init() method and
     * stored in such decoupled classes are not reliable from the transactional
     * point of view.
     */
    public static final String EM = "EM";
    
    
    private transient IServices services;
    
    /**
     * Default constructor creating an empty context.
     */
    public RequestContext() {
    }

    /**
     * Help constructor setting the client certificate and Remote IP.
     * 
     * @param clientCertificate Client certificate
     * @param remoteIP Remote IP address of the request
     */
    public RequestContext(Certificate clientCertificate, String remoteIP) {
        context.put(CLIENT_CERTIFICATE, clientCertificate);
        context.put(REMOTE_IP, remoteIP);
    }

    /**
     * Help constructor used for calls from the RMI cli.
     * 
     * @param calledFromCli True if called from the RMI CLI
     */
    public RequestContext(boolean calledFromCli) {
        context.put(CALLED_FROM_CLI, calledFromCli);
    }

    /**
     * Retrieves specified field from the context, this could be a custom value or
     * one of the specified constants.
     * 
     * @param field Field to get value of
     * @return The value of the field
     */
    public Object get(String field) {
        return context.get(field);
    }

    /**
     * Sets specified field from the context, this could be a custom value or
     * one of the specified constants.
     * 
     * @param field Field to set value of
     * @param data The value to set
     */
    public void put(String field, Object data) {
        context.put(field, data);
    }

    /**
     * Removes specified field from the context, this could be a custom value or
     * one of the specified constants.
     * 
     * @param field The field to remove
     */
    public void remove(String field) {
        context.remove(field);
    }

    public boolean isCalledFromCLI() {
        boolean retval = false;

        if (context.get(CALLED_FROM_CLI) != null) {
            retval = (Boolean) context.get(CALLED_FROM_CLI);
        }

        return retval;
    }

    public Map<String, Object> asUnmodifiableMap() {
        return Collections.unmodifiableMap(context);
    }
    
    /**
     * @return The current EntityManager if available
     */
    public EntityManager getEntityManager() {
        final Object o = context.get(EM);
        if (o instanceof EntityManager) {
            return (EntityManager) o;
        } else {
            return null;
        }
    }

    /**
     * A worker implementation should call this method to indicate if it was 
     * able to successfully fulfill the request.
     * Setting True means that the configured Accounter can go on and charge 
     * the client for the request.
     * @param b True if the request was fulfilled
     */
    public void setRequestFulfilledByWorker(boolean b) {
        context.put(RequestContext.WORKER_FULFILLED_REQUEST, b);
    }

    /**
     * @return True if the request was marked as fulfilled by the worker
     */
    public boolean isRequestFulfilledByWorker() {
        return Boolean.TRUE.equals(context.get(RequestContext.WORKER_FULFILLED_REQUEST));
    }

    public IServices getServices() {
        return services;
    }
    
    public void setServices(IServices services) {
        this.services = services;
    }
    
    /**
     * Make a copy of the request context with a deep-copied log map to avoid
     * passing on a reference for dispatcher workers.
     * 
     * @return A new request context 
     */
    public RequestContext copyWithNewLogMap() {
        final RequestContext newContext = new RequestContext();
        
        newContext.services = services;
        newContext.context = new HashMap<>();
        
        for (final String key : context.keySet()) {
            final Object value = context.get(key);
            if (LOGMAP.equals(key)) {
                /* take a deep-copy of the log map, the map contains strings,
                   so cloning each entry is enough */
                final HashMap<String, String> logMap =
                        (HashMap<String, String>) value;
                newContext.context.put(LOGMAP, logMap.clone());
            } else {
                newContext.context.put(key, value);
            }
        }
        
        return newContext;
    }
}
