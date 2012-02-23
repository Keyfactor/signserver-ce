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
package org.signserver.module.statusproperties;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.EnumSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import javax.ejb.EJB;
import javax.naming.NamingException;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.GenericServletRequest;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.server.signers.BaseSigner;
import org.signserver.statusrepo.IStatusRepositorySession;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.common.StatusEntry;
import org.signserver.statusrepo.common.StatusName;

/**
 * Worker for setting and querying status properties.
 *
 * Worker properties:
 *  (none)
 * 
 * The worker accepts a GenericPropertiesRequest or GenericSignRequest with 
 * properties in the request data.
 * 
 * Request properties:
 * <i>GET</i> - Comma-separated list of status properties to query
 * <i>x.VALUE</i> - Where x is a status property: Sets the value of the property
 * <i>x.EXPIRATION</i> - Where x is a status property: Sets the expiration time 
 * for x (x.VALUE must also be specified)
 * If no property is specified all status properties are returned
 * 
 * @author Markus Kilås
 * @version $Id$
 * @see IStatusRepositorySession
 * @see GenericPropertiesRequest
 * @see GenericPropertiesResponse
 */
public class StatusPropertiesWorker extends BaseSigner {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(StatusPropertiesWorker.class);
    
    private static final String UPDATE = "UPDATE";
    private static final String VALUE = "VALUE";
    private static final String EXPIRATION = "EXPIRATION";
    
    /** StatusRepositorySession. */
    @EJB
    private IStatusRepositorySession.IRemote statusRepository;
    
    private IStatusRepositorySession.IRemote getStatusRepository() {
        if (statusRepository == null) {
            try {
                statusRepository = ServiceLocator.getInstance().lookupRemote(IStatusRepositorySession.IRemote.class);
            } catch (NamingException ex) {
                throw new RuntimeException("Unable to lookup worker session", ex);
            }
        }
        return statusRepository;
    }
    
    @Override
    public ProcessResponse processData(ProcessRequest request, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        
        final ProcessResponse ret;
        final Properties requestData, responseData;
        
        // Check that the request contains a valid request
        if (request instanceof GenericPropertiesRequest) {
            requestData = ((GenericPropertiesRequest) request).getProperties();
        } else if (request instanceof GenericSignRequest) {
            requestData = new Properties();
            try {
                requestData.load(new ByteArrayInputStream(((GenericSignRequest) request).getRequestData()));
            } catch (IOException ex) {
                LOG.error("Error in request: " + requestContext.get(RequestContext.TRANSACTION_ID), ex);
                throw new IllegalRequestException("Error parsing request. " + "See server log for information.");
            }
        } else {
            throw new IllegalRequestException(
                "Recieved request was not of expected type.");
        }
        
        // Log values
        final Map<String, String> logMap = (Map<String, String>) requestContext.get(RequestContext.LOGMAP);

        // Process the request
        responseData = process(requestData, logMap);

        if (request instanceof GenericSignRequest) {
            final GenericSignRequest signRequest = (GenericServletRequest) request;
            try {
                final ByteArrayOutputStream bout = new ByteArrayOutputStream();
                responseData.store(bout, null);
                if (request instanceof GenericServletRequest) {
                    ret = new GenericServletResponse(signRequest.getRequestID(),
                        bout.toByteArray(), null, null, null, "text/plain");
                } else {
                    ret = new GenericSignResponse(signRequest.getRequestID(),
                        signRequest.getRequestData(), null, null, null);
                }
            } catch (IOException ex) {
                LOG.error("Error constructing response for request: "
                        + requestContext.get(RequestContext.TRANSACTION_ID),
                        ex);
                throw new SignServerException("Error constructing response."
                        + "See server log for information.");
            }
        } else {
            ret = new GenericPropertiesResponse(responseData);
        }

        return ret;
    }

    private Properties process(Properties requestData, Map<String, String> logMap) throws IllegalRequestException {
        try {
            Properties result = new Properties();
            
            final Set<StatusName> gets;
            if (requestData.isEmpty()) { // No request, just print every valid property
                gets = EnumSet.allOf(StatusName.class);
            } else {
                // Add all requested names
                gets = EnumSet.noneOf(StatusName.class);
                String getValue = requestData.getProperty("GET");
                if (getValue != null) {
                    for (String key : getValue.split(",|\\s")) {
                        try {
                            gets.add(StatusName.valueOf(key));
                        } catch (IllegalArgumentException ex) {
                            throw new IllegalRequestException("No such status property: " + key);
                        }
                    }
                }
                
                // Set values
                for (Object k : requestData.keySet()) {
                    String key = (String) k;
                    if (key.endsWith("." + VALUE)) {
                        String name = key.substring(0, key.indexOf("." + VALUE));
                        String expiration = requestData.getProperty(name + "." + EXPIRATION);
                        try {
                            if (expiration == null) {
                                getStatusRepository().update(name, requestData.getProperty(key));
                            } else {
                                getStatusRepository().update(name, requestData.getProperty(key), Long.parseLong(expiration));
                            }
                            gets.add(StatusName.valueOf(name));
                        } catch (NumberFormatException ex) {
                            throw new IllegalRequestException("Illegal expiration value for property: " + name);
                        } catch (NoSuchPropertyException ex) {
                            throw new IllegalRequestException(ex.getMessage());
                        }
                    }
                }
            }
            
            // Get the current values for the valid properties
            for (StatusName get : gets) {
                StatusEntry entry = getStatusRepository().getValidEntry(get.name());
                if (entry != null) {
                    result.put(get.name() + "." + UPDATE, String.valueOf(entry.getUpdateTime()));
                    result.put(get.name() + "." + VALUE, String.valueOf(entry.getValue()));
                    result.put(get.name() + "." + EXPIRATION, String.valueOf(entry.getExpirationTime()));
                }
            }
            
            return result;
        } catch (NoSuchPropertyException ex) {
            throw new RuntimeException(ex);
        }
    }
    
}
