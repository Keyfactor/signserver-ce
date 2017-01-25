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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.*;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerStatus;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.cryptotokens.NullCryptoToken;
import org.signserver.server.signers.BaseSigner;
import org.signserver.statusrepo.StatusRepositorySessionLocal;
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
    
    private static final ICryptoTokenV4 CRYPTO_TOKEN = new NullCryptoToken(WorkerStatus.STATUS_ACTIVE);

    protected StatusRepositorySessionLocal getStatusRepository(IServices services) {
        return services.get(StatusRepositorySessionLocal.class);
    }
    
    @Override
    public Response processData(Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        
        final ProcessResponse ret;
        final Properties requestProperties, responseProperties;
        
        // Check that the request contains a valid request
        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException(
                "Received request was not of expected type.");
        }
        final SignatureRequest request = (SignatureRequest) signRequest;
        final ReadableData requestData = request.getRequestData();
        final WritableData responseData = request.getResponseData();
        
        if (request instanceof SignatureRequest) {
            requestProperties = new Properties();
            try (InputStream in = requestData.getAsInputStream()) {
                requestProperties.load(in);
            } catch (IOException ex) {
                LOG.error("Error in request: " + requestContext.get(RequestContext.TRANSACTION_ID), ex);
                throw new IllegalRequestException("Error parsing request. " + "See server log for information.");
            }
        } else {
            throw new IllegalRequestException(
                "Received request was not of expected type.");
        }
        
        // Process the request
        responseProperties = process(requestProperties, requestContext);

        try (OutputStream out = responseData.getAsOutputStream()) {
            responseProperties.store(out, null);
        } catch (IOException ex) {
            LOG.error("Error constructing response for request: "
                    + requestContext.get(RequestContext.TRANSACTION_ID),
                    ex);
            throw new SignServerException("Error constructing response."
                    + "See server log for information.");
        }
        
        
        // The client can be charged for the request
        requestContext.setRequestFulfilledByWorker(true);

        return new SignatureResponse(request.getRequestID(),
                    responseData, null, null, null, "text/plain");
    }

    private Properties process(final Properties requestData, final RequestContext context) throws IllegalRequestException {
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
                                getStatusRepository(context.getServices()).update(name, requestData.getProperty(key));
                            } else {
                                getStatusRepository(context.getServices()).update(name, requestData.getProperty(key), Long.parseLong(expiration));
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
                StatusEntry entry = getStatusRepository(context.getServices()).getValidEntry(get.name());
                if (entry != null) {
                    result.put(get.name() + "." + UPDATE, String.valueOf(entry.getUpdateTime()));
                    result.put(get.name() + "." + VALUE, entry.getValue() == null ? "" : String.valueOf(entry.getValue()));
                    result.put(get.name() + "." + EXPIRATION, String.valueOf(entry.getExpirationTime()));
                }
            }
            
            return result;
        } catch (NoSuchPropertyException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    protected boolean isNoCertificates() {
        // This worker does not require any signer certificate so don't
        // report any error or information about it.
        return true;
    }

    @Override
    public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
        ICryptoTokenV4 result = super.getCryptoToken(services);

        // Not configuring a crypto token for this worker is not a problem as
        // this worker does not use a crypto token. Instead a dummy instance
        // is returned.
        if (result == null) {
            result = CRYPTO_TOKEN;
        }

        return result;
    }

}
