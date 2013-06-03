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
package org.signserver.server;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.AccessDeniedException;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.util.XForwardedForUtils;
import org.signserver.server.log.LogMap;

/**
 * Authorizer only accepting requests from certain IP addresses.
 *
 * Properties:
 * ALLOW_FROM = Comma separated list of IP addresses to allow requests from.
 * By default all other addresses are denied access.
 *
 * If a worker is invoked directly using an EJB call and no REMOTE_IP is
 * specified in the RequestContext the IP-address is set to the String "null".
 * In that case, to allow requests using EJB calls, null can be added to the
 * list of allowed addresses.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class RemoteAddressAuthorizer implements IAuthorizer {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            RemoteAddressAuthorizer.class);

    private static final String PROPERTY_ALLOW_FROM = "ALLOW_FROM";

    private Set<InetAddress> allowFromAddresses;
    private boolean allowEJB;
    private List<String> fatalErrors;
    
    private int workerId;

    /**
     * Init this authorizer and loading the list of allowed addresses.
     *
     * @param workerId
     * @param config
     * @param em
     * @throws SignServerException
     */
    @Override
    public void init(final int workerId, final WorkerConfig config,
            final EntityManager em)
            throws SignServerException {
        this.workerId = workerId;

        final String allowFromProperty = config.getProperty(PROPERTY_ALLOW_FROM);
       
        setAllowFromProperty(allowFromProperty);
    }

    // allow the test (same package) to set the allow list manually
    void setAllowFromProperty(final String allowFromProperty) {
        allowFromAddresses = new HashSet<InetAddress>();
        fatalErrors = new LinkedList<String>();

        if (allowFromProperty != null) {
            final String[] allowFromStrings = allowFromProperty.split(",");
            
            for (String allowFromString : allowFromStrings) {
                allowFromString = allowFromString.trim();
                if (allowFromString.length() > 0) {
                    if ("null".equals(allowFromString)) {
                        allowEJB = true;
                    } else {
                        try {
                            allowFromAddresses.add(InetAddress.getByName(allowFromString));
                        } catch (UnknownHostException e) {
                            fatalErrors.add(PROPERTY_ALLOW_FROM + ", illegal address: " + allowFromString);
                        }
                    }
                }
            }
        }
    }
    
    /**
     * Throws AuthorizationRequiredException unless the requestor's IP address
     * is allowed.
     *
     * @param request
     * @param requestContext
     * @throws SignServerException
     * @throws IllegalRequestException
     */
    @Override
    public void isAuthorized(final ProcessRequest request,
            final RequestContext requestContext)
            throws AccessDeniedException, SignServerException, IllegalRequestException {

        final String remote = (String) requestContext.get(RequestContext.REMOTE_IP);

        if (!fatalErrors.isEmpty()) {
            throw new SignServerException("Misconfigured");
        }
        
        if (!isAddressAuthorized(remote)) {
            LOG.error("Worker " + workerId + ": "
                    + "Not authorized remote address: " + remote);
            throw new AccessDeniedException("Remote address not authorized");
        }
        
        LogMap.getInstance(requestContext).put(IAuthorizer.LOG_REMOTEADDRESS, remote);
    }

    // allow test (same package) to run the authorization functionallity directly
    boolean isAddressAuthorized(final String address) throws IllegalRequestException {
        InetAddress remoteAddress;
        try {
            remoteAddress = InetAddress.getByName(address);
        } catch (UnknownHostException e) {
            throw new IllegalRequestException("Illegal remote address: " + address);
        }

        if ((address == null && !allowEJB) || (address != null && !allowFromAddresses.contains(remoteAddress))) {
            return false;
        } else {
            return true;
        }
    }
    
    @Override
    public List<String> getFatalErrors() {
        return fatalErrors;
    }
}
