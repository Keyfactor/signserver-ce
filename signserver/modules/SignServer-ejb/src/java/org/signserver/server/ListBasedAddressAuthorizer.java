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
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import javax.persistence.EntityManager;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.signserver.common.AccessDeniedException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.util.XForwardedForUtils;
import org.signserver.server.log.LogMap;

/**
 * Authorizer with the ability to accept or deny remote and
 * forwarded addresses based on white and black listing.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */

public class ListBasedAddressAuthorizer implements IAuthorizer {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            ListBasedAddressAuthorizer.class);

    private static final String PROPERTY_WHITELISTED_DIRECT_ADDRESSES = "WHITELISTED_DIRECT_ADDRESSES";
    private static final String PROPERTY_BLACKLISTED_DIRECT_ADDRESSES = "BLACKLISTED_DIRECT_ADDRESSES";
    private static final String PROPERTY_WHITELISTED_FORWARDED_ADDRESSES = "WHITELISTED_FORWARDED_ADDRESSES";
    private static final String PROPERTY_BLACKLISTED_FORWARDED_ADDRESSES = "BLACKLISTED_FORWARDED_ADDRESSES";
    private static final String PROPERTY_MAX_FORWARDED_ADDRESSES = "MAX_FORWARDED_ADDRESSES";
    
    private static final int MAX_FORWARDED_ADDRESSES_DEFAULT = 1;
    
    private Set<InetAddress> addressesDirect;
    private Set<InetAddress> addressesForwarded;
    private boolean isDirectWhitelisting;
    private boolean isForwardedWhitelisting;
    private String whitelistedDirectAddresses;
    private String blacklistedDirectAddresses;
    private String whitelistedForwardedAddresses;
    private String blacklistedForwardedAddresses;
    private int maxForwardedAddresses;
    
    private int workerId;

    private List<String> fatalErrors;
    
    @Override
    public void init(int workerId, WorkerConfig config, EntityManager em)
            throws SignServerException {
        this.workerId = workerId;
        
        whitelistedDirectAddresses = config.getProperty(PROPERTY_WHITELISTED_DIRECT_ADDRESSES);
        blacklistedDirectAddresses = config.getProperty(PROPERTY_BLACKLISTED_DIRECT_ADDRESSES);
        whitelistedForwardedAddresses = config.getProperty(PROPERTY_WHITELISTED_FORWARDED_ADDRESSES);
        blacklistedForwardedAddresses = config.getProperty(PROPERTY_BLACKLISTED_FORWARDED_ADDRESSES);

        setFatalErrors();
        
        if (fatalErrors.size() > 0) {
            throw new SignServerException("Invalid properties specified: " + StringUtils.join(fatalErrors, '\n'));
        }

        isDirectWhitelisting = whitelistedDirectAddresses != null;
        isForwardedWhitelisting = whitelistedForwardedAddresses != null;
        
        if (whitelistedDirectAddresses != null) {
            addressesDirect = splitAddresses(whitelistedDirectAddresses, PROPERTY_WHITELISTED_DIRECT_ADDRESSES);
        } else {
            addressesDirect = splitAddresses(blacklistedDirectAddresses, PROPERTY_BLACKLISTED_DIRECT_ADDRESSES);
        }
        
        if (whitelistedForwardedAddresses != null) {
            addressesForwarded = splitAddresses(whitelistedForwardedAddresses, PROPERTY_WHITELISTED_FORWARDED_ADDRESSES);
        } else {
            addressesForwarded = splitAddresses(blacklistedForwardedAddresses, PROPERTY_BLACKLISTED_FORWARDED_ADDRESSES);
        }
        
        maxForwardedAddresses =
                Integer.parseInt(config.getProperty(PROPERTY_MAX_FORWARDED_ADDRESSES, Integer.toString(MAX_FORWARDED_ADDRESSES_DEFAULT)));
    }
    
    /**
     * Helper method to extract addresses from configuration properties. Will also set fatal errors for malformed addresses.
     * 
     * @param addresses Comma-separeated list of IP addresses (taken from the configuration)
     * @param component Used to prefix a possible error string
     * @return A set of InetAddress objects representing the list
     */
    private Set<InetAddress> splitAddresses(final String addresses, final String component) {
        final Set<InetAddress> res = new HashSet<InetAddress>();
        final String[] addressArr = addresses.split(",");
        
        for (String address : addressArr) {
            address = address.trim();
            if (address.length() > 0) {
                try {
                    res.add(InetAddress.getByName(address));
                } catch (UnknownHostException e) {
                    fatalErrors.add(component + ", illegal address specified: " + address);
                }
            }
        }

        return res;
    }

    @Override
    public void isAuthorized(ProcessRequest request,
            RequestContext requestContext) throws IllegalRequestException,
            AccessDeniedException, SignServerException {
        final String remote = (String) requestContext.get(RequestContext.REMOTE_IP);
        final String[] forwardedAddresses = XForwardedForUtils.getXForwardedForIPs(requestContext, maxForwardedAddresses);
        InetAddress remoteAddress;
        try {
            remoteAddress = InetAddress.getByName(remote);
        } catch (UnknownHostException e) {
            throw new IllegalRequestException("Illegal remote address in request: " + remote);
        }
        
        // check direct address
        if ((isDirectWhitelisting && !addressesDirect.contains(remoteAddress)) ||
                (!isDirectWhitelisting && addressesDirect.contains(remoteAddress))) {
            LOG.error("Worker " + workerId + ": "
                    + "Not authorized remote address: " + remote);
            throw new AccessDeniedException("Remote address not authorized");
        }
        
        
        if (isForwardedWhitelisting) {
            // if there is no forwarded header, of if header is empty
            if (forwardedAddresses == null || forwardedAddresses.length == 0) {
                throw new AccessDeniedException("No forwarded address in request");
            }
            
            boolean isAuthorized = true;
            
            for (final String forwarded : forwardedAddresses) {
                InetAddress forwardedAddress;
                try {
                    forwardedAddress = InetAddress.getByName(forwarded);
                } catch (UnknownHostException e) {
                    throw new IllegalRequestException("Illegal forwarded address in request: " + forwarded);
                }
                
                if (!addressesForwarded.contains(forwardedAddress)) {
                    isAuthorized = false;
                    break;
                    
                }
            }
            
            if (!isAuthorized) {
                LOG.error("Worker " + workerId + ": "
                        + "No authorized forwarded address among inspected addesses");
                throw new AccessDeniedException("Forwarded address not athorized");
            }
        } else {
            if (forwardedAddresses != null && forwardedAddresses.length > 0) {
                for (final String forwarded : forwardedAddresses) {
                    InetAddress forwardedAddress;
                    try {
                        forwardedAddress = InetAddress.getByName(forwarded);
                    } catch (UnknownHostException e) {
                        throw new IllegalRequestException("Illegal forwarded address in request: " + forwarded);
                    }
                    
                    if (addressesForwarded.contains(forwardedAddress)) {
                        LOG.error("Worker " + workerId + ": "
                                + "Found blacklisted address among inspected addresses: " + forwarded);
                        throw new AccessDeniedException("Forwarded address not athorized");
                    }
                }
            }
        }
        
        logRemoteAddress(remote, forwardedAddresses, requestContext);
    }
    
    private void setFatalErrors() {
        fatalErrors = new LinkedList<String>();
        
        // check that one (and only one) each of the direct and forwarded properties at a time is specified
        if (whitelistedDirectAddresses != null && blacklistedDirectAddresses != null) {
            fatalErrors.add("Only one of " + PROPERTY_WHITELISTED_DIRECT_ADDRESSES + " and " +
                    PROPERTY_BLACKLISTED_DIRECT_ADDRESSES + " can be specified.");
        }
        
        if (whitelistedForwardedAddresses != null && blacklistedForwardedAddresses != null) {
            fatalErrors.add("Only one of " + PROPERTY_WHITELISTED_DIRECT_ADDRESSES + " and " +
                    PROPERTY_BLACKLISTED_DIRECT_ADDRESSES + " can be specified.");
        }
        
        if (whitelistedDirectAddresses == null && blacklistedDirectAddresses == null) {
            fatalErrors.add("One of " + PROPERTY_WHITELISTED_DIRECT_ADDRESSES  + " or " +
                    PROPERTY_BLACKLISTED_DIRECT_ADDRESSES + " must be specified.");
        }
        
        if (whitelistedForwardedAddresses == null && blacklistedForwardedAddresses == null) {
            fatalErrors.add("One of " + PROPERTY_WHITELISTED_FORWARDED_ADDRESSES  + " or " +
                    PROPERTY_BLACKLISTED_FORWARDED_ADDRESSES + " must be specified.");
        }
    }
    
    @Override
    public List<String> getFatalErrors() {
        return fatalErrors;
    }
    
    private void logRemoteAddress(final String remoteAddress, final String[] forwardedAddresses,
            final RequestContext requestContext) {
        final LogMap logMap = LogMap.getInstance(requestContext);
        logMap.put(IAuthorizer.LOG_REMOTEADDRESS, remoteAddress);
        logMap.put(IAuthorizer.LOG_FORWARDED_ADDRESS, StringUtils.join(forwardedAddresses, ","));
    }
}
