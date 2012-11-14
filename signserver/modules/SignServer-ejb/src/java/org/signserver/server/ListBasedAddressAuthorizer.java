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

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.persistence.EntityManager;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.util.XForwardedForUtils;

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
    
    private Set<String> addressesDirect;
    private Set<String> addressesForwarded;
    private boolean isDirectWhitelisting;
    private boolean isForwardedWhitelisting;
    private String whitelistedDirectAddresses;
    private String blacklistedDirectAddresses;
    private String whitelistedForwardedAddresses;
    private String blacklistedForwardedAddresses;

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
            addressesDirect = splitAddresses(whitelistedDirectAddresses);
        } else {
            addressesDirect = splitAddresses(blacklistedDirectAddresses);
        }
        
        if (whitelistedForwardedAddresses != null) {
            addressesForwarded = splitAddresses(whitelistedForwardedAddresses);
        } else {
            addressesForwarded = splitAddresses(blacklistedForwardedAddresses);
        }
    }
    
    private Set<String> splitAddresses(final String addresses) {
        final Set<String> res = new HashSet<String>();
        final String[] addressArr = addresses.split(",");
        
        for (String address : addressArr) {
            address = address.trim();
            if (address.length() > 0) {
                res.add(address);
            }
        }

        return res;
    }

    @Override
    public void isAuthorized(ProcessRequest request,
            RequestContext requestContext) throws IllegalRequestException,
            SignServerException {
        final String remoteAddress = (String) requestContext.get(RequestContext.REMOTE_IP);
        final String forwardedAddress = XForwardedForUtils.getXForwardedForIP(requestContext);
        
        // check direct address
        if ((isDirectWhitelisting && !addressesDirect.contains(remoteAddress)) ||
                (!isDirectWhitelisting && addressesDirect.contains(remoteAddress))) {
            LOG.error("Worker " + workerId + ": "
                    + "Not authorized remote address: " + remoteAddress);
            throw new AuthorizationRequiredException("Access denied");
        }
        
        // check the forwarded address
        if (((isForwardedWhitelisting && (forwardedAddress == null || !addressesForwarded.contains(forwardedAddress))) ||
                (!isForwardedWhitelisting && addressesForwarded.contains(forwardedAddress)))) {
            LOG.error("Worker " + workerId + ": "
                    + "Not authorized forwarded address: " + forwardedAddress);

            throw new AuthorizationRequiredException("Access denied");
        }
        
        logRemoteAddress(remoteAddress, forwardedAddress, requestContext);
    }
    
    public void setFatalErrors() {
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
    
    private void logRemoteAddress(final String remoteAddress, final String forwardedAddress,
            final RequestContext requestContext) {
        Map<String, String> logMap = (Map)
                requestContext.get(RequestContext.LOGMAP);
        if (logMap == null) {
            logMap = new HashMap<String, String>();
            requestContext.put(RequestContext.LOGMAP, logMap);
        }
        logMap.put(IAuthorizer.LOG_REMOTEADDRESS, remoteAddress);
        if (forwardedAddress != null) {
            logMap.put(IAuthorizer.LOG_FORWARDED_ADDRESS, forwardedAddress);
        }
    }
}
