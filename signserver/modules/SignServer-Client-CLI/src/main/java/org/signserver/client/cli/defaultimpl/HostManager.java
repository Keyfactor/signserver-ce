/** ***********************************************************************
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
 ************************************************************************ */
package org.signserver.client.cli.defaultimpl;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.apache.log4j.Logger;

/**
 * Class containing logic for managing participant hosts under load balancing & fail over.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class HostManager {

    private static final Logger LOG = Logger.getLogger(HostManager.class);
    
    private final List<String> participantHosts;
    private int currentIndex = -1;
    private final boolean useLoadBalancing;
    private final Random random = new Random();
    private boolean firstRequestWithLoadBalancing;
    private int randomIndex = -1;

    public HostManager(List<String> hosts, boolean useLoadBalancing) {
        participantHosts = new ArrayList(hosts);
        this.useLoadBalancing = useLoadBalancing;

        if (useLoadBalancing) { // get randomized host for first attempt if loadbalancing is enabled
            randomIndex = getHostIndexByRandom();
            firstRequestWithLoadBalancing = true;
        }
    }
    
    /**
     * Determines the next host to be used for sending signing request.
     *
     * @returns host.
     */
    synchronized String getNextHostForRequest() {
        if (participantHosts.isEmpty()) {
            return null;
        }

        checkNextHostIndex();
        String host = participantHosts.get(currentIndex);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("hosts size: " + participantHosts.size());
        }       
        if (LOG.isInfoEnabled()) {
            LOG.info("Next host retrieved for signing: " + host);
        }
        return host;
    }

    private void checkNextHostIndex() {
        if (useLoadBalancing) {
            if (firstRequestWithLoadBalancing) {
                currentIndex = randomIndex;
                if (LOG.isDebugEnabled()) {
                    LOG.debug("random index: " + currentIndex);
                }
                firstRequestWithLoadBalancing = false;
            } else {
                updateCurrentIndex();
            }
        } else { // always return first host in the list
            currentIndex = 0;
        }
    }
    
    /**
     * Determines the next host to be used for sending signing request when last request was unsuccessful due to connection failure.
     *
     * @returns host.
     */
    synchronized String getNextHostForRequestWhenFailure() {
        if (participantHosts.isEmpty()) {
            return null;
        }

        updateCurrentIndex();        
        String host = participantHosts.get(currentIndex);

        if (LOG.isDebugEnabled()) {
            LOG.debug("hosts size: " + participantHosts.size());
        }
        if (LOG.isInfoEnabled()) {
            LOG.info("Next host retrieved for signing: " + host);
        }
        return host;
    }
    
    private void updateCurrentIndex() {
        currentIndex = currentIndex + 1;
        // if we get to the end, start again
        if (currentIndex >= participantHosts.size()) {
            currentIndex = 0;
        }
    }

    synchronized int getHostIndexByRandom() {
        return random.nextInt(participantHosts.size());
    }

    /**
     * Removes the specified host from participating in load balancing or fail
     * over if connection failure occurred while serving a request.
     *
     * @param host to be removed.
     */
    synchronized void removeHost(String host) {
        // If condition is imporant here to avoid a scenario where multiple thread try to remove host and only one of them actually remove
        // the host and others just decrease the currentIndex (it may set currentIndex to negative value)
        if (participantHosts.remove(host)) {
            currentIndex = currentIndex - 1;
        }
    }

    synchronized boolean hasHost() {
        return !participantHosts.isEmpty();
    }
}
