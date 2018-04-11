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
public class RoundRobinUtils {

    private static final Logger LOG = Logger.getLogger(RoundRobinUtils.class);

    private static RoundRobinUtils instance;
    private static List<String> participantHosts;
    private int currentIndex = -1;
    private boolean firstHostDeterminedByRandom;
    private final Random random = new Random();

    private RoundRobinUtils(List<String> hosts, boolean firstHostDeterminedByRandom) {
        participantHosts = hosts;
        this.firstHostDeterminedByRandom = firstHostDeterminedByRandom;
    }

    synchronized static RoundRobinUtils getInstance(List<String> hosts, boolean firstHostDeterminedByRandom) {
        if (instance == null) {
            participantHosts = new ArrayList(hosts);
            instance = new RoundRobinUtils(participantHosts, firstHostDeterminedByRandom);
        }
        return instance;
    }

    /**
     * Determines the next host to be used for sending signing request.
     *
     * @returns host.
     */
    synchronized String getNextHostForRequest() {
        checkNextHostIndex();
        String host = participantHosts.get(currentIndex);
        LOG.error("hosts size: " + participantHosts.size());
        LOG.error("Next host retrieved for signing: " + host);
        return host;
    }

    private void checkNextHostIndex() {
        if (firstHostDeterminedByRandom) { // get randomized host for first attempt if loadbalancing is enabled
            currentIndex = getHostIndexByRandom();
            LOG.error("random index: " + currentIndex);
            firstHostDeterminedByRandom = false;
        } else {
            currentIndex = currentIndex + 1;
            // if we get to the end, start again
            if (currentIndex == participantHosts.size()) {
                currentIndex = 0;
            }
        }
    }

    private int getHostIndexByRandom() {
        return random.nextInt(participantHosts.size());
    }

    /**
     * Removes the specified host from participating in load balancing or fail
     * over if connection failure occurred while serving a request.
     *
     * @param host to be removed.
     */
    synchronized void removeHost(String host) {
        participantHosts.remove(host);
        currentIndex = currentIndex - 1;
    }

    static void destroy() {
        if (instance != null) {
            instance = null;
        }
    }
}
