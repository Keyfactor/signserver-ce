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

import java.util.Iterator;
import java.util.List;
import org.apache.log4j.Logger;

/**
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class RoundRobinUtils {

    private static final Logger LOG = Logger.getLogger(RoundRobinUtils.class);

    private static RoundRobinUtils instance;
    private static List<String> participantHosts;
    private static Iterator<String> iterator;

    private RoundRobinUtils(List<String> hosts) {
        participantHosts = hosts;
        iterator = participantHosts.iterator();
    }

    public static RoundRobinUtils getInstance(List<String> hosts) {
        if (instance == null) {
            instance = new RoundRobinUtils(hosts);
        }
        return instance;
    }

    public String getHostForFirstAttempt() {
        // TODO: get randomized host for first attempt 
        // if we get to the end, start again
        if (!iterator.hasNext()) {
            iterator = participantHosts.iterator();
        }
        String host = iterator.next();
        LOG.error("Next host retrieved for signing: " + host);
        return host;
    }

}
