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
package org.signserver.healthcheck;

import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;

/**
 * Utility methods related to the Health check functionality.
 * 
 * @version $Id$
 */
public class HealthCheckUtils {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(HealthCheckUtils.class);

    public static List<String> checkMemory(int minfreememory) {
        final LinkedList<String> result = new LinkedList<>();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Checking JVM heap memory.");
        }
        // Memory still not allocated by the JVM + available memory of what is allocated by the JVM
        final long maxAllocation = Runtime.getRuntime().maxMemory();

        // The total amount of memory allocated to the JVM
        final long currentlyAllocation = Runtime.getRuntime().totalMemory();

        // Available memory of what is allocated by the JVM
        final long freeAllocated = Runtime.getRuntime().freeMemory();

        // Memory still not allocated by the JVM + available memory of what is allocated by the JVM
        final long currentFreeMemory = maxAllocation - currentlyAllocation + freeAllocated;
        if (LOG.isDebugEnabled()) {
            LOG.debug((100L * (maxAllocation - currentFreeMemory) / maxAllocation) + "% of the " + (maxAllocation / 1048576L) + " MiB heap is currently used.");
        }

        if (minfreememory >= currentFreeMemory) {
            result.add("Error Virtual Memory is about to run out, currently free memory :" + currentFreeMemory);
        }
        return result;
    }

    public static List<String> checkDB(final EntityManager em, final String checkDBString) {
        final LinkedList<String> result = new LinkedList<>();
        try {
            em.createNativeQuery(checkDBString).getResultList();
        } catch (Exception e) {
            result.add("Error creating connection to SignServer Database.");
            LOG.error("Error creating connection to SignServer Database.", e);
        }
        return result;
    }
}
