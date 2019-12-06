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
package org.signserver.module.sample.components;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.apache.log4j.Logger;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.ArchiveException;
import org.signserver.server.archive.Archiver;
import org.signserver.server.archive.ArchiverInitException;
import org.signserver.server.archive.BaseArchiver;

/**
 * Skeleton sample archiver not doing anything...
 * <p>
 * The archiver has the following worker properties:
 * </p>
 * <ul>
 *    <li><b>ARCHIVERx.TYPES</b> = List of archivable types, 
 *        ie "REQUEST", "RESPONSE". Empty list means all.
 *        (Optional, default: "")</li>
 *    <li><b>ARCHIVERx.PROPERTY...</b> = Description of property...
 *        (Required/Optional, default: ...)</li>
 * </ul>
 * @author ...
 * @version $Id$
 */
public class SkeletonArchiver extends BaseArchiver implements Archiver {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SkeletonArchiver.class);

    // Worker properties
    public static final String PROPERTY_TYPES = "TYPES";
    //...

    // Log fields
    //...

    // Configuration errors
    private boolean configErrors;

    // Configuration values
    private Set<String> archiveTypes;
    //...

    @Override
    public void init(int listIndex, WorkerConfig config, 
            SignServerContext context) throws ArchiverInitException {
        // Read properties
        //...

        // Optional property ARCHIVERx.TYPES
        archiveTypes = new HashSet<>();
        final String propertyTypes
                = "ARCHIVER" + listIndex + "." + PROPERTY_TYPES;
        final String typeValue = config.getProperty(propertyTypes);
        if (typeValue != null && !typeValue.trim().isEmpty()) {
            archiveTypes.addAll(Arrays.asList(typeValue.split("[\\s,]")));
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Archive of types: "
                    + (archiveTypes.isEmpty() ? "all" : archiveTypes));
        }

        // Ok if we got this far
        configErrors = false;
    }

    @Override
    public boolean archive(Archivable archivable, RequestContext requestContext)
            throws ArchiveException {
        if (configErrors) {
            throw new ArchiveException("Archiver is misconfigured");
        }
        // Only archive if configured to archive all
        // or configured to archive this type
        if (archiveTypes.isEmpty()
                || archiveTypes.contains(archivable.getType())) {

            // Log interesting values
            //...

            // Do the archiving
            //...

            // Return true indicating that the archiving was performed
            return true;
        } else {
            // We don't archive this type
            return false;
        }
    }
}
