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

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.ArchiveException;
import org.signserver.server.archive.Archiver;
import org.signserver.server.archive.ArchiverInitException;
import org.signserver.server.archive.BaseArchiver;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;

/**
 * Sample archiver archiving requests and responses as files to disk.
 * <p>
 * The archiver has two worker properties:
 * </p>
 * <ul>
 *    <li>
 *        <b>ARCHIVERx.FOLDER</b> = Directory for saving the files to (Required)
 *    </li>
 *    <li>
 *        <b>ARCHIVERx.TYPES</b> = List of archivable types,
 *        ie "REQUEST", "RESPONSE". Empty list means all.
 *        (Optional, default: "")
 *   </li>
 * </ul>
 * @author Markus Kilås
 * @version $Id$
 */
public class FileArchiver extends BaseArchiver implements Archiver {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(FileArchiver.class);

    // Worker properties
    public static final String PROPERTY_FOLDER = "FOLDER";
    public static final String PROPERTY_TYPES = "TYPES";

    // Log fields
    public static final String LOG_ARCHIVED_FILES = "ARCHIVED_FILES";

    // Configuration values
    private String workerName;
    private File folder;
    private Set<String> archiveTypes;

    @Override
    public void init(int listIndex, WorkerConfig config,
            SignServerContext context) throws ArchiverInitException {
        workerName = config.getProperty("NAME");

        // Required property ARCHIVERx.FOLDER
        final String propertyFolder
                = "ARCHIVER" + listIndex + "." + PROPERTY_FOLDER;
        final String folderValue = config.getProperty(propertyFolder);
        if (folderValue == null || folderValue.trim().isEmpty()) {
            addFatalError("Missing required property: " + propertyFolder);
        }
        folder = new File(folderValue);

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
    }

    @Override
    public boolean archive(Archivable archivable, RequestContext requestContext)
            throws ArchiveException {
        try {
            // Only archive if configured to archive all
            // or configured to archive this type
            if (archiveTypes.isEmpty()
                    || archiveTypes.contains(archivable.getType())) {
                final String fileName = workerName  + "-"
                        + archivable.getArchiveId() + "-"
                        + archivable.getType() + ".dat";

                // Log the file name
                LogMap logMap = LogMap.getInstance(requestContext);
                final Object loggable = logMap.get(LOG_ARCHIVED_FILES);
                final String files;
                if (loggable == null) {
                    files = fileName;
                } else {
                    files = loggable.toString() + ", " + fileName;
                }
                logMap.put(LOG_ARCHIVED_FILES,
                            new Loggable() {
                                @Override
                                public String toString() {
                                    return files;
                                }
                            });

                // Do the archiving, ie write the file
                FileUtils.writeByteArrayToFile(new File(folder, fileName),
                        archivable.getContentEncoded());
                
                // Return true indicating that the archiving was performed
                return true;
            } else {
                // We don't archive this type
                return false;
            }
        } catch (IOException ex) {
            throw new ArchiveException("Unable to archive "
                    + archivable.getArchiveId(), ex);
        }
    }
}
