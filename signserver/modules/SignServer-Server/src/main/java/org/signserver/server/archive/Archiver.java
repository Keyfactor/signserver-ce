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
package org.signserver.server.archive;

import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;

/**
 * Archives ArchivableS.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public interface Archiver {

    /**
     * Initializes this Archiver by providing the configuration etc.
     * 
     * This method is called at least once before the Archiver is first used. 
     * In addition it can also be called as part of a reload of a worker.
     * 
     * Note: The EntityManager available in the SignServerContext should only be
     * used during initialization. For archiving, only the EntityManager 
     * available in the request context should be used.
     * 
     * @param listIndex The number this Archiver has in the list of ArchiverS in 
     * the ARCHIVERS property. Can be used to get properties for this particular 
     * Archiver.
     * @param config The worker configuration containing the workers all 
     * configuration properties.
     * @param context The context can contain dependencies such as an EntityManager (to only use during initialization).
     * @throws ArchiverInitException The Archiver can through this Exception if
     * the configuration was wrong or if it failed to initialize for some reason.
     */
    void init(int listIndex, WorkerConfig config, SignServerContext context) throws ArchiverInitException;

    /**
     * Request archival of the Archivable.
     * 
     * The Archiver can indicate that it has chosen not archive the Archivable for 
     * any reason by returning false. The idea is that all ArchiverS might not 
     * be configured to handle all types of Archivables. On the other hand by 
     * returning true the Archiver indicates that it has archived the item 
     * successfully. 
     * 
     * If archiving fails the Archiver can through an ArchiveException that 
     * might cause the complete SignServer request to fail.
     * 
     * For database access, an EntityManager is available in the RequestContext.
     * 
     * @param archivable The item to archive.
     * @param requestContext The current request details and runtime dependencies such as an EntityManager.
     * @return True if the item was archived.
     * @throws ArchiveException In case the item could not be archived.
     */
    boolean archive(Archivable archivable, RequestContext requestContext) throws ArchiveException;
}
