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
package org.signserver.ejb.worker.impl;

import java.util.List;
import org.signserver.server.IAccounter;
import org.signserver.server.IAuthorizer;
import org.signserver.server.IWorker;
import org.signserver.server.archive.Archiver;
import org.signserver.server.log.IWorkerLogger;

/**
 * Holder for the worker object and its components.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class WorkerWithComponents {

    private final int id;
    private final IWorker worker;
    private final List<String> createErrors;
    private final PreloadedWorkerConfig preloadedConfig;
    private final IWorkerLogger workerLogger;
    private final IAuthorizer authorizer;
    private final IAccounter accounter;
    private final List<Archiver> archivers;

    public WorkerWithComponents(int id, IWorker worker, List<String> createErrors, PreloadedWorkerConfig preloadedConfig, IWorkerLogger workerLogger, IAuthorizer authorizer, IAccounter accounter, List<Archiver> archivers) {
        this.id = id;
        this.worker = worker;
        this.createErrors = createErrors;
        this.preloadedConfig = preloadedConfig;
        this.workerLogger = workerLogger;
        this.authorizer = authorizer;
        this.accounter = accounter;
        this.archivers = archivers;
    }

    public IWorker getWorker() {
        return worker;
    }

    public List<String> getCreateErrors() {
        return createErrors;
    }
    
    public boolean hasCreateErrors() {
        return !createErrors.isEmpty();
    }

    public PreloadedWorkerConfig getPreloadedConfig() {
        return preloadedConfig;
    }

    public IWorkerLogger getWorkerLogger() {
        return workerLogger;
    }

    public IAuthorizer getAuthorizer() {
        return authorizer;
    }

    public IAccounter getAccounter() {
        return accounter;
    }

    public List<Archiver> getArchivers() {
        return archivers;
    }

    public int getId() {
        return id;
    }
    
}
