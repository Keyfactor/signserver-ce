/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector;

import java.util.Collection;

import javax.ejb.Local;

import org.signserver.ejbca.peerconnector.task.BackgroundTask;

/**
 * SSB for performing long running background tasks under JEE5.
 * 
 * @version $Id$
 */
@Local
public interface BackgroundTaskSessionLocal extends BackgroundTaskSession {

    /**
     * Register and start execution of a BackgroundTask via an EJB @TimeOut.
     * @return true if the task was successfully scheduled.
     */
    boolean startBackgroundTaskNoAuth(BackgroundTask backgroundTask);

    /** Remove a specific BackgroundTask defined by type and a (per type) unique id. */
    void removeBackgroundTask(String type, int intValue);
    
    /** @return all the registered BackgroundTasks of the requested type. */
    Collection<BackgroundTask> getBackgroundTasksByType(String type);

    /** @return a specific BackgroundTask defined by type and a (per type) unique id. */
    BackgroundTask getBackgroundTask(String type, int id);

}
