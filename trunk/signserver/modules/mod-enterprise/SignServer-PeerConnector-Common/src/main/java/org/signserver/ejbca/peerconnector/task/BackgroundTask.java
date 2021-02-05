/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector.task;

import java.io.Serializable;

/**
 * Interface for long running background tasks.
 * 
 * @version $Id$
 */
public interface BackgroundTask extends Serializable {

    /** Executed when the task is started through an EJB @TimeOut */
    void run();

    /** @return a String that identifies this type of task */
    String getType();

    /** @return an identifier that is unique per type of task */
    int getId();

    /** Invoked when the task is requested to cancel. Task will stop as soon as possible. */
    void cancel();
    
    /** @return the epoch time of creation in milliseconds. */
    long getTimeCreated();

    /** @return true if the task has signaled that it is finished. */
    boolean isDone();

    /** @return a failure message if the task is done and unsuccessful, null otherwise */
    String getFailureMessage();

    /** @return true if the task has been requested to cancel its operation. */
    boolean isCancelled();
    
    /**
     * @return a verbose status message describing the current state
     */
    String getStatusMessage();

}
