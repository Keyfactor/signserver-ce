package org.signserver.server.genericws;

import org.signserver.common.WorkerStatus;

/**
 * Interface can be used to check the status of a Web Services deployed
 * with the Generic WS API. It should check if the Web Service is healthy.
 * 
 * @author Philip Vendil 8 okt 2008
 * @version $Id$
 */
public interface IStatusChecker {

    /**
     * 
     * @return method that should return an implementation
     * of a WorkerStatus object containing the current status
     * of the object.
     */
    WorkerStatus getStatus();
}
