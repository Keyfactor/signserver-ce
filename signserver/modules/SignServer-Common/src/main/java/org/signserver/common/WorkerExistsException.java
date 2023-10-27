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
package org.signserver.common;

/**
 * Exception where the given worker ID already exists.
 *
 * @author Nima Saboonchi
 * @version $Id$
 */
public class WorkerExistsException extends IllegalRequestException {

    private String workerIdOrName;

    public WorkerExistsException(String workerIdOrName) {
        super("Worker already exists: " + workerIdOrName);
    }

    public String getWorkerIdOrName() {
        return workerIdOrName;
    }

    public void setWorkerIdOrName(String workerIdOrName) {
        this.workerIdOrName = workerIdOrName;
    }

}
