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
 * Exception where the given worker ID or worker name could not be found.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class NoSuchWorkerException extends IllegalRequestException {

    private String workerIdOrName;
    
    public NoSuchWorkerException(String workerIdOrName) {
        super("No such worker: " + workerIdOrName);
    }

    public String getWorkerIdOrName() {
        return workerIdOrName;
    }

    public void setWorkerIdOrName(String workerIdOrName) {
        this.workerIdOrName = workerIdOrName;
    }
    
}
