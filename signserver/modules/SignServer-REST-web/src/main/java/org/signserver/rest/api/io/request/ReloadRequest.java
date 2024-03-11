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
package org.signserver.rest.api.io.request;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

import java.util.List;


/**
 * Represents a reload request for REST.
 * @author Nima Saboonchi
 */
@Schema(
        name = "ReloadRequest",
        description = "Represents a reload request."
)
public class ReloadRequest {

    @Schema(
            required = true,
            description = "List of worker IDs to reload."

    )
    private List<Integer> workerIDs;

    public List<Integer> getWorkerIDs() {
        return workerIDs;
    }

    public void setWorkerIDs(List<Integer> workerIDs) {
        this.workerIDs = workerIDs;
    }

    public ReloadRequest() {
    }

}
