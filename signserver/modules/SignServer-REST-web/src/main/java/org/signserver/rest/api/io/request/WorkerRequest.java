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

import java.util.Map;

/**
 * @author Nima Saboonchi
 */
@Schema(
        name = "WorkerRequest",
        description = "Represents a worker request."
)
public class WorkerRequest {

    @Schema(
            required = false,
            description = "Worker properties list"

    )
    private Map<String, String> properties;


    public WorkerRequest(Map<String, String> properties) {
        this.properties = properties;
    }

    public WorkerRequest() {
    }

    public Map<String, String> getProperties() {
        return properties;
    }

    public void setProperties(Map<String, String> properties) {
        this.properties = properties;
    }


}
