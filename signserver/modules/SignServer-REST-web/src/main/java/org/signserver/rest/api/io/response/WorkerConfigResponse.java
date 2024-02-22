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
package org.signserver.rest.api.io.response;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * Reprosents a response getting the contiguration of worker.
 *
 * @author Marcus Lundblad
 */
@Schema(
    name = "WorkerConfigResponse",
    description = "POJO that represents a get configuration response."
)
public class WorkerConfigResponse {
    @Schema(
            description = "Worker properties list"

    )
    private Map<String, String> properties;


    public WorkerConfigResponse(final Map<String, String> properties) {
        this.properties = properties;
    }

    public Map<String, String> getProperties() {
        return properties;
    }

    public void setProperties(final Map<String, String> properties) {
        this.properties = properties;
    }
}
