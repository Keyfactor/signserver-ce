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

import java.util.List;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * Represents a listing of available workers.
 * 
 * @author Marcus Lundblad
 */
@Schema(
    name = "ListWorkersResponse",
    description = "POJO representing a response listing the workers"
)
public class ListWorkersResponse {
    @Schema(
        name = "workers",
        description = "Workers list. Array with worker ID/name pairs. Empty when no workers available"
)
    private List<Worker> workers;
    
    public ListWorkersResponse(final List<Worker> workers) {
        this.workers = workers;
    }

    public List<Worker> getWorkers() {
        return workers;
    }
    
    public static class Worker {
        private int id;
        private String name;

        public Worker(final int id, final String name) {
            this.id = id;
            this.name = name;
        }

        public int getId() {
            return id;
        }

        public String getName() {
            return name;
        }
    }
}
