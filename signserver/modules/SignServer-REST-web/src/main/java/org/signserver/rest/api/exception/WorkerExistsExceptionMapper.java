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
package org.signserver.rest.api.exception;

import org.signserver.common.WorkerExistsException;
import org.signserver.rest.api.entities.ErrorMessage;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

import static jakarta.ws.rs.core.Response.status;

@Provider
public class WorkerExistsExceptionMapper implements ExceptionMapper<WorkerExistsException> {

    @Override
    public Response toResponse(WorkerExistsException e) {
        return status(Response.Status.CONFLICT)
                .header("Content-Type", "application/json")
                .entity(new ErrorMessage(e.getMessage()))
                .build();
    }
}
