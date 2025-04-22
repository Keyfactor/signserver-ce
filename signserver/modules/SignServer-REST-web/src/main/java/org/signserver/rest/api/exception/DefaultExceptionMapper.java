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

import org.signserver.rest.api.entities.ErrorMessage;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

import static jakarta.ws.rs.core.Response.status;
import org.apache.log4j.Logger;

/**
 * Mapper for raw Exception type as fallback when there is no other mapper.
 *
 * This one does not give any more details to the client as that could be
 * sensitive and should not leave server-side.
 */
@Provider
public class DefaultExceptionMapper implements ExceptionMapper<Exception> {

    private static final Logger LOG = Logger.getLogger(DefaultExceptionMapper.class);

    @Override
    public Response toResponse(Exception e) {
        LOG.error("Unhandled REST exception: " + e.getMessage());
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Unhandled REST exception", e);
        }

        return status(Response.Status.INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/json")
                .entity(new ErrorMessage("The server were unable to process the request. See server-side logs for more details."))
                .build();
    }

}
