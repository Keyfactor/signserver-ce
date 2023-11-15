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

import javax.ws.rs.core.Response;
import static javax.ws.rs.core.Response.status;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.rest.api.entities.ErrorMessage;

/**
 * Exception indicating that the user is not authorized to perform the
 * operation.
 *
 * @author Hanna Hansson
 * @version $Id$
 */
@Provider
public class AdminNotAuthorizedExceptionMapper implements ExceptionMapper<AdminNotAuthorizedException> {

    @Override
    public Response toResponse(AdminNotAuthorizedException e) {
        return status(Response.Status.UNAUTHORIZED)
                .header("Content-Type", "application/json")
                .entity(new ErrorMessage(e.getMessage()))
                .build();
    }
}
