package org.signserver.rest.api.exception;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import org.signserver.common.ReadOnlyWorkerException;
import org.signserver.rest.api.entities.ErrorMessage;

import static jakarta.ws.rs.core.Response.status;

@Provider
public class ReadOnlyWorkerExceptionMapper implements ExceptionMapper<ReadOnlyWorkerException> {

    @Override
    public Response toResponse(ReadOnlyWorkerException e) {
        return status(Response.Status.METHOD_NOT_ALLOWED)
                .header("Content-Type", "application/json")
                .entity(new ErrorMessage(e.getMessage()))
                .build();
    }
}
