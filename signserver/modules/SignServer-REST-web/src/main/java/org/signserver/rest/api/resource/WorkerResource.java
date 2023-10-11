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
package org.signserver.rest.api.resource;

import org.apache.commons.fileupload.FileUploadException;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.*;
import org.signserver.common.data.Request;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.rest.api.entities.Metadata;
import org.signserver.rest.api.exception.InternalServerException;
import org.signserver.rest.api.exception.RequestFailedException;
import org.signserver.rest.api.io.request.ProcessRequest;
import org.signserver.rest.api.io.response.ProcessResponse;
import org.signserver.server.CredentialUtils;
import org.signserver.server.data.impl.*;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.nio.charset.StandardCharsets;

import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.parameters.RequestBody;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponseSchema;
import org.signserver.rest.api.entities.ErrorMessage;
import org.signserver.rest.api.entities.DataEncoding;

/**
 * REST API implementation containing operations:
 * GET /workers : Returns a list of available workers
 * POST /workers/{idOrName}/process : Gets data bytes or a file, worker, MetaData and returns signature.
 *
 * @author Nima Saboonchi
 * @version $Id$
 */
@Stateless
@Path("/workers")
public class WorkerResource {
    private static final Logger LOG = Logger.getLogger(WorkerResource.class);

    @EJB
    private ProcessSessionLocal processSession;

    @EJB
    private GlobalConfigurationSessionLocal globalSession;

    @EJB
    private WorkerSessionLocal workerSession;

    private DataFactory dataFactory;

    @PostConstruct
    protected void init() {
        dataFactory = DataUtils.createDataFactory();
    }

    /**
     * Generic REST operation for request signing of a byte array.
     *
     * @param idOrName           Name or ID of worker to send the request to
     * @param httpServletRequest Http Servlet request to extract request context from it
     * @param request            Additional request meta data
     * @return The response data
     * @throws RequestFailedException  In case the request could not be processed typically because some error in the request data.
     * @throws InternalServerException In case the request could not be processed by some error at the server side.
     */
    @POST
    @Path("{idOrName}/process")
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @APIResponse(
        responseCode = "400",
        description = "Bad request from the client",
        content = @Content(
            mediaType = MediaType.APPLICATION_JSON,
            schema = @Schema(implementation = ErrorMessage.class)
        )
    )
    @APIResponse(
        responseCode = "404",
        description = "No such worker",
        content = @Content(
            mediaType = MediaType.APPLICATION_JSON,
            schema = @Schema(implementation = ErrorMessage.class)
        )
    )
    @APIResponse(
        responseCode = "503",
        description = "Crypto Token not available",
        content = @Content(
            mediaType = MediaType.APPLICATION_JSON,
            schema = @Schema(implementation = ErrorMessage.class)
        )
    )
    @APIResponse(
        responseCode = "500",
        description = "The server were unable to process the request. See server-side logs for more details.",
        content = @Content(
            mediaType = MediaType.APPLICATION_JSON,
            schema = @Schema(implementation = ErrorMessage.class)
        )
    )
    @APIResponseSchema(
        value = ProcessResponse.class,
        responseCode = "200",
        responseDescription = "The response data"
    )
    @Operation(
        summary = "Submit data for processing",
        description = "Submit data/document/file for processing such as for "
                + "instance signing and get back the result (i.e. signature)."
    )
    public Response process(
            @Parameter(
                description = "Worker Id or name of the worker",
                example = "ExampleSigner1",
                schema = @Schema(anyOf = {String.class, Integer.class})
            )
            @PathParam("idOrName") final String idOrName,
            @Context final HttpServletRequest httpServletRequest,
            @RequestBody(
                description = "The request"
            ) final ProcessRequest request) throws RequestFailedException, InternalServerException, CryptoTokenOfflineException, IllegalRequestException {
        final List<Metadata> requestMetadata = new ArrayList<>();
        if (request.getMetaData() != null) {
            request.getMetaData().forEach((name, value) -> requestMetadata.add(new Metadata(name, value)));
        }
        if (request.getData() == null) {
            throw new IllegalRequestException("Missing data in request");
        }
        byte[] dataBytes = request.getData().getBytes(StandardCharsets.UTF_8);

        DataEncoding encoding = request.getEncoding();
        if (encoding == DataEncoding.BASE64) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Decoding base64 data");
            }
            if (dataBytes.length > 0) {
                try {
                    dataBytes = Base64.decode(dataBytes);
                } catch (DecoderException ex) {
                    throw new InternalServerException("Incorrect base64 data");
                }
            }
        }
        return process(idOrName, httpServletRequest, requestMetadata, dataBytes);
    }

    /**
     * Generic process method to handle signing operations.
     *
     * @param idOrName           Name or ID of worker to send the request to
     * @param httpServletRequest Http Servlet request to extract request context from it
     * @param requestMetadata    Additional request meta data
     * @param data               Actual data to be signed
     * @return The response data
     * @throws RequestFailedException  In case the request could not be processed typically because some error in the request data.
     * @throws InternalServerException In case the request could not be processed by some error at the server side.
     */
    public Response process(String idOrName, HttpServletRequest httpServletRequest, List<Metadata> requestMetadata,
                            byte[] data) throws RequestFailedException, InternalServerException, CryptoTokenOfflineException, IllegalRequestException {
        final UploadConfig uploadConfig = UploadConfig.create(globalSession);

        final int requestId = ThreadLocalRandom.current().nextInt();

        CloseableReadableData requestData;
        CloseableWritableData responseData;

        try {
            requestData = dataFactory.createReadableData(data, uploadConfig.getMaxUploadSize(), uploadConfig.getRepository());
            responseData = dataFactory.createWritableData(requestData, uploadConfig.getRepository());

        } catch (FileUploadException e) {
            throw new RuntimeException(e);
        }

        final RequestContext requestContext = handleRequestContext(requestMetadata, httpServletRequest);
        WorkerIdentifier workerIdentifier = WorkerIdentifier.createFromIdOrName(idOrName);

        final Request req = new SignatureRequest(requestId, requestData, responseData);


        try {
            // Check if this came in as a high priority request
            Set<Integer> highPriorityWorkers = (Set<Integer>) httpServletRequest.getAttribute(RequestContext.QOS_PRIORITY_WORKER_ID_LIST);
            if (highPriorityWorkers == null) {
                LOG.debug("Not highest priority request");
            } else {
                if (!workerIdentifier.hasId()) {
                    try {
                        workerIdentifier = new WorkerIdentifier(workerSession.getWorkerId(workerIdentifier.getName()), workerIdentifier.getName());
                    } catch (InvalidWorkerIdException ex) {
                        LOG.debug("No such worker: " + ex.getMessage());
                    }
                }

                if (!highPriorityWorkers.contains(workerIdentifier.getId())) {
                    LOG.error("Worker with id " + workerIdentifier.getId() + " not one of the highest priority workers: " + highPriorityWorkers);
                    throw new RequestFailedException("Requests to the high priority endpoint not allowed for this worker");
                }
            }


            AdminInfo adminInfo = new AdminInfo("REST user", null, null);

            final org.signserver.common.data.Response resp = processSession.process(adminInfo, workerIdentifier, req, requestContext);

            if (resp instanceof SignatureResponse) {
                final SignatureResponse signatureResponse = (SignatureResponse) resp;

                if (signatureResponse.getRequestID() != requestId) {
                    LOG.error("Response ID " + signatureResponse.getRequestID() + " not matching request ID " + requestId);
                    throw new InternalServerException("Error in process operation, response id didn't match request id");
                }
                return Response.ok(new ProcessResponse(signatureResponse.getArchiveId(),
                                Base64.toBase64String(signatureResponse.getResponseData().toReadableData().getAsByteArray()),
                                String.valueOf(signatureResponse.getRequestID()),
                                signatureResponse.getSignerCertificate() == null ? null : Base64.toBase64String(signatureResponse.getSignerCertificate().getEncoded()),
                                getResponseMetadata(requestContext)))
                        .header("Content-Type", MediaType.APPLICATION_JSON).build();
            } else {
                LOG.error("Unexpected return type: " + resp.getClass().getName());
                throw new InternalServerException("Unexpected return type");
            }
        } catch (AuthorizationRequiredException | AccessDeniedException e) {
            LOG.info("Request failed: " + e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Request failed: " + e.getMessage(), e);
            }
            throw new RequestFailedException(e.getMessage());
        } catch (IOException e) {
            LOG.debug("Internal IO error", e);
            throw new InternalServerException("Internal IO error: " + e.getMessage());
        } catch (SignServerException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Internal server error", e);
            }
            throw new InternalServerException("Internal server error: " + e.getMessage());
        } catch (CertificateEncodingException e) {
            LOG.error("Certificate encoding error", e);
            throw new InternalServerException("Internal server error");
        }
    }

    private X509Certificate getClientCertificate(HttpServletRequest httpServletRequest) {
        X509Certificate[] certificates = (X509Certificate[]) httpServletRequest.getAttribute("javax.servlet.request.X509Certificate");

        if (certificates != null) {
            return certificates[0];
        }
        return null;
    }

    private RequestContext handleRequestContext(final List<Metadata> requestMetadata, HttpServletRequest httpServletRequest) {
        String requestIP = httpServletRequest.getRemoteAddr();
        X509Certificate clientCertificate = getClientCertificate(httpServletRequest);
        final RequestContext requestContext = new RequestContext(clientCertificate, requestIP);

        // Add credentials to the context
        CredentialUtils.addToRequestContext(requestContext, httpServletRequest, clientCertificate);

        final LogMap logMap = LogMap.getInstance(requestContext);

        final String xForwardedFor = httpServletRequest.getHeader(RequestContext.X_FORWARDED_FOR);

        // Add HTTP specific log entries
        logMap.put(IWorkerLogger.LOG_REQUEST_FULLURL, new Loggable() {
            @Override
            public String toString() {
                return httpServletRequest.getRequestURL().append("?")
                        .append(httpServletRequest.getQueryString()).toString();
            }
        });
        logMap.put(IWorkerLogger.LOG_REQUEST_LENGTH, new Loggable() {
            @Override
            public String toString() {
                return httpServletRequest.getHeader("Content-Length");
            }
        });
        logMap.put(IWorkerLogger.LOG_XFORWARDEDFOR, new Loggable() {
            @Override
            public String toString() {
                return httpServletRequest.getHeader("X-Forwarded-For");
            }
        });

        if (xForwardedFor != null) {
            requestContext.put(RequestContext.X_FORWARDED_FOR, xForwardedFor);
        }

        // Add and log the X-SignServer-Custom-1 header if available
        final String xCustom1 = httpServletRequest.getHeader(RequestContext.X_SIGNSERVER_CUSTOM_1);
        if (xCustom1 != null && !xCustom1.isEmpty()) {
            requestContext.put(RequestContext.X_SIGNSERVER_CUSTOM_1, xCustom1);
        }
        logMap.put(IWorkerLogger.LOG_XCUSTOM1, xCustom1);

        if (requestMetadata == null) {
            requestContext.remove(RequestContext.REQUEST_METADATA);
        } else {
            final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
            for (Metadata rmd : requestMetadata) {
                metadata.put(rmd.getName(), rmd.getValue());
            }

            // Special handling of FILENAME
            final String fileName = metadata.get(RequestContext.FILENAME);
            if (fileName != null) {
                requestContext.put(RequestContext.FILENAME, fileName);
                logMap.put(IWorkerLogger.LOG_FILENAME, new Loggable() {
                    @Override
                    public String toString() {
                        return fileName;
                    }
                });
            }
        }

        final Integer qosPriority = (Integer) httpServletRequest.getAttribute(RequestContext.QOS_PRIORITY);
        if (qosPriority != null) {
            requestContext.put(RequestContext.QOS_PRIORITY, qosPriority);
        }
        return requestContext;
    }

    private Map<String, String> getResponseMetadata(final RequestContext requestContext) {
        // TODO: DSS-x: Implement support for "Response Metadata":
//        final Object o = requestContext.get(RequestContext.RESPONSE_METADATA);
//        if (o instanceof Map) {
//            return (Map<String, String>) o;
//        } else {
            return Collections.emptyMap();
//        }
    }
}
