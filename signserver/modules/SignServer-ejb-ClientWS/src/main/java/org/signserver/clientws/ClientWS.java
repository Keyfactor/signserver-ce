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
package org.signserver.clientws;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.servlet.http.HttpServletRequest;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SODRequest;
import org.signserver.common.data.SODResponse;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.server.CredentialUtils;
import org.signserver.server.data.impl.TemporarlyWritableData;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.data.impl.DataFactory;
import org.signserver.server.data.impl.DataUtils;
import org.signserver.server.data.impl.UploadConfig;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;

/**
 * Client web services implementation containing operations for requesting 
 * signing etc.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@WebService(serviceName = "ClientWSService")
@Stateless()
public class ClientWS {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ClientWS.class);
    
    private static final String HTTP_AUTH_BASIC_AUTHORIZATION = "Authorization";
    
    @Resource
    private WebServiceContext wsContext;
    
    @EJB
    private ProcessSessionLocal processSession;
    
    @EJB
    private GlobalConfigurationSessionLocal globalSession;

    private DataFactory dataFactory;
    
    @PostConstruct
    public void init() {
        dataFactory = DataUtils.createDataFactory();
    }
    
    private ProcessSessionLocal getProcessSession() {
        return processSession;
    }

    private final Random random = new Random();
    
    /**
     * Generic operation for request signing of a byte array.
     *
     * @param workerIdOrName Name or ID of worker to send the request to
     * @param requestMetadata Additional request meta data
     * @param data The byte[] array with data in some format understood by the 
     * worker
     * @return The response data
     * @throws RequestFailedException In case the request could not be processed typically because some error in the request data.
     * @throws InternalServerException In case the request could not be processed by some error at the server side.
     */
    @WebMethod(operationName="processData")
    public DataResponse processData(
            @WebParam(name = "worker") final String workerIdOrName, 
            @WebParam(name = "metadata") List<Metadata> requestMetadata, 
            @WebParam(name = "data") byte[] data) throws RequestFailedException, InternalServerException {
        final DataResponse result;
        
        final UploadConfig uploadConfig = UploadConfig.create(globalSession);
        try (
                CloseableReadableData requestData = dataFactory.createReadableData(data, uploadConfig.getMaxUploadSize(), uploadConfig.getRepository());
                CloseableWritableData responseData = dataFactory.createWritableData(requestData, uploadConfig.getRepository());
            ) {
            final RequestContext requestContext = handleRequestContext(requestMetadata);
            final int requestId = random.nextInt();
            
            // Upload handling (Note: UploadUtil.cleanUp() in finally clause)
            
            final Request req = new SignatureRequest(requestId, requestData, responseData);

            final Response resp = getProcessSession().process(new AdminInfo("CLI user", null, null), WorkerIdentifier.createFromIdOrName(workerIdOrName), req, requestContext);
            
            if (resp instanceof SignatureResponse) {
                final SignatureResponse signResponse = (SignatureResponse) resp;
                if (signResponse.getRequestID() != requestId) {
                    LOG.error("Response ID " + signResponse.getRequestID() + " not matching request ID " + requestId);
                    throw new InternalServerException("Error in process operation, response id didn't match request id");
                }
                result = new DataResponse(requestId, signResponse.getResponseData().toReadableData().getAsByteArray(), signResponse.getArchiveId(), signResponse.getSignerCertificate() == null ? null : signResponse.getSignerCertificate().getEncoded(), getResponseMetadata(requestContext));
            } else {
                LOG.error("Unexpected return type: " + resp.getClass().getName());
                throw new InternalServerException("Unexpected return type");
            }
        } catch (CertificateEncodingException ex) {
            LOG.error("Signer certificate could not be encoded", ex);
            throw new InternalServerException("Signer certificate could not be encoded");
        } catch (IllegalRequestException ex) {
            LOG.info("Request failed: " + ex.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.info("Request failed: " + ex.getMessage(), ex);
            }
            throw new RequestFailedException(ex.getMessage());
        } catch (CryptoTokenOfflineException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Service unvailable", ex);
            }
            throw new InternalServerException("Service unavailable: " + ex.getMessage());
        } catch (AuthorizationRequiredException | AccessDeniedException ex) {
            LOG.info("Request failed: " + ex.getMessage());
            throw new RequestFailedException(ex.getMessage());
        } catch (SignServerException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Internal server error", ex);
            }
            throw new InternalServerException("Internal server error: " + ex.getMessage());
        } catch (FileUploadBase.SizeLimitExceededException ex) {
            LOG.error("Maximum content length exceeded: " + ex.getLocalizedMessage());
            throw new RequestFailedException("Maximum content length exceeded");
        } catch (FileUploadException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Upload failed", ex);
            }
            throw new RequestFailedException("Upload failed: " + ex.getLocalizedMessage());
        } catch (IOException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Internal IO error", ex);
            }
            throw new InternalServerException("Internal IO error: " + ex.getMessage());
        }
        return result;
    }
    
    /**
     * Operation for requesting signing and production of an MRTD SOd based on 
     * the supplied data groups / data group hashes.
     * @param workerIdOrName Name or ID of worker to send the request to
     * @param requestMetadata Additional request meta data
     * @param data A SODRequest containing the datagroups/datagroups hashes
     * @return The response data
     * @throws RequestFailedException In case the request could not be processed typically because some error in the request data.
     * @throws InternalServerException In case the request could not be processed by some error at the server side.
     */
    @WebMethod(operationName = "processSOD")
    public org.signserver.clientws.SODResponse processSOD(
            @WebParam(name = "worker") final String workerIdOrName, 
            @WebParam(name = "metadata") final List<Metadata> requestMetadata,
            @WebParam(name = "sodData") final org.signserver.clientws.SODRequest data) throws RequestFailedException, InternalServerException {
        final org.signserver.clientws.SODResponse result;
        try (CloseableWritableData responseData = new TemporarlyWritableData(false, new UploadConfig().getRepository())) {
            final RequestContext requestContext = handleRequestContext(requestMetadata);
            final int requestId = random.nextInt();
        
            // Collect all [dataGroup1, dataGroup2, ..., dataGroupN]
            final List<DataGroup> dataGroups = data.getDataGroups();
            final HashMap<Integer,byte[]> dataGroupsMap = new HashMap<>();
            for (DataGroup dataGroup : dataGroups) {
                final int dataGroupId = dataGroup.getId();
                if ((dataGroupId > -1) && (dataGroupId < 17)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Adding data group " + dataGroupId);
                            if (LOG.isTraceEnabled()) {
                                LOG.trace("with value " + dataGroup.getValue());
                            }
                        }
                        dataGroupsMap.put(dataGroup.getId(), dataGroup.getValue());
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Ignoring data group " + dataGroupId);
                    }
                }
            }
            if (data.getDataGroups().isEmpty()) {
                throw new RequestFailedException("Missing dataGroup fields in request");
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Received number of dataGroups: " + dataGroups.size());
            }
            
            // LDS versioning
            String ldsVersion = data.getLdsVersion();
            String unicodeVersion = data.getUnicodeVersion();
            if (ldsVersion != null && ldsVersion.trim().isEmpty()) {
                ldsVersion = null;
            }
            if (unicodeVersion != null && unicodeVersion.trim().isEmpty()) {
                unicodeVersion = null;
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Requested versions: LDS=" + ldsVersion
                        + ", Unicode=" + unicodeVersion);
            }

            // Use special SOD sign request type
            final SODRequest req = new SODRequest(requestId, dataGroupsMap, ldsVersion, unicodeVersion, responseData);
            final Response resp = getProcessSession().process(new AdminInfo("CLI user", null, null), WorkerIdentifier.createFromIdOrName(workerIdOrName), req, requestContext);
            
            if (resp instanceof SODResponse) {
                SODResponse signResponse = (SODResponse) resp; 
                if (signResponse.getRequestID() != requestId) {
                    LOG.error("Response ID " + signResponse.getRequestID() + " not matching request ID " + requestId);
                    throw new SignServerException("Error in process operation, response id didn't match request id");
                }

                result = new org.signserver.clientws.SODResponse(requestId, responseData.toReadableData().getAsByteArray(), signResponse.getArchiveId(), signResponse.getSignerCertificate() == null ? null : signResponse.getSignerCertificate().getEncoded(), getResponseMetadata(requestContext));
            } else {
                LOG.error("Unexpected return type: " + resp.getClass().getName());
                throw new SignServerException("Unexpected return type");
            }
        } catch (CertificateEncodingException ex) {
            LOG.error("Certificate encoding error", ex);
            throw new InternalServerException("Internal server error");
        } catch (NoSuchWorkerException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Worker Not Found: " + ex.getWorkerIdOrName());
            }
            throw new RequestFailedException("Worker Not Found");
        } catch (CryptoTokenOfflineException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Service unvailable", ex);
            }
            throw new InternalServerException("Service unavailable: " + ex.getMessage());
        } catch (IllegalRequestException | AuthorizationRequiredException | AccessDeniedException ex) {
            LOG.info("Request failed: " + ex.getMessage());
            throw new RequestFailedException(ex.getMessage());
        } catch (SignServerException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Internal server error", ex);
            }
            throw new InternalServerException("Internal server error: " + ex.getMessage());
        } catch (IOException ex) { 
            if (LOG.isDebugEnabled()) {
                LOG.debug("Internal IO error", ex);
            }
            throw new InternalServerException("Internal IO error: " + ex.getMessage());
        }
        return result;
    }
    
    
    private String getRequestIP() {
        MessageContext msgContext = wsContext.getMessageContext();
        HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);

        return request.getRemoteAddr();
    }
    
    private X509Certificate getClientCertificate() {
        MessageContext msgContext = wsContext.getMessageContext();
        HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
        X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

        if (certificates != null) {
            return certificates[0];
        }
        return null;
    }

    private RequestContext handleRequestContext(final List<Metadata> requestMetadata) {
        final HttpServletRequest servletRequest =
                (HttpServletRequest) wsContext.getMessageContext().get(MessageContext.SERVLET_REQUEST);
        String requestIP = getRequestIP();
        X509Certificate clientCertificate = getClientCertificate();
        final RequestContext requestContext = new RequestContext(clientCertificate, requestIP);

        // Add credentials to the context
        CredentialUtils.addToRequestContext(requestContext, servletRequest, clientCertificate);

        final LogMap logMap = LogMap.getInstance(requestContext);

        final String xForwardedFor = servletRequest.getHeader(RequestContext.X_FORWARDED_FOR);

        // Add HTTP specific log entries
        logMap.put(IWorkerLogger.LOG_REQUEST_FULLURL, new Loggable() {
            @Override
            public String toString() {
                return servletRequest.getRequestURL().append("?")
                        .append(servletRequest.getQueryString()).toString();
            }
        });
                
        logMap.put(IWorkerLogger.LOG_REQUEST_LENGTH, new Loggable() {
            @Override
            public String toString() {
                return servletRequest.getHeader("Content-Length");
            }
        });

        logMap.put(IWorkerLogger.LOG_XFORWARDEDFOR, new Loggable() {
            @Override
            public String toString() {
                return servletRequest.getHeader("X-Forwarded-For");
            }
        });

        if (xForwardedFor != null) {
            requestContext.put(RequestContext.X_FORWARDED_FOR, xForwardedFor);
        }
        
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
        
        return requestContext;
    }

    private List<Metadata> getResponseMetadata(final RequestContext requestContext) {
        final LinkedList<Metadata> result = new LinkedList<>();
        // TODO: DSS-x: Implement support for "Response Metadata":
        //Object o = requestContext.get(RequestContext.REQUEST_METADATA);
        //if (o instanceof Map) {
        //    Map<String, String> requestMetadata = (Map<String, String>) o;
        //    for (Map.Entry<String, String> entry : requestMetadata.entrySet()) {
        //        result.add(new Metadata(entry.getKey(), entry.getValue()));
        //    }
        //}
        return result;
    }
}
