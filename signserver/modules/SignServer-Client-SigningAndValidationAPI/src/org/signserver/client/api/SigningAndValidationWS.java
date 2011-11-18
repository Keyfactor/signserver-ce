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
package org.signserver.client.api;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import java.util.Map;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GenericValidationRequest;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.protocol.ws.client.WSClientUtil;
import org.signserver.protocol.ws.gen.CryptoTokenOfflineException_Exception;
import org.signserver.protocol.ws.gen.IllegalRequestException_Exception;
import org.signserver.protocol.ws.gen.InvalidWorkerIdException_Exception;
import org.signserver.protocol.ws.gen.ProcessRequestWS;
import org.signserver.protocol.ws.gen.ProcessRequestWS.RequestMetadata.Entry;
import org.signserver.protocol.ws.gen.ProcessResponseWS;
import org.signserver.protocol.ws.gen.SignServerException_Exception;
import org.signserver.protocol.ws.gen.SignServerWS;
import org.signserver.protocol.ws.gen.SignServerWSService;

/**
 * Implements ISigningAndValidation using Web Services interface.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SigningAndValidationWS implements ISigningAndValidation {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SigningAndValidationWS.class);
    
    private SignServerWS signserver;

    /**
     * Creates an instance of SigningAndValidationWS using an WebService host and port.
     *
     * @param host The remote host to connect to.
     * @param port The remote port to connect to.
     */
    public SigningAndValidationWS(final String host, final int port) {
        this(host, port, null, null);
    }

    /**
     * Creates an instance of SigningAndValidationWS using an WebService host and port.
     *
     * @param host The remote host to connect to.
     * @param port The remote port to connect to.
     * @param useHTTPS True if SSL/TLS is to be used (HTTPS).
     */
    public SigningAndValidationWS(final String host, final int port,
            final boolean useHTTPS) {
        this(host, port, useHTTPS, null, null);
    }

    /**
     * Creates an instance of SigningAndValidationWS using WebService host and port
     * as well as username and password.
     * 
     * Notice: The password is transmitted insecurely over HTTP. This constructor 
     * should only be used if the communication is secured by some other means.
     *
     * @param host The remote host to connect to.
     * @param port The remote port to connect to.
     * @param username Username for authentication.
     * @param password Password for authentication.
     */
    public SigningAndValidationWS(final String host, final int port,
            final String username, final String password) {
        this(host, port, false, username, password);
    }

    /**
     * Creates an instance of SigningAndValidationWS using an WebService host and port.
     *
     * @param host The remote host to connect to.
     * @param port The remote port to connect to.
     * @param useHTTPS True if SSL/TLS is to be used (HTTPS).
     * @param username Username for authentication.
     * @param password Password for authentication.
     */
    public SigningAndValidationWS(final String host, final int port,
            final boolean useHTTPS,
            final String username, final String password) {
        final String url = (useHTTPS ? "https://" : "http://")
                + host + ":" + port
                + "/signserver/signserverws/signserverws?wsdl";
        final SignServerWSService service;
        try {
            service = new SignServerWSService(new URL(url),
                    new QName("gen.ws.protocol.signserver.org",
                    "SignServerWSService"));
        } catch (MalformedURLException ex) {
            throw new IllegalArgumentException("Malformed URL: "
                    + url, ex);
        }
        signserver = service.getSignServerWSPort();

        // Authentication
        if (username != null && password != null) {
            ((BindingProvider) signserver).getRequestContext().put(BindingProvider.USERNAME_PROPERTY, username);
            ((BindingProvider) signserver).getRequestContext().put(BindingProvider.PASSWORD_PROPERTY, password);
        }

        SignServerUtil.installBCProvider();
    }

    public ProcessResponse process(int workerId, ProcessRequest request, RequestContext context) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        return process("" + workerId, request, context);
    }

    @Override
    public ProcessResponse process(String workerIdOrName, ProcessRequest request, RequestContext context) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        List<ProcessResponse> responses = process(workerIdOrName, Collections.singletonList(request), context);
        if (responses.size() != 1) {
            throw new SignServerException("Unexpected number of responses: " + responses.size());
        }
        return responses.get(0);
    }

    public List<ProcessResponse> process(String workerIdOrName, List<ProcessRequest> requests, RequestContext context) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        try {
            List<ProcessRequestWS> list = new LinkedList<ProcessRequestWS>();

            ProcessRequestWS.RequestMetadata metadata = new ProcessRequestWS.RequestMetadata();
            Map<String, String> requestMetadata = (Map<String, String>) context.get(RequestContext.REQUEST_METADATA);
            if (requestMetadata != null) {
                List<Entry> entries = metadata.getEntry();
                for (Map.Entry<String, String> entry : requestMetadata.entrySet()) {
                    Entry e = new Entry();
                    e.setKey(entry.getKey());
                    e.setValue(entry.getValue());
                    entries.add(e);
                }
            }
            
            for (ProcessRequest req : requests) {
                ProcessRequestWS reqWS = new ProcessRequestWS();
                reqWS.setRequestDataBase64(new String(Base64.encode(RequestAndResponseManager.serializeProcessRequest(req))));
                reqWS.setRequestMetadata(metadata);
                list.add(reqWS);
            }

            List<ProcessResponseWS> resps;
            try {
                resps = signserver.process(workerIdOrName, list);
            } catch (CryptoTokenOfflineException_Exception e) {
                LOG.error(null, e);
                throw new CryptoTokenOfflineException(e.getMessage());
            } catch (IllegalRequestException_Exception e) {
                LOG.error(null, e);
                throw new IllegalRequestException(e.getMessage());
            } catch (InvalidWorkerIdException_Exception e) {
                LOG.error(null, e);
                throw new IllegalRequestException(e.getMessage());
            } catch (SignServerException_Exception e) {
                LOG.error(null, e);
                throw new SignServerException(e.getMessage());
            }

            List<org.signserver.protocol.ws.ProcessResponseWS> responses2 = WSClientUtil.convertProcessResponseWS(resps);

            List<ProcessResponse> responses3 = new LinkedList<ProcessResponse>();
            for (org.signserver.protocol.ws.ProcessResponseWS resp : responses2) {
                responses3.add(RequestAndResponseManager.parseProcessResponse(resp.getResponseData()));
            }

            return responses3;

        } catch (IOException ex) {
            throw new SignServerException("Serialization/deserialization failed", ex);
        }
    }

    @Override
    public GenericSignResponse sign(String signIdOrName, byte[] document) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {

        ProcessResponse resp = process(signIdOrName, new GenericSignRequest(1, document), new RequestContext());

        if (!(resp instanceof GenericSignResponse)) {
            throw new SignServerException("Unexpected response type: " + resp.getClass().getName());
        }
        return (GenericSignResponse) resp;
    }

    @Override
    public GenericValidationResponse validate(String validatorIdOrName, byte[] document) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        ProcessResponse resp = process(validatorIdOrName, new GenericValidationRequest(1, document), new RequestContext());

        if (!(resp instanceof GenericValidationResponse)) {
            throw new SignServerException("Unexpected response type: " + resp.getClass().getName());
        }
        return (GenericValidationResponse) resp;
    }
}
