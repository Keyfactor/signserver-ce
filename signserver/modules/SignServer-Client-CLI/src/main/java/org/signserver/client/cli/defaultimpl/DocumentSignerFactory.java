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
package org.signserver.client.cli.defaultimpl;

import static java.lang.System.out;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import org.apache.log4j.Logger;
import org.signserver.client.cli.defaultimpl.SignDocumentCommand.Protocol;

/**
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class DocumentSignerFactory {
    /** Logger for this class */
    private static final Logger LOG =
            Logger.getLogger(DocumentSignerFactory.class);
    
    private final Protocol protocol;
    private final String host;
    private final String servlet;
    private final int port;
    private final String digestAlgorithm;
    private final SSLSocketFactory sf;
    private final KeyStoreOptions keyStoreOptions;
    private final String username;
    private final String currentPassword;
    private final String pdfPassword;
    private final HostManager hostsManager;
    private final int timeOutLimit;

    public DocumentSignerFactory(final Protocol protocol,
                                 final KeyStoreOptions keyStoreOptions,
                                 final String host,
                                 final String servlet,
                                 final Integer port,
                                 final String digestAlgorithm,
                                 final String username,
                                 final String currentPassword,
                                 final String pdfPassword,
                                 final HostManager hostsManager,
                                 final int timeOutLimit) {
        this.protocol = protocol;
        this.host = host;
        this.servlet = servlet;
        this.digestAlgorithm = digestAlgorithm;
        this.keyStoreOptions = keyStoreOptions;
        this.username = username;
        this.currentPassword = currentPassword;
        this.pdfPassword = pdfPassword;
        this.hostsManager = hostsManager;
        this.timeOutLimit = timeOutLimit;
        sf = keyStoreOptions.setupHTTPS(createConsolePasswordReader(), out); // TODO: Should be done earlier and only once (not for each signer)
        
        if (port == null) {
            if (keyStoreOptions.isUsePrivateHTTPS()) {
                this.port = KeyStoreOptions.DEFAULT_PRIVATE_HTTPS_PORT;
            } else if (keyStoreOptions.isUseHTTPS()) {
                this.port = KeyStoreOptions.DEFAULT_PUBLIC_HTTPS_PORT;
            } else {
                this.port = KeyStoreOptions.DEFAULT_HTTP_PORT;
            }
        } else {
            this.port = port;
        }
    }

    public DocumentSigner createSigner(final String workerName,
                                       final Map<String, String> metadata,
                                       final boolean clientSide,
                                       final boolean isSignatureInputHash,
                                       final String typeId) {
        return createSigner(0, workerName, metadata, clientSide,
                            isSignatureInputHash, typeId);
    }

    public DocumentSigner createSigner(final int workerId,
                                       final Map<String, String> metadata,
                                       final boolean clientSide,
                                       final boolean isSignatureInputHash,
                                       final String typeId) {
        return createSigner(workerId, null, metadata, clientSide,
                            isSignatureInputHash, typeId);
    }

    private DocumentSigner createSigner(final int workerId,
                                        final String workerName,
                                        final Map<String, String> metadata,
                                        final boolean clientside,
                                        final boolean isSignatureInputHash,
                                        final String typeId) {
        final DocumentSigner signer;

        if (clientside) {
            if (isSignatureInputHash) {
                metadata.put("USING_CLIENTSUPPLIED_HASH", "true");
            }
            metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", digestAlgorithm);
        }

        if (typeId != null) {
            metadata.put("FILE_TYPE", typeId);
        }

        switch (protocol) {
            case WEBSERVICES: {
                LOG.debug("Using SignServerWS as procotol");
            
                final String workerIdOrName;
                if (workerId == 0) {
                    workerIdOrName = workerName;
                } else {
                    workerIdOrName = String.valueOf(workerId);
                }

                signer = new WebServicesDocumentSigner(
                    host,
                    port,
                    servlet,
                    workerIdOrName,
                    keyStoreOptions.isUseHTTPS(),
                    username, currentPassword,
                    pdfPassword, sf, metadata);
                break;
            }
            case CLIENTWS: {
                LOG.debug("Using ClientWS as procotol");
            
                final String workerIdOrName;
                if (workerId == 0) {
                    workerIdOrName = workerName;
                } else {
                    workerIdOrName = String.valueOf(workerId);
                }

                signer = new ClientWSDocumentSigner(
                    host,
                    port,
                    servlet,
                    workerIdOrName,
                    keyStoreOptions.isUseHTTPS(),
                    username, currentPassword,
                    pdfPassword, sf, metadata);
                break;
            }
            case HTTP:
            default: {
                LOG.debug("Using HTTP as procotol");
                
                if (sf != null) {
                    HttpsURLConnection.setDefaultSSLSocketFactory(sf);
                }
                
                if (workerId == 0) {
                    signer = new HTTPDocumentSigner(hostsManager, port, servlet,
                                                    keyStoreOptions.isUseHTTPS(),
                                                    workerName, username,
                                                    currentPassword, pdfPassword,
                                                    metadata, timeOutLimit);
                } else {
                    signer = new HTTPDocumentSigner(hostsManager, port, servlet,
                                                    keyStoreOptions.isUseHTTPS(),
                                                    workerId, username,
                                                    currentPassword, pdfPassword,
                                                    metadata, timeOutLimit);
                }
            }
        }

        return signer;
    }
    

    private ConsolePasswordReader createConsolePasswordReader() {
        return new DefaultConsolePasswordReader();
    }
}
