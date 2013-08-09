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

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;

import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;

/**
 * Docuement validator using the HTTP protocol.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class HTTPDocumentValidator extends AbstractDocumentValidator {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(HTTPDocumentValidator.class);
    
    private URL processServlet;
    private String workerName;
    private int workerId;
    private String username;
    private String password;

    public HTTPDocumentValidator(final URL processServlet,
            final String workerName, final String username,
            final String password) {
        this.processServlet = processServlet;
        this.workerName = workerName;
        this.workerId = 0;
        this.username = username;
        this.password = password;
    }
    
    public HTTPDocumentValidator(final URL processServlet,
            final int workerId, final String username,
            final String password) {
        this.processServlet = processServlet;
        this.workerName = null;
        this.workerId = workerId;
        this.username = username;
        this.password = password;
    }
    
    @Override
    protected void doValidate(byte[] data, String encoding, OutputStream out)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException, IOException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending validation request "
                    + " containing data of length " + data.length + " bytes"
                    + " to worker " + workerName);
        }

        

    }

}
