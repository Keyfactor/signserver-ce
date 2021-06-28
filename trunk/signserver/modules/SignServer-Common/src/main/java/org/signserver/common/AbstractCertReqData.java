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
package org.signserver.common;

import java.io.IOException;

/**
 * Represents a certificate signing request.
 * 
 * Concrete implementations should provide formatting in both binary and
 * PEM / ASCII armored form.
 * 
 * Replaces Base64SignerCertReqData.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class AbstractCertReqData implements ICertReqData {
    private final String contentType;
    private final String fileSuffix;

    public AbstractCertReqData(String contentType, String fileSuffix) {
        this.contentType = contentType;
        this.fileSuffix = fileSuffix;
    }

    /**
     * @return The MIME type for this type of request.
     */
    public String getContentType() {
        return contentType;
    }

    /**
     * @return The file suffix to use for this type of request if it is going
     * to be stored as a file.
     */
    public String getFileSuffix() {
        return fileSuffix;
    }
    
    /**
     * @return The request in text form (i.e. PEM or ASCII armored form).
     * @throws IOException in case of problem encoding the request.
     */
    public abstract String toArmoredForm() throws IOException;
    
    /**
     * @return The request in binary form.
     * @throws IOException in case of problem encoding the request.
     */
    public abstract byte[] toBinaryForm() throws IOException;
    
}
