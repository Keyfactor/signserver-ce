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
package org.signserver.validationservice.server;

import org.signserver.common.SignServerException;

/**
 * TODO: Document me!
 *
 * @version $Id$
 */
public class CRLCertRevokedException extends SignServerException {

    private static final long serialVersionUID = 1L;
    private int reasonCode;

    public void setReasonCode(int reasonCode) {
        this.reasonCode = reasonCode;
    }

    public int getReasonCode() {
        return reasonCode;
    }

    public CRLCertRevokedException(String message, int reasonCode) {
        super(message);
        this.reasonCode = reasonCode;
    }

    public CRLCertRevokedException(String message, Throwable e, int reasonCode) {
        super(message, e);
        this.reasonCode = reasonCode;
    }
}
