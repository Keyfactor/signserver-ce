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
public class OCSPStatusNotGoodException extends SignServerException {

    private static final long serialVersionUID = 1L;
    private Object certStatus;

    public void setCertStatus(Object certStatus) {
        this.certStatus = certStatus;
    }

    public Object getCertStatus() {
        return certStatus;
    }

    public OCSPStatusNotGoodException(String message, Object certStatus) {
        super(message);
        this.certStatus = certStatus;
    }

    public OCSPStatusNotGoodException(String message, Throwable e, Object certStatus) {
        super(message, e);
        this.certStatus = certStatus;
    }
}
