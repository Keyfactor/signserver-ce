/** ***********************************************************************
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
 ************************************************************************ */
package org.signserver.ejb.interfaces;

import javax.ejb.Local;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.server.log.AdminInfo;

/**
 * Local interface for the process session to be used internally when
 * transaction is needed.
 *
 * @author Vinay Singh
 * @version $Id: ProcessTransactionSessionLocal.java 9302 2018-05-04 15:08:01Z vinays
 * $
 */
@Local
public interface ProcessTransactionSessionLocal {

    /**
     * The Worker Beans main method. Takes requests processes them and returns a
     * response. This method is used when a transaction is needed.
     *
     * @param info Administrator information
     * @param wi id of worker who should process the request
     * @param request the request
     * @param requestContext
     * @return The process response
     * @throws IllegalRequestException
     * @throws CryptoTokenOfflineException
     * @throws SignServerException
     */
    Response processWithTransaction(final AdminInfo info, WorkerIdentifier wi, Request request,
            RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException;

}
