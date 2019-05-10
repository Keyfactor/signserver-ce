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
package org.signserver.module.openpgp.signer;

import javax.persistence.EntityManager;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.server.WorkerContext;
import org.signserver.server.signers.BaseSigner;

/**
 * Base class for OpenPGP signing. To be extended for specific implementations.
 *
 * @author Vinay Singh
 * @Version $Id$
 */
public class BaseOpenPGPSigner extends BaseSigner {

    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Response processData(Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
