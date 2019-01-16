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
package org.signserver.module.jarchive.signer;

import javax.persistence.EntityManager;
import org.signserver.common.WorkerConfig;
import org.signserver.module.cmssigner.CMSSigner;
import org.signserver.module.extendedcmssigner.ExtendedCMSSigner;
import org.signserver.server.WorkerContext;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;

/**
 * ExtendedCMSSigner suitable for creating CMS signatures to be included in JAR file signatures.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class JArchiveCMSSigner extends ExtendedCMSSigner {

    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {        

        // Override default value for DIRECTSIGNATURE to be TRUE
        String value = config.getProperty(CMSSigner.DIRECTSIGNATURE_PROPERTY, DEFAULT_NULL);
        if (value == null) {
            config.setProperty(CMSSigner.DIRECTSIGNATURE_PROPERTY, String.valueOf(true));
        }
        
        super.init(workerId, config, workerContext, workerEM);
    }

}
