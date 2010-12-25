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
package org.signserver.server;

import javax.ejb.EJBException;
import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.RequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;

/**
 * Default implementation of IWorkerLookup for timestamp requests.
 *
 * Returns the timestampsigner read by the global configuration property
 * DEFAULTTIMESTAMPSIGNER.
 *
 * @author Markus Kilås
 * $Id$
 */
public class DefaultTimeStampSignerLookup implements ITimeStampSignerLookup {

    private static final Logger LOG = 
            Logger.getLogger(DefaultTimeStampSignerLookup.class);

    private IGlobalConfigurationSession.ILocal gCSession;

    public String lookupClientAuthorizedWorker(IClientCredential credential, RequestContext context) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(">lockupClientAuthorizedWorker");
        }
        try {
            final GlobalConfiguration config = getGlobalConfigurationSession().getGlobalConfiguration();
            final String result =
                    config.getProperty(GlobalConfiguration.SCOPE_GLOBAL,
                    "DEFAULTTIMESTAMPSIGNER");

            if (LOG.isDebugEnabled()) {
                LOG.debug("Will return worker: " + result);
            }

            return result;
        } catch (Exception ex) {
            throw new EJBException("Looking up worker failed", ex);
        }
    }

    private IGlobalConfigurationSession.ILocal getGlobalConfigurationSession() throws Exception {
        if (gCSession == null) {
            gCSession = ServiceLocator.getInstance().lookupLocal(
                        IGlobalConfigurationSession.ILocal.class);
        }
        return gCSession;
    }
}
