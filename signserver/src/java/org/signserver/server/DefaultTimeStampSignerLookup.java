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

import java.util.Hashtable;
import javax.ejb.EJBException;
import javax.naming.Context;
import javax.naming.InitialContext;
import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.RequestContext;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;

/**
 * Default implementation of IWorkerLookup for timestamp requests.
 *
 * Returns the timestampsigner read by the global configuration property
 * DEFAULTTIMESTAMPSIGNER.
 *
 * @author markus
 * $Id$
 */
public class DefaultTimeStampSignerLookup implements ITimeStampSignerLookup {

    private static final Logger LOG = 
            Logger.getLogger(DefaultTimeStampSignerLookup.class);

    private IGlobalConfigurationSession.ILocal gCSession;

    public String lockupClientAuthorizedWorker(IClientCredential credential, RequestContext context) {
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
            final Context context = getInitialContext();
            gCSession = (IGlobalConfigurationSession.ILocal) context.lookup(IGlobalConfigurationSession.ILocal.JNDI_NAME);
        }
        return gCSession;
    }

    /**
     * Get the initial naming context
     */
    private Context getInitialContext() throws Exception {
        final Hashtable<String, String> props = new Hashtable<String, String>();
        props.put(Context.INITIAL_CONTEXT_FACTORY, "org.jnp.interfaces.NamingContextFactory");
        props.put(Context.URL_PKG_PREFIXES, "org.jboss.naming:org.jnp.interfaces");
        props.put(Context.PROVIDER_URL, "jnp://localhost:1099");
        return new InitialContext(props);
    }
}
