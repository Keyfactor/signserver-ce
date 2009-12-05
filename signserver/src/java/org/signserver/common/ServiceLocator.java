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

import javax.naming.InitialContext;
import javax.naming.NamingException;
import org.apache.log4j.Logger;

/**
 *
 * @author markus
 * @version $Id$
 */
public final class ServiceLocator {

    /** Log4j instance. */
    private static final Logger LOG = Logger.getLogger(ServiceLocator.class);

    /** Initial context. */
    private final transient InitialContext initialContext;

    /** The singleton instance. */
    private static ServiceLocator instance;

    static {
        try {
            instance = new ServiceLocator();
        } catch (NamingException se) {
            throw new RuntimeException(se);
        }
    }

    /**
     * Constructs the instance.
     * @throws NamingException In case of failure
     */
    private ServiceLocator() throws NamingException {
        initialContext = new InitialContext();
    }

    /**
     * Get the ServiceLocator instance.
     * @return The ServiceLocator instance
     */
    public static ServiceLocator getInstance() {
        return instance;
    }

    /**
     * @param <T> Type of class
     * @param remoteInterface Remote interface to lookup
     * @return an instance of the remote interface
     * @throws RemoteException in case of failure to lookup
     */
    public <T> T lookupRemote(final Class<T> remoteInterface)
            throws NamingException {
        T beanInterface;
        try {
            // First try using JBoss JNDI
            beanInterface = (T) initialContext.lookup(
                    getJBossJNDIName(remoteInterface, true));
        } catch (NamingException e) {
            try {
                // Then try using Glassfish JNDI
                beanInterface = (T) initialContext.lookup(
                        getGlassfishJNDIName(remoteInterface));
            } catch (NamingException ex) {
                LOG.error("Error looking up signserver interface", ex);
                throw ex;
            }
        }
        return beanInterface;
    }

        /**
     * @param <T> Type of class
     * @param remoteInterface Remote interface to lookup
     * @return an instance of the remote interface
     * @throws NamingException in case of failure to lookup
     */
    public <T> T lookupLocal(final Class<T> localInterface)
            throws NamingException {
        T beanInterface;
        try {
            // First try using JBoss JNDI
            beanInterface = (T) initialContext.lookup(
                    getJBossJNDIName(localInterface, false));
        } catch (NamingException e) {
            try {
                // Then try using Glassfish JNDI
                beanInterface = (T) initialContext.lookup(
                        getGlassfishJNDIName(localInterface));
            } catch (NamingException ex) {
                LOG.error("Error looking up signserver interface", ex);
                throw ex;
            }
        }
        return beanInterface;
    }

    /**
     * @param remoteInterface Remote interface of bean
     * @return JNDI name for the bean the JBoss way
     */
    private String getJBossJNDIName(final Class clazz,
            final boolean remote) {

        String interfaceName = clazz.getSimpleName();
        if (clazz.getEnclosingClass() != null
                && ((remote && "IRemote".equals(interfaceName))
                    || (!remote && "ILocal".equals(interfaceName)))) {
            interfaceName = clazz.getEnclosingClass().getSimpleName();
        }
        if (interfaceName.charAt(0) == 'I') {
            interfaceName = interfaceName.substring(1);
        }
        final String result = "signserver/" + interfaceName + "Bean"
                + (remote ? "/remote" : "/local");
        if (LOG.isDebugEnabled()) {
            LOG.debug("JBoss JNDI name: " + result);
        }
        return result;
    }

    /**
     * @param remoteInterface Remote interface of bean
     * @return JNDI name for the bean the Glassfish way
     */
    private String getGlassfishJNDIName(final Class remoteInterface) {
        final String result = remoteInterface.getName();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Glassfish JNDI name: " + result);
        }
        return result;
    }

}
