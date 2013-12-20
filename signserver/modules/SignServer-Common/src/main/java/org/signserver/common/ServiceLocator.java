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
 * Helper class for doing JNDI lookups.
 *
 * @author Markus Kilås
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
     * @throws NamingException in case of failure to lookup
     */
    @SuppressWarnings("unchecked") // Don't think we can make this without unchecked cast
    public <T> T lookupRemote(final Class<T> remoteInterface)
            throws NamingException {
        return lookupRemote(remoteInterface, null);
    }
    /**
     * @param <T> Type of class
     * @param remoteInterface Remote interface to lookup
     * @return an instance of the remote interface
     * @throws NamingException in case of failure to lookup
     */
    @SuppressWarnings("unchecked") // Don't think we can make this without unchecked cast
    public <T> T lookupRemote(final Class<T> remoteInterface, final String module)
            throws NamingException {
        T beanInterface;
        try {
            // First try using JBoss JNDI
            beanInterface = (T) initialContext.lookup(
                    getJBossJNDIName(remoteInterface, true));
        } catch (NamingException e) {
            try {
                // Then try using GlassFish JNDI
                beanInterface = (T) initialContext.lookup(
                        getGlassfishJNDIName(remoteInterface, true));
            } catch (NamingException ex) {
                try {
                    // Then try using portable JNDI (GlassFish 3+, JBoss 7+)
                    beanInterface = (T) initialContext.lookup(
                            getPortableJNDIName(remoteInterface, module, true));
                } catch (NamingException exx) {
                    try {
                        // Then try using JBoss 7 JNDI
                        beanInterface = (T) initialContext.lookup(
                                getJBoss7JNDIName(remoteInterface, module, true));
                    } catch (NamingException exxx) {
                        LOG.error("Error looking up SignServer interface", exxx);
                        throw exx;
                    }
                }
            }
        }
        return beanInterface;
    }

    /**
     * @param <T> Type of class
     * @param localInterface Local interface to lookup
     * @return an instance of the remote interface
     * @throws NamingException in case of failure to lookup
     */
    @SuppressWarnings("unchecked") // Don't think we can make this without unchecked cast
    public <T> T lookupLocal(final Class<T> localInterface)
            throws NamingException {
        T beanInterface;
        try {
            // First try using JBoss JNDI
            beanInterface = (T) initialContext.lookup(
                    getJBossJNDIName(localInterface, false));
        } catch (NamingException e) {
            try {
                 // Then try using portable JNDI (GlassFish 3+, JBoss 7+)
                 beanInterface = (T) initialContext.lookup(
                         getPortableJNDIName(localInterface, null, false));
             } catch (NamingException exx) {
                 try {
                     // Then try using JBoss 7 JNDI
                     beanInterface = (T) initialContext.lookup(
                             getJBoss7JNDIName(localInterface, null, false));
                 } catch (NamingException exxx) {
                     try {
                        // Then try using GlassFish _Remote_ JNDI
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Trying GlassFish remote JNDI instead");
                        }
                        beanInterface = (T) initialContext.lookup(
                            getGlassfishJNDIName(localInterface, true));
                     } catch (NamingException ex) {
                         if (LOG.isDebugEnabled()) {
                             LOG.debug("Last exception: " + ex.getExplanation());
                         }
                         LOG.error("Error looking up SignServer local interface", exxx);
                        throw exx;
                     }
                 }
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
        final String result;
        
        if (clazz.getName().startsWith("org.cesecore")) {
            result = "cesecore/" + clazz.getSimpleName();
        } else {

            String interfaceName = clazz.getSimpleName();
            if (clazz.getEnclosingClass() != null
                    && ((remote && "IRemote".equals(interfaceName))
                        || (!remote && "ILocal".equals(interfaceName)))) {
                interfaceName = clazz.getEnclosingClass().getSimpleName();
            }
            if (interfaceName.charAt(0) == 'I') {
                interfaceName = interfaceName.substring(1);
            }
            result = "signserver/" + interfaceName + "Bean"
                    + (remote ? "/remote" : "/local");
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("JBoss JNDI name: " + result);
        }
        return result;
    }

    /**
     * @param clazz Interface of bean
     * @return JNDI name for the bean the Glassfish way
     */
    private String getGlassfishJNDIName(final Class clazz, final boolean remote) {
        final String result = withViewName(clazz.getName(), remote);
        if (LOG.isDebugEnabled()) {
            LOG.debug("GlassFish JNDI name: " + result);
        }
        return result;
    }
    
    /**
     * @return Name ending with Remote or Local
     */
    private String withViewName(final String name, final boolean remote) {
        final String result;
        if (remote) {
            if (name.endsWith("Remote")) {
                result = name;
            } else {
                result = name + "$IRemote";
            }
        } else {
            if (name.endsWith("Local")) {
                result = name;
            } else {
                result = name + "$ILocal";
            }
        }
        return result;
    }
    
    private String getPortableJNDIName(final Class clazz, String module,final boolean remote) {
        if (module == null) {
            module = "SignServer-ejb";
        }
        final String result = "java:global/signserver/" + module + "/"
                + getBeanName(clazz, remote) + "!" + withViewName(clazz.getName(), remote);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Portable JNDI name: " + result);
        }
        return result;
    }
    
    private String getJBoss7JNDIName(final Class clazz, String module, final boolean remote) {
        if (module == null) {
            module = "SignServer-ejb";
        }
        final String viewClassName = withViewName(clazz.getName(), remote);
        
        String beanName = getBeanName(clazz, remote);

        final String jndiNameJEE6;
        if (remote) {
            jndiNameJEE6 = "ejb:signserver" + "/" + module + "//"  + beanName + "!" + viewClassName;
        } else {
            jndiNameJEE6 = "java:app/" + module + "/"+ beanName + "!" + viewClassName;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("JBoss 7 JNDI name: " + jndiNameJEE6);
        }
        return jndiNameJEE6;
    }

    private String getBeanName(final Class clazz, final boolean remote) {
        String beanName = clazz.getSimpleName();
        if (clazz.getEnclosingClass() != null
                && ((remote && "IRemote".equals(beanName))
                    || (!remote && "ILocal".equals(beanName)))) {
            beanName = clazz.getEnclosingClass().getSimpleName();
        }
        if (beanName.endsWith("Remote")) {
            beanName = beanName.substring(0, beanName.length() - "Remote".length());
        }
        if (beanName.charAt(0) == 'I') {
            beanName = beanName.substring(1);
        }
        beanName += "Bean";
        return beanName;
    }
}
