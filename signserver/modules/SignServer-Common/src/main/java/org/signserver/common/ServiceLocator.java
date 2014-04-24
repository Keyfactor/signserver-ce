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
 * The strategy is simply to try each names (corresponding to how different 
 * application servers want it) at a time until it succeeds or there are no 
 * more names.
 * 
 * One possible optimization would be to cache the result but that is not 
 * implemented currently.
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
    
    private static final NameProvider PROVIDER_JBOSS5 = new JBoss5NameProvider();
    private static final NameProvider PROVIDER_JBOSS7 = new JBoss7NameProvider();
    private static final NameProvider PROVIDER_GLASSFISH = new GlassFishNameProvider();
    private static final NameProvider PROVIDER_GLASSFISH_REMOTEONLY = new GlassFishNameProvider(true);
    private static final NameProvider PROVIDER_PORTABLE = new PortableNameProvider();
    
    /** List of providers for the remote names. */
    private static final NameProvider[] NAMES_REMOTE = new NameProvider[] { PROVIDER_JBOSS7, PROVIDER_GLASSFISH, PROVIDER_JBOSS5 };
    
    /** 
     * List of providers for the local names.
     * Note that because of the trouble of finding an approach that works across 
     * multiple application servers, for GlassFish we fall back to use the 
     * remote interface. Using the local would have required some configuration 
     * for GlassFish but would instead then make JBoss 5 fail...
     */
    private static final NameProvider[] NAMES_LOCAL = new NameProvider[] { PROVIDER_PORTABLE, PROVIDER_GLASSFISH, PROVIDER_JBOSS7, PROVIDER_JBOSS5, PROVIDER_GLASSFISH_REMOTEONLY };

    /** Prefix for CESeCore modules. */
    private static final String CESECORE_APP = "ejbca";

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
     * @param module Name of module the implementation should be located in
     * @return an instance of the remote interface
     * @throws NamingException in case of failure to lookup
     */
    @SuppressWarnings("unchecked") // Don't think we can make this without unchecked cast
    public <T> T lookupRemote(final Class<T> remoteInterface, final String module)
            throws NamingException {
        return lookup(remoteInterface, module, true);
    }
    
    /** Try lookup using each name until it succeeds or there are no more names in the array. */
    @SuppressWarnings("unchecked") // Don't think we can make this without unchecked cast
    private <T> T lookup(final Class<T> clazz, final String module, final boolean remote) throws NamingException {
        T result = null;
        final NameProvider[] providers = remote ? NAMES_REMOTE : NAMES_LOCAL;
        NamingException lastException = null;
        for (NameProvider provider : providers) {
            try {
                result = (T) initialContext.lookup(provider.getName(clazz, module, remote));
                break;
            } catch (NamingException ex) {
                lastException = ex;
            }
        }
        if (result == null) {
            if (lastException == null) {
                throw new NamingException("Error looking up SignServer interface");
            } else {
                throw lastException;
            }
        }
        return result;
    }

    /**
     * @param <T> Type of class
     * @param localInterface Local interface to lookup
     * @return an instance of the remote interface
     * @throws NamingException in case of failure to lookup
     */
    public <T> T lookupLocal(final Class<T> localInterface)
            throws NamingException {
        return lookup(localInterface, null, false);
    }
    
    /**
     * @return Name ending with Remote or Local
     */
    private static String withViewName(final String name, final boolean remote) {
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

    private static String getBeanName(final Class clazz, final boolean remote) {
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
    
    private interface NameProvider {
        String getName(Class clazz, String module, boolean remote);
    }
    
    private static class JBoss5NameProvider implements NameProvider {
        @Override
        public String getName(Class clazz, String module, boolean remote) {
            final String result;

            if (clazz.getName().startsWith("org.cesecore")) {
                result = CESECORE_APP + "/" + clazz.getSimpleName();
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
    }
    
    private static class PortableNameProvider implements NameProvider {
        @Override
        public String getName(Class clazz, String module, boolean remote) {
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
    }
    
    private static class JBoss7NameProvider implements NameProvider {
        @Override
        public String getName(Class clazz, String module, boolean remote) {
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
    }
    
    private static class GlassFishNameProvider implements NameProvider {
        private final boolean remoteOnly;

        public GlassFishNameProvider() {
            this.remoteOnly = false;
        }
        
        public GlassFishNameProvider(boolean remoteOnly) {
            this.remoteOnly = remoteOnly;
        }
        
        @Override
        public String getName(Class clazz, String module, boolean remote) {
            if (remoteOnly) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Trying GlassFish remote JNDI instead");
                }
            }
            final String result = withViewName(clazz.getName(), remote || remoteOnly);
            if (LOG.isDebugEnabled()) {
                LOG.debug("GlassFish JNDI name: " + result);
            }
            return result;
        }
    }    
}
