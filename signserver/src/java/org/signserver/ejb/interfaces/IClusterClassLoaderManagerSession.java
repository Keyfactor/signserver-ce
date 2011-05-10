package org.signserver.ejb.interfaces;

import javax.ejb.Local;
import javax.ejb.Remote;

/**
 * Common interface containing all the session bean methods.
 *
 * This session bean is resposible for managing the resource
 * data in the ClusterClassLoader
 */
public interface IClusterClassLoaderManagerSession {

    /**
     * Method used to add a resource to the cluster class loader.
     * @param moduleName the name of the module
     * @param part the name of the module part
     * @param version the version of the module
     * @param jarName the name of the jar containing the resource
     * @param resourceName the full name of the resource
     * @param implInterfaces all interfaces implemented if the resource is a
     * class.
     * @param description optional description of the resource
     * @param comment optional comment of the resource
     * @param resourceData the actual resource data
     */
    void addResource(String moduleName, String part, int version,
            String jarName, String resourceName, String implInterfaces,
            String description, String comment, byte[] resourceData);

    /**
     * Method removing the specified part of the given module.
     * @param moduleName the name of the module.
     * @param part the part of the module to remove
     * @param version the version of the module
     */
    void removeModulePart(String moduleName, String part, int version);

    /**
     * @return a list of all module names in the system.
     */
    String[] listAllModules();

    /**
     * @param moduleName name of module to list versions for
     * @return a list of all version for the specified module.
     */
    Integer[] listAllModuleVersions(String moduleName);

    /**
     * @param moduleName name of module to list parts for
     * @param version version of module to list parts for
     * @return a list of all parts for the specified module.
     */
    String[] listAllModuleParts(String moduleName, int version);

    /**
     * Lists all jars in the given module part.
     * @param moduleName the name of the module
     * @param part the name of the part in the module
     * @param version the version
     * @return an array of jar names in the module.
     */
    String[] getJarNames(String moduleName, String part, int version);

    @Remote
    interface IRemote extends IClusterClassLoaderManagerSession {

        String JNDI_NAME =
                "signserver/ClusterClassLoaderManagerSessionBean/remote";
    }

    @Local
    interface ILocal extends IClusterClassLoaderManagerSession {

        String JNDI_NAME =
                "signserver/ClusterClassLoaderManagerSessionBean/local";
    }
}
