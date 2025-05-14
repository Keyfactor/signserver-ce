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

import org.apache.log4j.Logger;

import java.lang.reflect.InvocationTargetException;

/**
 * Utility class for loading components by class name.
 * This class provides a generic method for safely loading classes,
 * with detailed logging and error handling via {@link ComponentLoadingException}.
 *
 * @version $Id$
 */
public class ComponentLoader {

    private static final Logger LOG = Logger.getLogger(ComponentLoader.class);
    private static final String LOADING_COMPONENT_GENERAL_ERROR = "Loading component by class name failed.";

    /**
     * Loads a class by its fully qualified name and casts it to the expected type.
     * This method attempts to load the specified class by name and ensure it is assignable to the expected type.
     * If any error occurs during this process, a {@link ComponentLoadingException} is thrown with a general error message
     * and the detailed error is logged.
     *
     * @param className the fully qualified name of the class to load
     * @param classType the expected type the loaded class should be assignable to
     * @param classLoader the class loader to be used for loading classes or resources, used to ensure correct class loading
     *                   in different execution environments selected
     * @param <T>       the generic type to return
     * @return an instance of the loaded class cast to the specified type
     * @throws ComponentLoadingException if the class cannot be loaded, instantiated, or cast to the specified type
     */
    public <T> T load(final String className, Class<T> classType, ClassLoader classLoader) throws ComponentLoadingException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Loading worker with class name: " + className);
        }
        try {
            Class<?> loadedClass = classLoader.loadClass(className);
            if (!classType.isAssignableFrom(loadedClass)) {
                LOG.error("Loaded class " + className + " is not of type " + classType.getName());
                throw new ComponentLoadingException(LOADING_COMPONENT_GENERAL_ERROR);
            }
            Object instance = loadedClass.getDeclaredConstructor().newInstance();
            return classType.cast(instance);
        } catch (ClassNotFoundException e) {
            LOG.error("[" + classType.getName() + "]" + " ClassNotFoundException: " + className + " " + e.getMessage(), e);
            throw new ComponentLoadingException(LOADING_COMPONENT_GENERAL_ERROR, e);
        } catch (InstantiationException e) {
            LOG.error("[" + classType.getName() + "]" + " InstantiationException: " + className + " " + e.getMessage(), e);
            throw new ComponentLoadingException(LOADING_COMPONENT_GENERAL_ERROR, e);
        } catch (IllegalAccessException e) {
            LOG.error("[" + classType.getName() + "]" + " IllegalAccessException: " + className + " " + e.getMessage(), e);
            throw new ComponentLoadingException(LOADING_COMPONENT_GENERAL_ERROR, e);
        } catch (InvocationTargetException e) {
            LOG.error("[" + classType.getName() + "]" + " InvocationTargetException: " + className + " " + e.getMessage(), e);
            throw new ComponentLoadingException(LOADING_COMPONENT_GENERAL_ERROR, e);
        } catch (NoSuchMethodException e) {
            LOG.error("[" + classType.getName() + "]" + " NoSuchMethodException: " + className + " " + e.getMessage(), e);
            throw new ComponentLoadingException(LOADING_COMPONENT_GENERAL_ERROR, e);
        }
    }
}
