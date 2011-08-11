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
package org.signserver.common.clusterclassloader;

import java.util.HashMap;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
class SimpleClassLoader extends ClassLoader {

    private byte[] classData = null;
    private String name = null;
    private Class<?> definedClass = null;

    public SimpleClassLoader(ClassLoader parent, byte[] classData, String name) {
        super(parent);
        this.classData = classData;
        this.name = name;
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {

        Class<?> retval = null;
        try {
            retval = getParent().loadClass(name);
        } catch (ClassNotFoundException e) {


            if (name.equals(this.name)) {
                if (definedClass == null) {
                    byte[] b = classData;
                    String strippedResourceName = ClusterClassLoaderUtils.getInternalObjectName(name.substring(3));
                    HashMap<String, String> mappings = new HashMap<String, String>();
                    mappings.put(strippedResourceName, "v" + 1 + "/" + strippedResourceName);
                    b = ClusterClassLoaderUtils.addVersionToClass(mappings, b);

                    definedClass = defineClass(name, b, 0, b.length);
                }
                retval = definedClass;
            }
        }

        return retval;
    }
}