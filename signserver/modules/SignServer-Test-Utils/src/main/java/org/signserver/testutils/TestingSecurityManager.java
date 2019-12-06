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
package org.signserver.testutils;

import java.security.Permission;

import junit.framework.Assert;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class TestingSecurityManager extends SecurityManager {

    public static void install() {
        final SecurityManager existing = System.getSecurityManager();
        if (existing instanceof TestingSecurityManager) {
            return;
        } else if (existing == null) {
            new TestingSecurityManager();
        } else {
            ClassLoader loader = existing.getClass().getClassLoader();
            Assert.fail(
                    "SecurityManager already set "
                    + "<" + existing + ">, "
                    + "class: " + existing.getClass() + ", "
                    + (loader == null ? "bootstap class loader" : ("class loader: <" + loader + "> "
                    + "class loader class: " + loader.getClass())));
        }
    }

    public static void remove() {
        final SecurityManager existing = System.getSecurityManager();
        if (existing instanceof TestingSecurityManager) {
            System.setSecurityManager(null);
        }
    }

    private TestingSecurityManager() {
        System.setSecurityManager(this);
    }

    @Override
    public void checkExit(int status) throws ExitException {
        throw new ExitException(status);
    }

    @Override
    public void checkPermission(Permission perm) {
        // do nothing
    }

    @Override
    public void checkPermission(Permission perm,
            Object context) {
        //do nothing
    }
}
