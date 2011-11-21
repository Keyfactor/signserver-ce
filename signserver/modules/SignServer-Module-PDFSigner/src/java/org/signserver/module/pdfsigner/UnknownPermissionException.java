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
package org.signserver.module.pdfsigner;

/**
 * Exception indicating that an unknown permission name was used.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class UnknownPermissionException extends Exception {
    private String permission;

    public UnknownPermissionException(String permission, String message) {
        super(message);
        this.permission = permission;
    }

    public UnknownPermissionException(String permission) {
        super("Unknown permission value: \"" + permission + "\"");
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
    
}
