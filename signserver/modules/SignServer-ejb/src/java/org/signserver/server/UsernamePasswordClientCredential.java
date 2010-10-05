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

import java.io.Serializable;


public class UsernamePasswordClientCredential implements IClientCredential,
        Serializable {

    private static final long serialVersionUID = 1L;

    private String username;
    private String hashedPassword;

    public UsernamePasswordClientCredential(final String username,
            final String hashedPassword) {
        this.username = username;
        this.hashedPassword = hashedPassword;
    }

    public String getPassword() {
        return hashedPassword;
    }

    public String getUsername() {
        return username;
    }
}
