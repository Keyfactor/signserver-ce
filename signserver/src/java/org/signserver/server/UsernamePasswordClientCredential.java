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


public class UsernamePasswordClientCredential implements IClientCredential {

    private String username;
    private String hashedPassword;

    public UsernamePasswordClientCredential(final String username, final String password) {
        this.username = username;
        this.hashedPassword = password;
    }

    public String getPassword() {
        return hashedPassword;
    }

    public String getUsername() {
        return username;
    }
}
