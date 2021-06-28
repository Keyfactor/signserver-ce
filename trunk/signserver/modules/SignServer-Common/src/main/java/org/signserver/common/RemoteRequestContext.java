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

import java.io.Serializable;

/**
 * Additional information provided by the client over the EJB interface.
 * The information provided with the request in an object of this type will
 * be included in the RequestContext.
 * Note that information in this object comes from the client.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class RemoteRequestContext implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private RequestMetadata metadata;
    private String username;
    private String password;

    public RemoteRequestContext() {   
    }
    
    public RemoteRequestContext(RequestMetadata metadata) {
        this.metadata = metadata;
    }

    public RequestMetadata getMetadata() {
        return metadata;
    }

    public void setMetadata(RequestMetadata metadata) {
        this.metadata = metadata;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

}
