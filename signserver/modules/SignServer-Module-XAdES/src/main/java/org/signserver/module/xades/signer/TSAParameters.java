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
package org.signserver.module.xades.signer;

/**
 * Class containing TSA Properties.
 * 
 * Based on patch contributed by Luis Maia &lt;lmaia@dcc.fc.up.pt&gt;.
 *
 * @author Luis Maia <lmaia@dcc.fc.up.pt>
 * @version $Id$
 */
public class TSAParameters {
    private final String url;
    private final String username;
    private final String password;

    /**
     * Constructs an new instance of TSA Parameters.
     * @param url URL of time-stamp service
     * @param username Username
     * @param password Password
     */
    public TSAParameters(final String url, final String username, final String password) {
        this.url = url;
        this.username = username;
        this.password = password;
    }

    /**
     * Constructs an new instance of XAdESSignerParameters without credentials.
     * @param url URL of time-stamp service
     */
    public TSAParameters(String url) {
        this(url, null, null);
    }

    /**
     * @return URL of time-stamp service
     */
    public String getUrl() {
        return url;
    }

    /**
     * @return Username
     */
    public String getUsername() {
        return username;
    }

    /**
     * @return Password
     */
    public String getPassword() {
        return password;
    }

    @Override
    public String toString() {
        return "TSAParameters{" + "url=" + url + ", username=" + username + ", password=<" + (password == null ? "null" : "masked") + ">}";
    }
    
}
