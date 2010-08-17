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
 * Class holding the results from testing a key.
 * 
 * @author markus
 * @version $Id$
 */
public class KeyTestResult implements Serializable {

    private static final long serialVersionUID = 1;

    /** Name of the key. */
    private String alias;

    /** If the signature was found consistent. */
    private boolean success;

    /** Status message: "OK" or error message. */
    private String status;

    /** Hash of public key. */
    private String publicKeyHash;

    /**
     * Creates a new instance of KeyTestResult.
     * @param alias The name the key
     * @param success If the signature was found consistent
     * @param status "OK" or error message
     */
    public KeyTestResult(final String alias, final boolean success,
            final String status, final String publicKeyHash) {
        this.alias = alias;
        this.success = success;
        this.status = status;
        this.publicKeyHash = publicKeyHash;
    }

    /**
     * @return Name of the key.
     */
    public String getAlias() {
        return alias;
    }

    /**
     * @return If the signature was found consistent.
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * @return Status message: "OK" or error message.
     */
    public String getStatus() {
        return status;
    }

    /**
     * @return Hash of public key.
     */
    public String getPublicKeyHash() {
        return publicKeyHash;
    }

}
