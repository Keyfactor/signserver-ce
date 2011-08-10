/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

/**
 * Abstract Status class containing token status.
 * 
 * @author Philip Vendil 23 nov 2007
 * @version $Id$
 */
public abstract class CryptoTokenStatus extends WorkerStatus {

    private static final long serialVersionUID = 1L;
    
    public static final int STATUS_ACTIVE = 1;
    public static final int STATUS_OFFLINE = 2;
    private int tokenStatus = 0;

    /** 
     * Main constructor
     */
    public CryptoTokenStatus(int workerId, int tokenStatus, WorkerConfig config) {
        super(workerId, config);
        this.tokenStatus = tokenStatus;
    }

    /**
     * @return Returns the tokenStatus.
     */
    public int getTokenStatus() {
        return tokenStatus;
    }

    /**
     * Method checking the crypto token that it is online.
     */
    @Override
    public String isOK() {
        String retval = null;
        if (this.getActiveSignerConfig().getProperties().getProperty(SignServerConstants.DISABLED) == null || !getActiveSignerConfig().getProperties().getProperty(SignServerConstants.DISABLED).equalsIgnoreCase("TRUE")) {
            if (getTokenStatus() == SignerStatus.STATUS_OFFLINE) {
                retval = "Error Crypto Token is disconnected, worker Id : " + workerId;
            }
        }
        return retval;
    }
}
