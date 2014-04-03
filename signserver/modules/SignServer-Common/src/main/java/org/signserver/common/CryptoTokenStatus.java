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

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

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
     * @deprecated Use the constructor taking an list of errors
     */
    @Deprecated
    public CryptoTokenStatus(int workerId, int tokenStatus, WorkerConfig config) {
        this(workerId, tokenStatus, Collections.<String>emptyList(), config);
    }
    
    public CryptoTokenStatus(int workerId, int tokenStatus, List<String> errors, WorkerConfig config) {
        super(workerId, addCryptoTokenError(tokenStatus, workerId, errors), config);
        this.tokenStatus = tokenStatus;
    }
    
    private static List<String> addCryptoTokenError(int tokenStatus, int workerId, List<String> errors) {
        if (tokenStatus == SignerStatus.STATUS_OFFLINE) {
            List<String> moreErrors = new LinkedList<String>(errors);
            moreErrors.add("Error Crypto Token is disconnected");
            return moreErrors;
        }
        return errors;
    }

    /**
     * @return Returns the tokenStatus.
     */
    public int getTokenStatus() {
        return tokenStatus;
    }

}
