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
import java.security.cert.Certificate;

/**
 * Interface used in responses from the SignSession.signData method. Should
 * be implemented by all types of signers.
 * 
 * 
 * @author Philip Vendil
 * $Id: ISignResponse.java,v 1.1 2007-02-27 16:18:10 herrvendil Exp $
 */

public interface ISignResponse extends Serializable{
	
	/**
	 * Should contain a unique request id used to link to the request
	 */
    public int getRequestID();
    
    /**
     * Should contain the data that is signed, this is a very general method
     * which result can very depending on signer
     */
    public Serializable getSignedData();
    
    /**
     * Method returning the certificate used for the signature
     * 
     * @return the Certificate that was used to sign.
     */
    
    public Certificate getSignerCertificate();
    
    
    /**
     * Method that should return an Id of the archived data could be
     * the response serialnumber.
     * 
     * return null of not implemented.
     */
    public String getArchiveId();
    
    /**
     * Method that should return a archive data object used for achiving.
     * return null if not implemented.
     */
    public ArchiveData getArchiveData();
    

}
