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
 * Interface used in responses from the WorkerSession.process method. Should
 * be implemented by all types of workers.
 * 
 * 
 * @author Philip Vendil
 * $Id: IProcessResponse.java,v 1.1 2007-11-09 15:45:49 herrvendil Exp $
 */

public interface IProcessResponse extends Serializable{
	

    
    /**
     * Should contain the data that is processed, this is a very general method
     * which result can very depending on worker
     */
    public Serializable getProcessedData();
    

    
    

    

}
