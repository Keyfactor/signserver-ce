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

import java.io.Externalizable;

/**
 * Interface used for requests to WorkerSession.process method. Should
 * be implemented by all types of workers.
 * 
 * 
 * @author Philip Vendil
 * $Id: IProcessRequest.java,v 1.2 2007-12-11 05:36:58 herrvendil Exp $
 */

public interface IProcessRequest extends Externalizable{
	


}
