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

package org.signserver.mailsigner;

import org.apache.mailet.MailetContext;
import org.signserver.server.WorkerContext;

/**
 * MailSigner specific context, contains the MailetContext
 * so the workers can access it.
 * 
 * 
 * @author Philip Vendil 3 aug 2008
 *
 * @version $Id$
 */

public class MailSignerContext extends WorkerContext {
	
	private MailetContext mailetContext;
	
	/**
	 * Default constructor.
	 * @param mailetContext the Mailet Context
	 */
	public MailSignerContext(MailetContext mailetContext){
	  this.mailetContext = mailetContext;	
	}
	
	/**
	 * 
	 * @return the current Mailet Context.
	 */
	public MailetContext getMailetContext(){
		return mailetContext;
	}
}
