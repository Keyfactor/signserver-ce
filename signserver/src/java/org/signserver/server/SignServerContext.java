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

import javax.persistence.EntityManager;

/**
 * SignServer specific context, contains the Entity Manager
 * so the workers can access it.
 * 
 * 
 * @author Philip Vendil 3 aug 2008
 *
 * @version $Id$
 */

public class SignServerContext extends WorkerContext {
	
	private EntityManager em;
	
	/**
	 * Default constructor.
	 * @param em the Entity Manager
	 */
	public SignServerContext(EntityManager em){
	  this.em = em;	
	}
	
	/**
	 * 
	 * @return the current Entity Manager.
	 */
	public EntityManager getEntityManager(){
		return em;
	}

}
