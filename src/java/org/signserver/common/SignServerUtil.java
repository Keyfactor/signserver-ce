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

import java.security.Security;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Containing common util methods used for various reasons
 * 
 * 
 * @author Philip Vendil 2007 jan 26
 *
 * @version $Id: SignServerUtil.java,v 1.2 2007-12-11 05:36:58 herrvendil Exp $
 */

public class SignServerUtil {

	private static Logger log = Logger.getLogger(SignServerUtil.class);
	
	public static void installBCProvider(){
		if (Security.addProvider(new BouncyCastleProvider()) < 0) {         
			Security.removeProvider("BC");
			if (Security.addProvider(new BouncyCastleProvider()) < 0) {
				log.error("Cannot even install BC provider again!");
			} 

		}
	}
	

	
}
