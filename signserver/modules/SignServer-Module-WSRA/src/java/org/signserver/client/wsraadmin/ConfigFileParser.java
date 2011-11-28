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
 
package org.signserver.client.wsraadmin;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Properties;

/**
 * A parser for the WSRAAdminCLI configuration file.
 * 
 * This is a file containing configuration how to
 * connect to the WSRA database, such 
 * as dialect, hostname, port etc
 * 
 * 
 * @author Philip Vendil 29 okt 2008
 *
 * @version $Id$
 */

public class ConfigFileParser {
	
	private Properties props =  new Properties();
	
	public ConfigFileParser(String fileName) throws IOException{		
		props.load(new FileInputStream(fileName));		
	}
	
	/**
	 * 
	 * @return all properties that have keys starting with 'hibernate'
	 */
	public Properties getHibernateConfiguration(){
		Properties retval = new Properties();
		
		Enumeration<?> e =  props.propertyNames();
		while(e.hasMoreElements()){
			String property = (String) e.nextElement();
			if(property.toLowerCase().startsWith("hibernate")){
				retval.setProperty(property, props.getProperty(property));
			}
		}
		
		return retval;
	}

}
