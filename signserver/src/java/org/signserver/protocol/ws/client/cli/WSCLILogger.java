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

package org.signserver.protocol.ws.client.cli;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.DateFormat;
import java.util.Date;

import org.signserver.cli.IllegalAdminCommandException;

/**
 * WS CLI logger managing the output to log file.
 * 
 * 
 * @author Philip Vendil 17 dec 2007
 *
 * @version $Id$
 */

public class WSCLILogger {
	
	private FileOutputStream fos;
	private PrintWriter logOut;
	
	DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.LONG);
	
	WSCLILogger(String path) throws IllegalAdminCommandException{
		try {
			fos = new FileOutputStream(path,true);
			logOut = new PrintWriter(fos);
		} catch (FileNotFoundException e) {
			throw new IllegalAdminCommandException("Error when opening log file " + path + " : " +e.getMessage());
		}	
	}
	
	void info(String message){		
		logOut.println(dateFormat.format(new Date()) + " INFO : " + message);
		logOut.flush();
	}
	void info(String message,Throwable t){
		logOut.println(dateFormat.format(new Date()) + " INFO : " + message);
		t.printStackTrace(logOut);
		logOut.flush();
	}
	void error(String message){
		logOut.println(dateFormat.format(new Date()) + " ERROR : " + message);
		logOut.flush();
	}
	void error(String message,Throwable t){
		logOut.println(dateFormat.format(new Date()) + " ERROR : " + message);
		t.printStackTrace(logOut);
		logOut.flush();
	}

	void close(){
		try {
			fos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		logOut.close();
	}
}
