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

import java.io.IOException;
import java.util.List;
import java.util.Properties;

import org.signserver.protocol.ws.ProcessRequestWS;
import org.signserver.protocol.ws.ProcessResponseWS;

/**
 * Interface used by the WS client for generator process requests
 * and processing the responses.
 * 
 * It is used to test different types of SignServer processors.
 * 
 * @author Philip Vendil 15 dec 2007
 *
 * @version $Id$
 */

public interface IWSRequestGenerator {

	/**
	 * Method used to generate one or more process requests that should be
	 * sent to the sign server.
	 * 
	 * @param props the CLI properties file that might be used for configuring this request generator.
	 * @return a list of 1 or more process requests sent to the sign server 
	 * @throws IOException if configuration or any other error occurred during
	 * generation. Should contain a descriptive error message.
	 */
	List<ProcessRequestWS> genProcessRequests(Properties props) throws IOException;
	
	/**
	 * Method that should process or check the data in the response.
	 * 
	 * @param responses the list of responses sent from the SignServer 
	 * @return null if everything is OK, otherwise a descriptive error message that
	 * is displayed for the user. 
	 */
	String processResponses(List<ProcessResponseWS> responses);
	
}
