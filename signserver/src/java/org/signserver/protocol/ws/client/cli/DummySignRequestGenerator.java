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
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.protocol.ws.ProcessRequestWS;
import org.signserver.protocol.ws.ProcessResponseWS;

/**
 * Request generator used for test and demonstration purposes.
 * 
 * Should be used to generate requests to the DummySigner
 * 
 * 
 * @author Philip Vendil 17 dec 2007
 *
 * @version $Id$
 */

public class DummySignRequestGenerator implements IWSRequestGenerator{

	public List<ProcessRequestWS> genProcessRequests(Properties props)
			throws IOException {
		GenericSignRequest req1 = new GenericSignRequest(1,"testdata".getBytes());
		GenericSignRequest req2 = new GenericSignRequest(2,"testdata2".getBytes());
		ArrayList<ProcessRequestWS> retval = new ArrayList<ProcessRequestWS>();
		retval.add(new ProcessRequestWS(req1));
		retval.add(new ProcessRequestWS(req2));
		return retval;
	}

	public String processResponses(List<ProcessResponseWS> responses) {
		if(responses.size() != 2){
			return "Error wrong number of responses, expected 2";
		}
		
		ProcessResponseWS res = responses.get(0);
		try {
			GenericSignResponse resp = (GenericSignResponse) res.getProcessResponse();
			if(resp.getRequestID() != 1 && resp.getRequestID() != 2){
				return "Error, invalid request id " + resp.getRequestID() + " in responses";
			}
			
		} catch (IOException e) {
			return "Error parsing response :  " + e.getMessage();
		}
		
		return null;
	}

}
