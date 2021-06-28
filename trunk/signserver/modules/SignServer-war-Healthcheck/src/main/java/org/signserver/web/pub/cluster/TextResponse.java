/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.signserver.web.pub.cluster;

import java.io.IOException;
import java.io.Writer;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;


/**
 * Class that responds with a text string of status is OK else it responds the error message (optional).
 * 
 * The following servlet init parameters might be used:
 * MaintenancePropertyName :  a string to return if a file with a propert=true exists, to deliberately take a node of from the cluster
 * OKMessage : the string to return when everything is ok.
 * SendServerError : (boolean) Send A 500 Server error is returned instead of errormessage
 * CustomErrorMsg : Send a static predefined errormessage instead of the on created by the healthchecker.
 * 
 * This class was copied from the old EJBCA-util.
 * 
 * @author Philip Vendil
 * @version $Id: TextResponse.java 5585 2008-05-01 20:55:00Z anatom $
 *
 */
public class TextResponse implements IHealthResponse {

	private static Logger log = Logger.getLogger(TextResponse.class);
	
	private static final String OK_MESSAGE = "ALLOK";
	private static final String DEFAULT_MAINTENANCE_MESSAGE = "DOWN_FOR_MAINTENANCE";
	
	
	private String okMessage = null;
	private boolean sendServerError = false;
	private String maintenanceMessage = null;
	private String customErrorMessage = null;
	
        @Override
	public void init(ServletConfig config) {
		okMessage = config.getInitParameter("OKMessage");
		if (okMessage == null) {
			okMessage = OK_MESSAGE;
		}
		
		maintenanceMessage = config.getInitParameter("MaintenancePropertyName");
		if(maintenanceMessage == null) {
			maintenanceMessage = DEFAULT_MAINTENANCE_MESSAGE;
		}
		
		
		
		if (config.getInitParameter("SendServerError") != null) {
		  sendServerError = config.getInitParameter("SendServerError").equalsIgnoreCase("TRUE");	
		}
		customErrorMessage = config.getInitParameter("CustomErrorMessage");

	}

        @Override
	public void respond(String status, HttpServletResponse resp) {
            resp.setContentType("text/plain");

            try (Writer out = resp.getWriter()) {
                if (status == null) {
                        // Return "EJBCAOK" Message
                        out.write(okMessage);
                } else {
                    if (customErrorMessage != null &&
                        customErrorMessage.length() > 0) {
                        status = customErrorMessage;
                    }

                    // Return failinfo
                    if (sendServerError) {
                        resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, status);
                    } else { 
                        out.write(status);
                    }
                }
                out.flush();
            } catch (IOException e) {
                    log.error("Error writing to Servlet Response.", e);
            }

	}

}
