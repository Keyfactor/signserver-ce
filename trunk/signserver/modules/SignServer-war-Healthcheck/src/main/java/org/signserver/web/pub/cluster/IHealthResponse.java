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

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletResponse;


/**
 * Inteface used to generate apporiate responses to different LoadBalancers HTTP requests.
 * 
 * This interface was copied from the old EJBCA-util.
 * 
 * @author Philip Vendil
 * @version $Id: IHealthResponse.java 5585 2008-05-01 20:55:00Z anatom $
 */
public interface IHealthResponse {	
    /**
     * Method used to initialize the health checker responder with parameters
     * set in the web.xml file.
     *
     * @param config Servlet configuration
     */
    public void init(ServletConfig config);

    /**
     * Method in charge of creating a response to the loadbalancer that this
     * node in the cluster shouldn't be used.
     *
     * @param status, if status is null then everything is OK, othervise failure
     * with a errormessage that might be used in the reply.
     * @param resp the HttpServletResponse.
     */
    public void respond(String status, HttpServletResponse resp);

}
