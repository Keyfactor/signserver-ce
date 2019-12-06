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

import javax.persistence.EntityManager;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;


/**
 * Inteface used for health polling purposes to see that everything is alive and ok.
 * 
 * This interface was copied from the old EJBCA-util.
 * 
 * @author Philip Vendil
 * @version $Id: IHealthCheck.java 5585 2008-05-01 20:55:00Z anatom $
 */
public interface IHealthCheck {	
    /**
     * Method used to initialize the health checker with parameters set in the
     * web.xml file.
     *
     * @param config Servlet configuration
     * @param em Entity managaer
     */
    void init(ServletConfig config, EntityManager em);

    /**
     * Method used to check the health of a specific application.
     *
     * @param request Servlet request
     * @return Null if everyting is OK, othervise it should return a String as
     * errormessage.
     */
    public String checkHealth(HttpServletRequest request);

}
