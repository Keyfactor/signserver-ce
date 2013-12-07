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
package org.signserver.common.genericws;

/**
 * Class containing constants specific for the 
 * Generic WS parts.
 *
 * @author Philip Vendil 8 okt 2008
 * @version $Id$
 */
public class GenericWSConstants {

    /**
     * Setting used to have a custom implementation checking
     * if a generic WS service is functioning properly.
     * 
     * If set it should be set to the class path to a class
     * implementing org.signserver.server.genericws.IStatusChecker
     */
    public static final String STATUSCHECKER = "STATUSCHECKER";
    
    /**
     * Setting used to give a non default location of the
     * sun-jaxws.xml file, such as a location on the file system
     * (used primarily for tests)
     */
    public static final String SUNJAXWSLOCATION = "SUNJAXWSLOCATION";
}
