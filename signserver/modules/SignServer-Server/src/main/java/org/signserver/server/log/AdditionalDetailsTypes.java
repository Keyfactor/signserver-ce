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
package org.signserver.server.log;

/**
 * Different types of additional details log fields that can be added to the
 * system log.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public enum AdditionalDetailsTypes {
    
    SCOPE,
    NODE,
    
    ERROR,
    SUCCESS,
    
    KEYALIAS,
    KEYALG,
    KEYSPEC,
    
    /**
     * If the "default key" was requested.
     */
    FOR_DEFAULTKEY,
    
    /**
     * The configured crypto token, or if none configured the name of the worker
     * involved or its worker ID.
     */
    CRYPTOTOKEN,

    TESTRESULTS,
    
    CERTIFICATE,
    CERTIFICATECHAIN,
    
    CSR, 

}
