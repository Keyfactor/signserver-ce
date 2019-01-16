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
package org.signserver.module.onetime.caconnector;

/**
 * Exception representing CA connector errors.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class CAException extends Exception {

    private static final long serialVersionUID = 1L;

    public CAException(String message) {
        super(message);
    }

    public CAException(String message, Throwable cause) {
        super(message, cause);
    }
    
    public CAException(Exception ex) {
        super(ex);
    }
}
