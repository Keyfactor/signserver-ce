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
package org.signserver.admin.web.ejb;

import org.signserver.admin.common.auth.AdminNotAuthorizedException;

/**
 *
 * @author Markus Kilås
 * @version $Id: NotLoggedInException.java 7635 2016-12-21 16:08:26Z netmackan $
 */
public class NotLoggedInException extends AdminNotAuthorizedException {

    /** serialVersionUID for this class. */
    private static final long serialVersionUID = 1;

    public NotLoggedInException(String message, Throwable cause) {
        super(message, cause);
    }

    public NotLoggedInException(String message) {
        super(message);
    }

    public NotLoggedInException() {
    }
    
}
