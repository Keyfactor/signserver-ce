/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
