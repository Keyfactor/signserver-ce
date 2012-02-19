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
package org.signserver.statusrepo.common;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class NoSuchPropertyException extends Exception {

    private String property;
    
    /**
     * Creates a new instance of
     * <code>NoSuchPropertyException</code> without detail message.
     */
    public NoSuchPropertyException() {
    }

    /**
     * Constructs an instance of
     * <code>NoSuchPropertyException</code> with the specified detail message.
     *
     * @param msg the detail message.
     */
    public NoSuchPropertyException(String property) {
        super("No such property: " + property);
        this.property = property;
    }

    public NoSuchPropertyException(String property, String message) {
        super(message);
        this.property = property;
    }

    public String getProperty() {
        return property;
    }
    
}
