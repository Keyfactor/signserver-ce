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
 * Exception thrown to indicate that a property with the requested name does 
 * not exist.
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
     * <code>NoSuchPropertyException</code> with the specified property.
     *
     * @param property Property that the exception corresponds to
     */
    public NoSuchPropertyException(String property) {
        super("No such property: " + property);
        this.property = property;
    }

    /**
     * Construct an instance of
     * <code>NoSuchPropertyException</code> with the specified property and detailed message.
     * 
     * @param property Property that the exception corresponds to
     * @param message Detailed message
     */
    public NoSuchPropertyException(String property, String message) {
        super(message);
        this.property = property;
    }

    /**
     * @return The non-existing requested property name
     */
    public String getProperty() {
        return property;
    }
    
}
