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
 * Implementation of Loggable that logs the string value (using String.valueOf())
 * of a stored instance when evaluation of the log message occurs.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 * @param <T> Type parameter
 */
public class StringValueLoggable<T> implements Loggable {
    final T value;
    
    public StringValueLoggable(T value) {
        this.value = value;
    }
    
    @Override
    public String logValue() {
        return String.valueOf((Object) value);
    }
}
