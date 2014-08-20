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
package org.signserver.admin.gui;

import java.util.Collection;

/**
 * Interface modelling query columns used in the
 * audit log and archive search query UI.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public interface QueryColumn {
   
    /**
     * Get column name, corresponding to database column name.
     * 
     * @return column name
     */
    public String getName();
    
    /**
     * Get column description to be shown in the UI.
     * 
     * @return column description
     */
    public String getDescription();
    
    public Type getType();
 
    /**
     * Give a list of possible discrete type values for a type column.
     * 
     * @return List of possible values
     * @throws IllegalArgumentException if called on a non-discrete column 
     */
    public Collection<String> getTypeValues() throws IllegalArgumentException;

    /**
     * Translate a presentation condition value (f.ex. RESPONSE, REQUEST)
     * into a form suitable for the hibernate query conditions (i.e. DB format)
     * 
     * @param value String representation in selection dialog
     * @return Object representation in DB
     */
    public String translateConditionValue(final String value);
    
    public enum Type {
        TEXT,
        NUMBER,
        TIME,
        TYPE
    }
}


