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
package org.signserver.common;

import java.io.Serializable;

/**
 * Identifier for a worker: either ID or name.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class WorkerIdentifier implements Serializable {

    private static final long serialVersionUID = 0L;

    private final Integer id;
    private final String name;

    public static WorkerIdentifier createFromIdOrName(String idOrName) {
        WorkerIdentifier result;
        try {
            // Try as int
            result = new WorkerIdentifier(Integer.parseInt(idOrName));
        } catch (NumberFormatException ignored) { // NOPMD
            // Otherwise it is a name
            result = new WorkerIdentifier(idOrName);
        }
        return result;
    }
    
    public WorkerIdentifier(Integer id, String name) {
        this.id = id;
        this.name = name;
    }

    public WorkerIdentifier(Integer id) {
        this.id = id;
        this.name = null;
    }

    public WorkerIdentifier(String name) {
        this.id = null;
        this.name = name;
    }

    public Integer getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public boolean hasId() {
        return id != null;
    }

    public boolean hasName() {
        return name != null;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("Worker{");
        if (id != null) {
            sb.append("id: ").append(id);
        }
        if (name != null) {
            if (id != null) {
                sb.append(", ");
            }
            sb.append("name: ").append(name);
        }
        sb.append("}");
        return sb.toString();
    }

}
