/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.common;

import java.io.Serializable;

/**
 *
 * @author user
 */
public class WorkerIdentifier implements Serializable {

    private static final long serialVersionUID = 0L;

    private final Integer id;
    private final String name;

    public static WorkerIdentifier createFromIdOrName(String idOrName) {
        final WorkerIdentifier result;
        Integer id = null;
        try {
            id = Integer.parseInt(idOrName);
        } catch (NumberFormatException ignored) {} // NOPMD
        if (id == null) {
            result = new WorkerIdentifier(idOrName);
        } else {
            result = new WorkerIdentifier(id);
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
