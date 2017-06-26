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
package org.signserver.test.random;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Worker ID and worker type pair.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class WorkerSpec {
    
    private static Pattern pattern;
    
    private int workerId;
    private WorkerType workerType;

    public WorkerSpec(int workerId, WorkerType workerType) {
        this.workerId = workerId;
        this.workerType = workerType;
    }

    public int getWorkerId() {
        return workerId;
    }

    public WorkerType getWorkerType() {
        return workerType;
    }
    
    public static WorkerSpec fromString(final String workerSpecString) throws IllegalArgumentException {
        final WorkerSpec result;
        final Matcher matcher = getPattern().matcher(workerSpecString);
        if (matcher.matches() && matcher.groupCount() == 2) {
            System.out.println("");
            final int workerId = Integer.parseInt(matcher.group(1));
            final WorkerType workerType = WorkerType.valueOf(matcher.group(2));
            result = new WorkerSpec(workerId, workerType);
            return result;
        } else {
            throw new IllegalArgumentException("Incorrect format for workerId/workerType: \"" + workerSpecString + "\"");
        }
    }
    
    private static Pattern getPattern() {
        if (pattern == null) {
            pattern = Pattern.compile("^([0-9]+)/([a-zA-Z]+)$");
        }
        return pattern;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final WorkerSpec other = (WorkerSpec) obj;
        if (this.workerId != other.workerId) {
            return false;
        }
        if (this.workerType != other.workerType) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 83 * hash + this.workerId;
        hash = 83 * hash + (this.workerType != null ? this.workerType.hashCode() : 0);
        return hash;
    }

    @Override
    public String toString() {
        return String.valueOf(workerId) + "/" + workerType.toString();
    }
        
}
