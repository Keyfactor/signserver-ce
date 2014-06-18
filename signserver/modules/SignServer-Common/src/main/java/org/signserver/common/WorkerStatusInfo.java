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
import java.util.List;

/**
 * Status information for a worker.
 *
 * Contains some basic information about the worker, its configuration as well
 * as a list of brief status entries and longer ("complete") entries.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class WorkerStatusInfo implements Serializable {

    private static final long serialVersionUID = 1L;

    private final int workerId;
    private final String workerName;
    private final String workerType;
    private final int tokenStatus;
    private final List<Entry> briefEntries;
    private final List<String> fatalErrors;
    private final List<Entry> completeEntries;
    private final WorkerConfig workerConfig;

    public WorkerStatusInfo(int workerId, String workerName, String workerType, int tokenStatus, List<Entry> briefEntries, List<String> fatalErrors, List<Entry> completeEntries, WorkerConfig workerConfig) {
        this.workerId = workerId;
        this.workerName = workerName;
        this.workerType = workerType;
        this.tokenStatus = tokenStatus;
        this.briefEntries = briefEntries;
        this.fatalErrors = fatalErrors;
        this.completeEntries = completeEntries;
        this.workerConfig = workerConfig;
    }

    public static long getSerialVersionUID() {
        return serialVersionUID;
    }

    public int getWorkerId() {
        return workerId;
    }

    public String getWorkerName() {
        return workerName;
    }

    public String getWorkerType() {
        return workerType;
    }

    public List<Entry> getBriefEntries() {
        return briefEntries;
    }

    public List<String> getFatalErrors() {
        return fatalErrors;
    }

    public List<Entry> getCompleteEntries() {
        return completeEntries;
    }

    public WorkerConfig getWorkerConfig() {
        return workerConfig;
    }

    public int getTokenStatus() {
        return tokenStatus;
    }

    public static class Entry implements Serializable {

        private static final long serialVersionUID = 1L;

        private final String title;
        private final String value;

        public Entry(String title, String value) {
            this.title = title;
            this.value = value;
        }

        public String getTitle() {
            return title;
        }

        public String getValue() {
            return value;
        }

        @Override
        public int hashCode() {
            int hash = 7;
            hash = 41 * hash + (this.title != null ? this.title.hashCode() : 0);
            hash = 41 * hash + (this.value != null ? this.value.hashCode() : 0);
            return hash;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final Entry other = (Entry) obj;
            if ((this.title == null) ? (other.title != null) : !this.title.equals(other.title)) {
                return false;
            }
            if ((this.value == null) ? (other.value != null) : !this.value.equals(other.value)) {
                return false;
            }
            return true;
        }
    }
}
