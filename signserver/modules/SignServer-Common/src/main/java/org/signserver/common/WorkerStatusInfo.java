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

    /**
     * Constructs a new instance of WorkerStatusInfo with information about a
     * worker.
     * @param workerId id of the worker
     * @param workerName name of the worker
     * @param workerType type of worker, such as "Signer", "Dispatcher" or just
     * "Worker" etc
     * @param tokenStatus status of the worker
     * @param briefEntries list of shorter, typically one line entries
     * @param fatalErrors list of fatal errors
     * @param completeEntries list of longer, possibly multi line entries
     * @param workerConfig the worker configuration
     * @see WorkerStatus#STATUS_ACTIVE
     * @see WorkerStatus#STATUS_OFFLINE
     */
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

    /**
     * @return id of the worker
     */
    public int getWorkerId() {
        return workerId;
    }

    /**
     * @return name of the worker
     */
    public String getWorkerName() {
        return workerName;
    }

    /**
     * @return type of worker, such as "Signer", "Dispatcher" or just
     * "Worker" etc
     */
    public String getWorkerType() {
        return workerType;
    }

    /**
     * @return list of shorter, typically one line entries
     */
    public List<Entry> getBriefEntries() {
        return briefEntries;
    }

    /**
     * @return list of fatal errors
     */
    public List<String> getFatalErrors() {
        return fatalErrors;
    }

    /**
     * @return list of longer, possibly multi line entries
     */
    public List<Entry> getCompleteEntries() {
        return completeEntries;
    }

    /**
     * @return the worker configuration
     */
    public WorkerConfig getWorkerConfig() {
        return workerConfig;
    }

    /**
     * @return status of the worker
     * @see WorkerStatus#STATUS_ACTIVE
     * @see WorkerStatus#STATUS_OFFLINE
     */
    public int getTokenStatus() {
        return tokenStatus;
    }

    /**
     * Holder for a status entry with a title and a value.
     */
    public static class Entry implements Serializable {

        private static final long serialVersionUID = 1L;

        private final String title;
        private final String value;

        /**
         * Constructs a new status entry.
         * @param title for this entry
         * @param value for this entry
         */
        public Entry(String title, String value) {
            this.title = title;
            this.value = value;
        }

        /**
         * @return the title
         */
        public String getTitle() {
            return title;
        }

        /**
         * @return the value
         */
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
