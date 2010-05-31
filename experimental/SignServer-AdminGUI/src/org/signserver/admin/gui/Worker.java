/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.signserver.admin.gui;

/**
 *
 * @author markus
 */
public class Worker {

    private int workerId;
    private String name;
    private String statusSummary;
    private Object[][] statusProperties;
    private Object[][] configurationProperties;
    private boolean active;

    public Worker(int workerId, String name, String statusSummary,
            final Object[][] statusProperties,
            final Object[][] configurationProperties,
            final boolean active) {
        this.workerId = workerId;
        this.name = name;
        this.statusSummary = statusSummary;
        this.statusProperties = statusProperties;
        this.configurationProperties = configurationProperties;
        this.active = active;
    }

    public String getName() {
        return name;
    }

    public int getWorkerId() {
        return workerId;
    }

    public String getStatusSummary() {
        return statusSummary;
    }

    public Object[][] getStatusProperties() {
        return statusProperties;
    }

    public Object[][] getConfigurationProperties() {
        return configurationProperties;
    }

    public boolean isActive() {
        return active;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Worker other = (Worker) obj;
        if (this.workerId != other.workerId) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 47 * hash + this.workerId;
        return hash;
    }

    @Override
    public String toString() {
        return "Worker[" + getName() + ", " + getWorkerId() + "]";
    }



}
