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
package org.signserver.timemonitor.ntp;

/**
 * Holder for the results from an NTPDateCommand execution.
 *
 * @author Markus Kilås
 * @version $Id: NTPDateResult.java 4514 2012-12-05 14:29:16Z marcus $
 */
public class NTPDateResult extends AbstractResult {

    private final String server;
    private final int stratum;
    private final double offset;
    private final double delay;
    private final boolean rateLimited;
    
    /**
     * Creates an new instance of NTPDateResult.
     * @param exitCode The exitCode.
     * @param errorMessage The errorMessage (if any)
     * @param server The server host
     * @param stratum The stratum
     * @param offset The time offset
     * @param delay The delay
     * @param rateLimited If the server has responded with a rate-limit response
     */
    public NTPDateResult(int exitCode, String errorMessage, String server,
            int stratum, double offset, double delay, boolean rateLimited) {
        super(exitCode, errorMessage);
        this.server = server;
        this.stratum = stratum;
        this.offset = offset;
        this.delay = delay;
        this.rateLimited = rateLimited;
    }

    public double getDelay() {
        return delay;
    }

    public double getOffset() {
        return offset;
    }

    public String getServer() {
        return server;
    }

    public int getStratum() {
        return stratum;
    }

    public boolean isRateLimited() {
        return rateLimited;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 47 * hash + (this.server != null ? this.server.hashCode() : 0);
        hash = 47 * hash + this.exitCode;
        hash = 47 * hash + this.stratum;
        hash = 47 * hash + (int) (Double.doubleToLongBits(this.offset) ^ (Double.doubleToLongBits(this.offset) >>> 32));
        hash = 47 * hash + (int) (Double.doubleToLongBits(this.delay) ^ (Double.doubleToLongBits(this.delay) >>> 32));
        hash = 47 * hash + (this.rateLimited ? 1 : 0);
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
        final NTPDateResult other = (NTPDateResult) obj;
        if ((this.server == null) ? (other.server != null) : !this.server.equals(other.server)) {
            return false;
        }
        if (this.exitCode != other.exitCode) {
            return false;
        }
        if (this.stratum != other.stratum) {
            return false;
        }
        if (Double.doubleToLongBits(this.offset) != Double.doubleToLongBits(other.offset)) {
            return false;
        }
        if (Double.doubleToLongBits(this.delay) != Double.doubleToLongBits(other.delay)) {
            return false;
        }
        if (this.rateLimited != other.rateLimited) {
            return false;
        }
        return true;
    }
    
    
    
    @Override
    public String toString() {
        return "NTPDateResult{" + "exitCode=" + exitCode + ", errorMessage=" + errorMessage + ", server=" + server + ", stratum=" + stratum + ", offset=" + offset + ", delay=" + delay + '}';
    }

}
