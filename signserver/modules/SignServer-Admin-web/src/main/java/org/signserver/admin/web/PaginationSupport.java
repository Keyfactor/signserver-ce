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
package org.signserver.admin.web;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class PaginationSupport {

    private int maxEntries = 20;
    private int queryingToIndex;
    private boolean enableFirst;
    private boolean enablePrevious;
    private boolean enableNext;
    private int fromIndex;

    public int getFromIndex() {
        return fromIndex;
    }

    public void setFromIndex(int fromIndex) {
        this.fromIndex = Math.max(0, fromIndex);
    }

    public int getMaxEntries() {
        return maxEntries;
    }

    public void setMaxEntries(int maxEntries) {
        this.maxEntries = Math.max(1, maxEntries);
    }

    public Integer getQueryingToIndex() {
        return queryingToIndex;
    }

    public boolean isEnableFirst() {
        return enableFirst;
    }

    public boolean isEnablePrevious() {
        return enablePrevious;
    }

    public boolean isEnableNext() {
        return enableNext;
    }

    public void goToFirst() {
        fromIndex = 0;
    }

    public void goBackwards() {
        // Step backwards
        int index = fromIndex - maxEntries;
        if (index < 0) {
            index = 0;
        }
        fromIndex = index;
    }

    public void goForward() {
        // Step forward
        final int index = fromIndex + maxEntries;
        fromIndex = index;
    }

    public void updateResults(int size, Boolean moreAvailable) {
        if (size < 1) {
            queryingToIndex = fromIndex + maxEntries; // We pretend we got all entries
            enableNext = false;
        } else {
            queryingToIndex = fromIndex + size;
            enableNext = (moreAvailable != null && moreAvailable) || (moreAvailable == null && size >= maxEntries);
        }

        enableFirst = enablePrevious = fromIndex > 0;
    }

}
