/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.server.integrityprotected;

/**
 * Get this node's next log row sequence number.
 * 
 * The sequence number is guaranteed to be unique as long as the read "node identifier"
 * read on first access is unique among the nodes sharing the database.
 * 
 * Based on Id: NodeSequenceHolder.java 24598 2016-10-31 11:34:40Z jeklund
 * @version $Id$
 */
public enum SequencialNodeSequenceHolder {
    INSTANCE;

    // We only want to use this from IntegrityProtectedDevice
    private SequencialNodeSequenceHolder() {}

    private String nodeId;
    private long startSequence;
    
    /** Interface for callback of methods that is invoked once. */
    public interface OnInitCallBack {
        /** @return the current node identifier */
        String getNodeId();
        /** @return the highest known sequence number for the node identifier returned by {@link OnInitCallBack#getNodeId()}*/
        long getMaxSequenceNumberForNode(String nodeId);
    }

    /** @return the node's next log row sequence number. */
    public long getStartSequence(final OnInitCallBack callBack) {
        if (nodeId == null) {
            nodeId = callBack.getNodeId();
            startSequence = callBack.getMaxSequenceNumberForNode(nodeId);
        }
        return startSequence;
    }

    /** @return the Node Identifier that this sequence number applies to. */
    public String getNodeId() {
        return nodeId;
    }

}
