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
package org.signserver.timemonitor.core;

import java.util.Iterator;
import org.apache.commons.collections.buffer.CircularFifoBuffer;

/**
 * Fixed size buffer of log entries.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class LogBuffer {
    private final CircularFifoBuffer buffer;

    public LogBuffer(final int size) {
        this.buffer = new CircularFifoBuffer(size);
    }

    public void add(final String entry) {
        buffer.add(entry);
    }

    public Iterator<String> iterator() {
        return buffer.iterator();
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("Log entries:\n");
        final Iterator iterator = buffer.iterator();
        while (iterator.hasNext()) {
            sb.append("   ").append(iterator.next()).append("\n");
        }
        return sb.toString();
    }

}
