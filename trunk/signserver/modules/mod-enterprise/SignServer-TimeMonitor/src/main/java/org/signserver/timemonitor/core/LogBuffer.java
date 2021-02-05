/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
