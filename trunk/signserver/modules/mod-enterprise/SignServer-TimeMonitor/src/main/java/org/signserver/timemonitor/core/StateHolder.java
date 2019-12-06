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

/**
 * Implementors of this interface are able to return the current states and
 * the last updated time.
 *
 * @author Markus Kilås
 * @version $Id: StateHolder.java 4569 2012-12-10 14:11:57Z marcus $
 */
public interface StateHolder {

    /**
     * @return The complete state of the TimeMonitor as one line in the state
     * format
     */
    StringBuilder getStateLine();
}
