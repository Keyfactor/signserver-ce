/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.timemonitor.common;

/**
 * Represents leap second state
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public enum LeapState {
   /**
    * No leap second is scheduled at the next possible leap second occurrence.
    */
   NONE,

   /**
    * A positive (extra) leap second is scheduled at the next possible occurrence.
    */
   POSITIVE,

   /**
    * A negative (removed) leap second is scheduled at the next possible occurrence.
    */
   NEGATIVE,

   /**
    * Leap second status is unknown.
    */
   UNKNOWN

}
