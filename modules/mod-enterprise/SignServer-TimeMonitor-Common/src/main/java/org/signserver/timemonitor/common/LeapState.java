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
package org.signserver.timemonitor.common;

/**
 * Represents leap second state
 * 
 * @author Marcus Lundblad
 * @version $Id: LeapState.java 4502 2012-12-03 15:06:36Z marcus $
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
