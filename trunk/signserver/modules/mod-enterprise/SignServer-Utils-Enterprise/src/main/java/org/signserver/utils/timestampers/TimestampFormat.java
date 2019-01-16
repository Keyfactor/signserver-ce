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
package org.signserver.utils.timestampers;

/**
 * Timestamp formats.
 * 
 * Currently Authenticode and RFC#3161
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public enum TimestampFormat {
    AUTHENTICODE,
    RFC3161
}
