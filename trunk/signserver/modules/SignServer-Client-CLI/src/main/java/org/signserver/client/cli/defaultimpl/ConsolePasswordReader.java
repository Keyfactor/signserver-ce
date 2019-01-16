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
package org.signserver.client.cli.defaultimpl;

import org.signserver.cli.spi.CommandFailureException;

/**
 * Interface providing facilities for reading a password.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public interface ConsolePasswordReader {
    char[] readPassword() throws CommandFailureException;
}
