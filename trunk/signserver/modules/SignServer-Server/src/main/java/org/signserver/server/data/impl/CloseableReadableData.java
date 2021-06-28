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
package org.signserver.server.data.impl;

import org.signserver.common.data.ReadableData;

/**
 * Represents a writable data that it also auto closable and can thus be used
 * in a try-with-resources clause.
 * 
 * This class is intended to be used by the Servlet (or WS) implementation
 * to handle the response data in order for it to be properly cleaned up (i.e.
 * any temporary response file being removed).
 * 
 * @author Markus Kilås
 * @version $Id$
 * @see CloseableWritableData
 */
public abstract class CloseableReadableData extends ResourcesAutoCloseable implements ReadableData {
}
