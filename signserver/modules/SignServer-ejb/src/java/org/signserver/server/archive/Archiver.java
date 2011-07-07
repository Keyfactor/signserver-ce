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
package org.signserver.server.archive;

import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;

/**
 * Archives ArchivableS.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public interface Archiver {

    void init(int listIndex, WorkerConfig config, SignServerContext context) throws ArchiverInitException;

    boolean archive(Archivable archivable, RequestContext requestContext) throws ArchiveException;
}
