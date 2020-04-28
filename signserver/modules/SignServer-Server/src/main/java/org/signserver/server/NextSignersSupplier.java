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
package org.signserver.server;

import java.util.List;
import org.signserver.common.SignServerException;

/**
 * Supplier of the current next signers.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface NextSignersSupplier {
    /**
     * @param services implementations to use
     * @return the current list of next signer instances
     * @throws SignServerException in case initialization of the crypto token
     * failed
     */
    List<IWorker> getCurrentNextSigners(final IServices services) throws SignServerException;
}
