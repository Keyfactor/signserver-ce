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
package org.signserver.server.signers;

/**
 * Worker not performing any operations on its own.
 * Meant as a placeholder for a crypto token to be referenced from an other 
 * worker.
 * @author Markus Kilås
 * @version $Id$
 */
public class CryptoWorker extends NullSigner {}
