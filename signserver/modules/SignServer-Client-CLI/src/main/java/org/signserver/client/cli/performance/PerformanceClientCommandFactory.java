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
package org.signserver.client.cli.performance;

import org.signserver.cli.spi.AbstractCommandFactory;
import org.signserver.client.cli.spi.ClientCommandFactory;

/**
 * CommandFactory for the performance client.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class PerformanceClientCommandFactory extends AbstractCommandFactory implements ClientCommandFactory {

    @Override
    protected void registerCommands() {
        // Top level commands
        put("pdfperformancetest", PDFPerformanceCommand.class);
    }

}
