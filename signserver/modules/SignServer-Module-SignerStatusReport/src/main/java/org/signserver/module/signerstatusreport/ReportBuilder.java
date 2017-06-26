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
package org.signserver.module.signerstatusreport;

/**
 * Capable of constructing an report.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public interface ReportBuilder {

    /**
     * @return The newly produced report
     */
    CharSequence buildReport();
    
}
