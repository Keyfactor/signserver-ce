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
package org.signserver.healthcheck;

import java.sql.Connection;
import java.sql.Statement;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.util.JDBCUtil;

/**
 * Utility methods related to the Healt check functionality.
 * 
 * @version $Id$
 */
public class HealthCheckUtils {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(HealthCheckUtils.class);

    public static String checkMemory(int minfreememory) {
        String retval = "";
        if (minfreememory >= Runtime.getRuntime().freeMemory()) {
            retval = "\nError Virtual Memory is about to run out, currently free memory :" + Runtime.getRuntime().freeMemory();
        }

        return retval;
    }

    public static String checkDB(String checkDBString) {
        String retval = "";
        Connection con = null;
        try {
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            Statement statement = con.createStatement();
            statement.execute(checkDBString);
            statement.close();
        } catch (Exception e) {
            retval = "\nError creating connection to SignServer Database.";
            LOG.error("Error creating connection to SignServer Database.", e);
        } finally {
            JDBCUtil.close(con);
        }
        return retval;
    }
}
