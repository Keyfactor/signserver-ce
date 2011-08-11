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
package org.signserver.db;

import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import junit.framework.TestCase;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class MysqlClusterContinouslyTestSeparately extends TestCase {

    private static int count = 0;
    private final static String FILENAME_TEST_OUTPUT = "test_out.txt";

    protected void setUp() throws Exception {
        super.setUp();
    }

    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test connection to mysql cluster
     */
    public void test01Connection() throws Exception {
        Connection con = null;
        try {
            con = getConnection();

            assertTrue(!con.isClosed());

            con.close();
        } catch (Exception e) {
            throw e;
        } finally {
            try {
                if (con != null) {
                    con.close();
                }
            } catch (SQLException e) {
            }
        }
    }

    /**
     * Test clearing the entire table
     */
    public void test02ClearDB() throws Exception {
        Connection con = null;
        try {
            con = getConnection();
            PreparedStatement ps = con.prepareStatement("delete from ctest");

            // Execute query.
            ps.execute();

            ps = con.prepareStatement("select count(ctest.i) from test.ctest");
            ResultSet rs = ps.executeQuery();
            rs.next();

            assertTrue(rs.getInt(1) == 0);
        } catch (Exception e) {
            throw e;
        } finally {
            try {
                if (con != null) {
                    con.close();
                }
            } catch (SQLException e) {
            }
        }
    }

    /**
     * Test adding a row once a second
     */
    public void test03AddContinously() throws Exception {


        PrintWriter fw = null;
        try {
            fw = new PrintWriter(new FileOutputStream(FILENAME_TEST_OUTPUT));
            // Parameters
            while (true) {
                // Instance creation
                try {
                    addRow(fw);
                    checkCount(fw);

                } catch (Exception ef) {
                    // fw.write(ef.getMessage());	
                }
                // Various assertions

                fw.flush();

                Thread.sleep(500); // Sleep for a second
            }
        } catch (Exception e) {
            fw.write(e.getMessage());
        } finally {
            if (fw != null) {
                fw.close();
            }
        }
    }

    private void addRow(PrintWriter fw) throws Exception {
        Connection con = null;
        try {
            con = getConnection();

            fw.write("Addning i " + (count + 1) + "\n");

            String query = "insert ctest () values ( " + count + ")";

            PreparedStatement ps = con.prepareStatement(query);

            // Execute query.
            ps.execute();
            count++;




        } catch (Exception e) {
            throw e;
        } finally {
            try {
                if (con != null) {
                    con.close();
                }
            } catch (SQLException e) {
            }
        }
    }

    /**
     * Test that the current rowcount is correct.
     */
    private void checkCount(PrintWriter fw) throws Exception {
        Connection con = null;
        try {
            con = getConnection();

            PreparedStatement ps = con.prepareStatement("select count(ctest.i) from test.ctest");
            ResultSet rs = ps.executeQuery();
            rs.next();


            int dbcount = rs.getInt(1);

            fw.write("Count is " + dbcount + "=" + count + "\n");

            //assertTrue(dbcount == count);		  

        } catch (Exception e) {
            throw e;
        } finally {
            try {
                if (con != null) {
                    con.close();
                }
            } catch (SQLException e) {
            }
        }
    }

    private Connection getConnection() throws Exception {

        Connection con = null;

        Class.forName("com.mysql.jdbc.Driver").newInstance();

        DriverManager.setLoginTimeout(1);
        con = DriverManager.getConnection("jdbc:mysql://192.168.1.15,192.168.1.18/test?failOverReadOnly=false&autoReconnect=false&secondsBeforeRetryMaster=120&connectTimeout=1",
                "ejbca", "foo123");

        return con;
    }
}
