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
public class SimpleMysqlClusterTestSeparately extends TestCase {

    private static int count = 0;

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
     * Test adding a row of the maximum count to the database.
     */
    public void test03AddRow() throws Exception {
        Connection con = null;
        try {
            con = getConnection();

            String query = "insert ctest () values ( " + count + ")";

            PreparedStatement ps = con.prepareStatement(query);

            // Execute query.
            ps.execute();

            ps = con.prepareStatement("select ctest.i from ctest where i = ?");
            ps.setInt(1, count);
            ResultSet rs = ps.executeQuery();
            rs.next();

            assertTrue(rs.getInt(1) == count);

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
    public void test04CheckCount() throws Exception {
        Connection con = null;
        try {
            con = getConnection();

            PreparedStatement ps = con.prepareStatement("select count(ctest.i) from test.ctest");
            ResultSet rs = ps.executeQuery();
            rs.next();

            assertTrue(rs.getInt(1) == 1);

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

        DriverManager.setLoginTimeout(3);
        con = DriverManager.getConnection("jdbc:mysql://192.168.1.15,192.168.1.18/test?autoReconnect=true&failOverReadOnly=false&roundRobinLoadBalance=true",
                "ejbca", "foo123");

        return con;
    }
}
