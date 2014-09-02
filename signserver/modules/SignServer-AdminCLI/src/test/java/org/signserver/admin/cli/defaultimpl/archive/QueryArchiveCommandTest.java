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
package org.signserver.admin.cli.defaultimpl.archive;

import java.text.ParseException;

import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import org.signserver.common.ArchiveMetadata;

import junit.framework.TestCase;

/**
 * Test the archive query parser.
 * 
 * @author Marcus Lundblad
 * @version $Id: QueryArchiveTest.java 4986 2014-08-19 06:32:54Z malu9369 $
 *
 */
public class QueryArchiveCommandTest extends TestCase {
    /**
     * Test with a valid criteria.
     * @throws Exception
     */
    public void test01ParseCriteria() throws Exception {
        final String criteria = "archiveid EQ 1";
        final Term term = QueryArchiveCommand.parseCriteria(criteria);
        
        assertEquals("Operation", RelationalOperator.EQ, term.getOperator());
        assertEquals("Name", ArchiveMetadata.ARCHIVE_ID, term.getName());
        assertEquals("Value", "1", term.getValue());
    }
    
    /**
     * Test that a non-existing operator isn't accepted.
     * @throws Exception
     */
    public void test02ParseCriteriaInvalidOperator() throws Exception {
        final String criteria = "signerid FOO 1";
        
        try {
            QueryArchiveCommand.parseCriteria(criteria);
            fail("Should throw an IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }

    /**
     * Test that the BETWEEN operator is properly rejected.
     * @throws Exception
     */
    public void test03ParseCriteriaBetween() throws Exception {
        final String criteria = "signerid BETWEEN 1";
        
        try {
            QueryArchiveCommand.parseCriteria(criteria);
            fail("Should throw an IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
    
    /**
     * Test that using numerical field yields an Integer value (otherwise hibernate will get upset...)
     * @throws Exception
     */
    public void test04ParseCriteriaNumericValue() throws Exception {
        final String criteria = "signerid GT 1";
        final Term term = QueryArchiveCommand.parseCriteria(criteria);
        
        assertEquals("Operation", RelationalOperator.GT, term.getOperator());
        assertEquals("Name", ArchiveMetadata.SIGNER_ID, term.getName());
        assertEquals("Value", Integer.valueOf(1), term.getValue());
    }
    
    /**
     * Test the NULL operator.
     */
    public void test05ParseCriteriaNull() throws Exception {
        final String criteria = "requestCertSerialnumber NULL";
        final Term term = QueryArchiveCommand.parseCriteria(criteria);
        
        assertEquals("Operation", RelationalOperator.NULL, term.getOperator());
        assertEquals("Name", ArchiveMetadata.REQUEST_CERT_SERIAL_NUMBER, term.getName());
        assertNull("Value", term.getValue());
    }
    
    /**
     * Test that setting a non-numeric value for a numeric field fails.
     * @throws Exception
     */
    public void test06ParseCriteriaInvalidValue() throws Exception {
        final String criteria = "signerid EQ foo";
        
        try {
            QueryArchiveCommand.parseCriteria(criteria);
            fail("Should throw a NumberFormatException");
        } catch (NumberFormatException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpect exception: " + e.getClass().getName());
        }
    }
    
    public void test07ParseCriteriaWithoutValue() throws Exception {
        final String criteria = "signerid EQ";
        
        try {
            QueryArchiveCommand.parseCriteria(criteria);
            fail("Should throw an IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
    
    /**
     * Test that using an invalid field name is rejected.
     * @throws Exception
     */
    public void test08ParseCriteriaInvalidField() throws Exception {
        final String criteria = "dummyField EQ 0";
        
        try {
            QueryArchiveCommand.parseCriteria(criteria);
            fail("Should throw an IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
    
    /**
     * Test that parsing a criteria with a millisecond time stamp works.
     * @throws Exception
     */
    public void test09DateMilliseconds() throws Exception {
        final String criteria = "time EQ 1234567890";
        final Term term = QueryArchiveCommand.parseCriteria(criteria);
        
        assertEquals("Operation", RelationalOperator.EQ, term.getOperator());
        assertEquals("Name", ArchiveMetadata.TIME, term.getName());
        assertEquals("Value", Long.valueOf(1234567890), term.getValue());
    }
    
    /**
     * Test that parsing a date criteria using an ISO format date works.
     * @throws Exception
     */
    public void test10DateISO() throws Exception {
        final String criteria = "time EQ 2013-02-11 14:00:00+0100";
        final Term term = QueryArchiveCommand.parseCriteria(criteria);
        
        assertEquals("Operation", RelationalOperator.EQ, term.getOperator());
        assertEquals("Name", ArchiveMetadata.TIME, term.getName());
        assertEquals("Value", Long.valueOf(1360587600000L), term.getValue()); 
    }
    
    public void test11DateInvalid() throws Exception {
        final String criteria = "time EQ foobar";
        
        try {
            QueryArchiveCommand.parseCriteria(criteria);
        } catch (ParseException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
}
