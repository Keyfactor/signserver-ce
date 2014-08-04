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
package org.signserver.admin.cli.defaultimpl.auditlog;

import java.text.ParseException;
import java.util.Collections;

import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import org.signserver.admin.cli.AdminCLIUtils;

import junit.framework.TestCase;

/**
 * Tests the query parser.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */

public class QueryAuditLogTest extends TestCase {

    private Term parseCriteria(final String criteria) throws ParseException {
        return AdminCLIUtils.parseCriteria(criteria, QueryAuditLogCommand.allowedFields,
                QueryAuditLogCommand.noArgOps, Collections.<String>emptySet(), 
                QueryAuditLogCommand.longFields, QueryAuditLogCommand.dateFields);
    }
    
    /**
     * Test with a valid criteria.
     * @throws Exception
     */
    public void test01ParseCriteria() throws Exception {
        final String criteria = "customId EQ 1";
        final Term term = parseCriteria(criteria);
                
        
        assertEquals("Operation", RelationalOperator.EQ, term.getOperator());
        assertEquals("Name", AuditRecordData.FIELD_CUSTOM_ID, term.getName());
        assertEquals("Value", "1", term.getValue());
    }
    
    /**
     * Test that a non-existing operator isn't accepted.
     * @throws Exception
     */
    public void test02ParseCriteriaInvalidOperator() throws Exception {
        final String criteria = "customId FOO 1";
        
        try {
            final Term term = parseCriteria(criteria);
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
        final String criteria = "customId BETWEEN 1";
        
        try {
            final Term term = parseCriteria(criteria);
            fail("Should throw an IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
    
    /**
     * Test that using numerical field yields a Long value (otherwise hibernate will get upset...)
     * @throws Exception
     */
    public void test04ParseCriteriaNumericValue() throws Exception {
        final String criteria = "sequenceNumber GT 1";
        final Term term = parseCriteria(criteria);
        
        assertEquals("Operation", RelationalOperator.GT, term.getOperator());
        assertEquals("Name", AuditRecordData.FIELD_SEQUENCENUMBER, term.getName());
        assertEquals("Value", Long.valueOf(1), term.getValue());
    }
    
    /**
     * Test the NULL operator.
     */
    public void test05ParseCriteriaNull() throws Exception {
        final String criteria = "searchDetail2 NULL";
        final Term term = parseCriteria(criteria);
        
        assertEquals("Operation", RelationalOperator.NULL, term.getOperator());
        assertEquals("Name", AuditRecordData.FIELD_SEARCHABLE_DETAIL2, term.getName());
        assertNull("Value", term.getValue());
    }
    
    /**
     * Test that setting a non-numeric value for a numeric field fails.
     * @throws Exception
     */
    public void test06ParseCriteriaInvalidValue() throws Exception {
        final String criteria = "sequenceNumber EQ foo";
        
        try {
            final Term term = parseCriteria(criteria);
            fail("Should throw a NumberFormatException");
        } catch (NumberFormatException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpect exception: " + e.getClass().getName());
        }
    }
    
    public void test07ParseCriteriaWithoutValue() throws Exception {
        final String criteria = "authToken EQ";
        
        try {
            final Term term = parseCriteria(criteria);
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
            final Term term = parseCriteria(criteria);
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
        final String criteria = "timeStamp EQ 1234567890";
        final Term term = parseCriteria(criteria);
        
        assertEquals("Operation", RelationalOperator.EQ, term.getOperator());
        assertEquals("Name", AuditRecordData.FIELD_TIMESTAMP, term.getName());
        assertEquals("Value", Long.valueOf(1234567890), term.getValue());
    }
    
    /**
     * Test that parsing a date criteria using an ISO format date works.
     * @throws Exception
     */
    public void test10DateISO() throws Exception {
        final String criteria = "timeStamp EQ 2013-02-11 14:00:00+0100";
        final Term term = parseCriteria(criteria);
        
        assertEquals("Operation", RelationalOperator.EQ, term.getOperator());
        assertEquals("Name", AuditRecordData.FIELD_TIMESTAMP, term.getName());
        assertEquals("Value", Long.valueOf(1360587600000L), term.getValue()); 
    }
    
    public void test11DateInvalid() throws Exception {
        final String criteria = "timeStamp EQ foobar";
        
        try {
            final Term term = parseCriteria(criteria);
        } catch (ParseException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
}
