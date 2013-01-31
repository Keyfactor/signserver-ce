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

import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;

import junit.framework.TestCase;

/**
 * Tests the query parser.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */

public class QueryAuditLogTest extends TestCase {

    public void test01ParseCriteria() throws Exception {
        final String criteria = "customId EQ 1";
        final Term term = QueryAuditLogCommand.parseCriteria(criteria);
        
        assertEquals("Operation", RelationalOperator.EQ, term.getOperator());
        assertEquals("Name", AuditRecordData.FIELD_CUSTOM_ID, term.getName());
        assertEquals("Value", "1", term.getValue());
    }
    
}
