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
package org.signserver.module.pdfsigner;


import com.lowagie.text.pdf.PdfWriter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import junit.framework.TestCase;

import org.apache.log4j.Logger;

/**
 * Unit tests for Permissions.
 *
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class PermissionsUnitTest extends TestCase {

    /** Logger for this class. */
    public static final Logger LOG = Logger.getLogger(PermissionsUnitTest.class);
    

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public void testCustructingFromStrings() throws Exception {
        Set set1 = new HashSet(Arrays.asList("ALLOW_COPY", "ALLOW_SCREENREADERS", "_NON_EXISTING_PERM_"));
        Set set2 = new HashSet(Arrays.asList("ALLOW_COPY", "ALLOW_SCREENREADERS"));
        
        Permissions one = Permissions.fromSet(set1);
        LOG.debug("one: " + one);
        assertEquals(set2, one.asSet());
        assertEquals(PdfWriter.ALLOW_COPY + PdfWriter.ALLOW_SCREENREADERS, one.asInt());
        
        Permissions two = Permissions.fromSet(set1, false);
        LOG.debug("two: " + two);
        assertEquals(set2, two.asSet());
        assertEquals(PdfWriter.ALLOW_COPY + PdfWriter.ALLOW_SCREENREADERS, two.asInt());
        
        try {
            Permissions three = Permissions.fromSet(set1, true);
            LOG.debug("three: " + three);
            fail("Should have failed with UnknownPermissionException");
        } catch (UnknownPermissionException ignored) { // NOPMD
            // OK
        }        
    }
    
    public void testContainsAnyRejected() throws Exception {
        
        // Permissions: COPY, Reject: COPY
        Permissions copy = Permissions.fromSet(Arrays.asList("ALLOW_COPY"), true);
        assertTrue(copy.containsAnyOf(copy));
        
        // Permissions: COPY, SCREENREADERS
        Permissions copyScreenreaders = Permissions.fromSet(Arrays.asList("ALLOW_COPY", "ALLOW_SCREENREADERS"), true);
        Permissions screenreaders = Permissions.fromSet(Arrays.asList("ALLOW_SCREENREADERS"), true);
        Permissions assembly = Permissions.fromSet(Arrays.asList("ALLOW_ASSEMBLY"), true);
        Permissions assemblyScreenreaders = Permissions.fromSet(Arrays.asList("ALLOW_ASSEMBLY", "ALLOW_SCREENREADERS"), true);
        assertTrue(copyScreenreaders.containsAnyOf(copy));
        assertTrue(copyScreenreaders.containsAnyOf(screenreaders));
        assertFalse(copyScreenreaders.containsAnyOf(assembly));
        assertTrue(copyScreenreaders.containsAnyOf(assemblyScreenreaders));
        
        // Permissions: COPY, PRINTING
        Permissions copyPrinting = Permissions.fromSet(Arrays.asList("ALLOW_COPY", "ALLOW_PRINTING"), true);
        Permissions printing = Permissions.fromSet(Arrays.asList("ALLOW_PRINTING"), true);
        Permissions degradedPrinting = Permissions.fromSet(Arrays.asList("ALLOW_DEGRADED_PRINTING"), true);
        assertTrue(copyPrinting.containsAnyOf(printing));
        
        // Peermissions: COPY, DEGRADED_PRINTING
        Permissions copyDegradedPrinting = Permissions.fromSet(Arrays.asList("ALLOW_COPY", "ALLOW_DEGRADED_PRINTING"), true);
        assertTrue(copyDegradedPrinting.containsAnyOf(printing));
        assertTrue(copyDegradedPrinting.containsAnyOf(degradedPrinting));
    }

}
