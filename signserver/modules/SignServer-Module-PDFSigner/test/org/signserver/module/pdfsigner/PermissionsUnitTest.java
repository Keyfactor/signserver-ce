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
import java.util.LinkedList;
import java.util.Set;
import junit.framework.TestCase;

import org.apache.log4j.Logger;

/**
 * Unit tests for Permissions.
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

    /**
     * Tests getting Permissions instances from collections of permission 
     * strings.
     */
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
    
    /**
     * Getting the permissions as a set of permission strings.
     */
    public void testToSet() throws Exception {
        
        Permissions degradedPrinting = Permissions.fromInt(4);
        assertEquals(Arrays.asList("ALLOW_DEGRADED_PRINTING").toString(), degradedPrinting.asSet().toString());
        
        Permissions copyScreenreaders = Permissions.fromInt(528);
        assertEquals(new HashSet(Arrays.asList("ALLOW_COPY", "ALLOW_SCREENREADERS")), copyScreenreaders.asSet());
        
        Permissions printingDegradedPrinting = Permissions.fromInt(2052);
        LOG.debug("printingDegradedPrinting: " + printingDegradedPrinting);
        assertEquals(new HashSet(Arrays.asList("ALLOW_PRINTING", "ALLOW_DEGRADED_PRINTING")), printingDegradedPrinting.asSet());
    }
    
    /**
     * Tests the method checking of the Permissions contains any of the supplied 
     * permissions.
     */
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
        
        // Permissions: DEGRADED_PRINTING, PRINTING
        Permissions printingDegradedPrinting = Permissions.fromSet(Arrays.asList("ALLOW_PRINTING", "ALLOW_DEGRADED_PRINTING"), true);
        LOG.debug("printingDegradedPrinting: " + printingDegradedPrinting);
        assertTrue(printingDegradedPrinting.containsAnyOf(printing));
        assertTrue(printingDegradedPrinting.containsAnyOf(degradedPrinting));
    }

    /**
     * Tests the methods returning a new/different Permissions object with the 
     * same permissions as the original one but with the supplied permissions
     * removed.
     */
    public void testWithRemovedPermissions() throws Exception {
        
        Permissions all = Permissions.fromSet(Arrays.asList("ALLOW_PRINTING", "ALLOW_MODIFY_CONTENTS", "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_SCREENREADERS", "ALLOW_ASSEMBLY", "ALLOW_DEGRADED_PRINTING"), true);
        
        Permissions a1 = all.withRemoved(Arrays.asList("ALLOW_ASSEMBLY"));
        Permissions e1 = Permissions.fromSet(Arrays.asList("ALLOW_PRINTING", "ALLOW_MODIFY_CONTENTS", "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_SCREENREADERS", "ALLOW_DEGRADED_PRINTING"), true);
        assertEquals(e1, a1);
        
        Permissions a2 = a1.withRemoved(Arrays.asList("ALLOW_COPY"));
        Permissions e2 = Permissions.fromSet(Arrays.asList("ALLOW_PRINTING", "ALLOW_MODIFY_CONTENTS", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_SCREENREADERS", "ALLOW_DEGRADED_PRINTING"), true);
        assertEquals(e2, a2);
        
        Permissions a3 = a2.withRemoved(Arrays.asList("ALLOW_MODIFY_ANNOTATIONS"));
        Permissions e3 = Permissions.fromSet(Arrays.asList("ALLOW_PRINTING", "ALLOW_MODIFY_CONTENTS", "ALLOW_FILL_IN", "ALLOW_SCREENREADERS", "ALLOW_DEGRADED_PRINTING"), true);
        assertEquals(e3, a3);
        
        Permissions a4 = a3.withRemoved(Arrays.asList("ALLOW_SCREENREADERS"));
        Permissions e4 = Permissions.fromSet(Arrays.asList("ALLOW_PRINTING", "ALLOW_MODIFY_CONTENTS", "ALLOW_FILL_IN", "ALLOW_DEGRADED_PRINTING"), true);
        assertEquals(e4, a4);
        
        Permissions a5 = a4.withRemoved(Arrays.asList("ALLOW_MODIFY_CONTENTS"));
        Permissions e5 = Permissions.fromSet(Arrays.asList("ALLOW_PRINTING", "ALLOW_FILL_IN", "ALLOW_DEGRADED_PRINTING"), true);
        LOG.debug("e5: " + e5);
        assertEquals(e5, a5);
        
        Permissions a6 = a5.withRemoved(Arrays.asList("ALLOW_FILL_IN"));
        Permissions e6 = Permissions.fromSet(Arrays.asList("ALLOW_PRINTING", "ALLOW_DEGRADED_PRINTING"), true);
        LOG.debug("e6: " + e6);
        assertEquals(e6, a6);
        
        // Special case in SignServer: removing PRINTING shouldnt' remove DEGRADED_PRINTING
        Permissions a7 = a6.withRemoved(Arrays.asList("ALLOW_PRINTING"));
        Permissions e7 = Permissions.fromSet(Arrays.asList("ALLOW_DEGRADED_PRINTING"), true);
        assertEquals(e7, a7);
        
        Permissions a8 = a7.withRemoved(Arrays.asList("_NON_EXISTiNG"));
        Permissions e8 = e7;
        assertEquals(e8, a8);
        
        Permissions a9 = a8.withRemoved(new LinkedList<String>());
        Permissions e9 = e7;
        assertEquals(e9, a9);
        
        Permissions a10 = a9.withRemoved(Arrays.asList("ALLOW_DEGRADED_PRINTING"));
        Permissions e10 = Permissions.fromSet(new LinkedList<String>(), true);
        assertEquals(e10, a10);
        
        Permissions a11 = a10.withRemoved(new LinkedList<String>());
        Permissions e11 = e10;
        assertEquals(e11, a11);
        
        Permissions a12 = a11.withRemoved(Arrays.asList("_NON_EXISTiNG123"));
        Permissions e12 = e10;
        assertEquals(e12, a12);
    }

}
