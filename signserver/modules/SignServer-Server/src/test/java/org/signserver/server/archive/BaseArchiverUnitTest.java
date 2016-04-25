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
package org.signserver.server.archive;

import java.util.List;
import junit.framework.TestCase;
import org.junit.Test;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;

/**
 * Unit tests for the base archiver class.
 * Currently contains unit tests for the getFatalErrors mechanism.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class BaseArchiverUnitTest extends TestCase {
    
    /**
     * Test that no fatal errors are included by default in a BaseArchiver
     * implementation.
     * 
     * @throws Exception 
     */
    @Test
    public void testNoErrors() throws Exception {
       final Archiver archiver = new BaseArchiver() {
           @Override
           public void init(int listIndex, WorkerConfig config, SignServerContext context) throws ArchiverInitException {
               throw new UnsupportedOperationException("Not supported yet.");
           }

           @Override
           public boolean archive(Archivable archivable, RequestContext requestContext) throws ArchiveException {
               throw new UnsupportedOperationException("Not supported yet.");
           }
       };
       
       final List<String> errors = archiver.getFatalErrors();
       assertTrue("Should not contain fatal errors", errors.isEmpty());
    }
    
    /**
     * Test that including exactly one error works as expected.
     * 
     * @throws Exception 
     */
    @Test
    public void testOneError() throws Exception {
        final Archiver archiver = new BaseArchiver() {
            {
                addFatalError("One error");
            }

            @Override
            public void init(int listIndex, WorkerConfig config, SignServerContext context) throws ArchiverInitException {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            @Override
            public boolean archive(Archivable archivable, RequestContext requestContext) throws ArchiveException {
                throw new UnsupportedOperationException("Not supported yet.");
            }
        };
        
        final List<String> errors = archiver.getFatalErrors();
        assertEquals("Should contain one error", 1, errors.size());
        assertTrue("Should contain specific error", errors.contains("One error"));
    }
    
    /**
     * Test that including two errors works as expected.
     * 
     * @throws Exception 
     */
    @Test
    public void testTwoErrors() throws Exception {
        final Archiver archiver = new BaseArchiver() {
            {
                addFatalError("One error");
                addFatalError("Second error");
            }

            @Override
            public void init(int listIndex, WorkerConfig config, SignServerContext context) throws ArchiverInitException {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            @Override
            public boolean archive(Archivable archivable, RequestContext requestContext) throws ArchiveException {
                throw new UnsupportedOperationException("Not supported yet.");
            }
        };
        
        final List<String> errors = archiver.getFatalErrors();
        assertEquals("Should contain two errors", 2, errors.size());
        assertTrue("Should contain specific error", errors.contains("One error"));
        assertTrue("Should contain the second error", errors.contains("Second error"));
    }
}
