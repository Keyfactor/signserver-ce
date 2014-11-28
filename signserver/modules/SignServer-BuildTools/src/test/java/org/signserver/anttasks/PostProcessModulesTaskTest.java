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
package org.signserver.anttasks;

import java.util.Properties;
import junit.framework.TestCase;

/**
 * Tests for the PostProcessModulesTask class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class PostProcessModulesTaskTest extends TestCase {
    
    public PostProcessModulesTaskTest(String testName) {
        super(testName);
    }
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }
    
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test of commentReplacement method, of class PostProcessModulesTask.
     */
    public void testCommentReplacement() throws Exception {
        PostProcessModulesTask instance = new PostProcessModulesTask();
        
        final Properties properties = new Properties();
        properties.setProperty("variable.name", "VALUE");
        final StringBuffer oldDocument = new StringBuffer("Line 1\nLine 2\n     <!--COMMENT-REPLACEMENT(variable.name)-->     \n");
        final StringBuffer actual = instance.commentReplacement(oldDocument, properties);
        final String expected = "Line 1\nLine 2\n     VALUE     \n";
        assertEquals(expected, actual.toString());
    }
    
}
