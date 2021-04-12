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
package org.signserver.client.cli.defaultimpl;

import java.util.Map;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.fail;
import org.junit.Test;
import org.signserver.cli.spi.IllegalCommandArgumentsException;

/**
 * Unit tests for the MetadataParser.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class MetadataParserUnitTest {
    /**
     * Test with valid metadata values.
     *
     * @throws Exception 
     */
    @Test
    public void parseMetadataValid() throws Exception {
        // given
        final int expectedNumItems = 4;
        final String[] input = { "option1=value1",
                                 "option2=value2",
                                 "option3=valuewithadditional=",
                                 "option4=value=more" };

        // when
        final Map<String, String> result = MetadataParser.parseMetadata(input);

        // expect
        assertEquals("Number of parsed items", expectedNumItems, result.size());
        assertEquals("First value", "value1", result.get("option1"));
        assertEquals("Second value", "value2", result.get("option2"));
        assertEquals("Third value", "valuewithadditional=", result.get("option3"));
        assertEquals("Forth value", "value=more", result.get("option4"));
    }

    /**
     * Test with an invalid metadata. Not containing an equal sign.
     *
     * @throws Exception 
     */
    @Test
    public void parseMetadataInvalid() throws Exception {
        // given
        final String[] input = { "optionwithoutparam" };

        // when
        try {
            final Map<String, String> result = MetadataParser.parseMetadata(input);

            // not expected (previous call should throw exception
            fail("Should trow IllegalCommandArgumensException");
        } catch (IllegalCommandArgumentsException e) {
            // expected
        }
    }
}
