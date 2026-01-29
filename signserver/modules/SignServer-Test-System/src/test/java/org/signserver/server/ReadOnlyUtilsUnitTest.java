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
package org.signserver.server;

import org.apache.log4j.Logger;
import org.signserver.common.util.ReadOnlyUtils;
import org.signserver.server.log.AdminInfo;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

/**
 * Unit tests for the ReadOnlyUtils class.
 */
public class ReadOnlyUtilsUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ReadOnlyUtilsUnitTest.class);

    private static final int ID_1 = 1;
    private static final int ID_2 = 2;
    private static final int ID_3 = 3;
    private static final int ID_4 = 4;
    private static final int ID_5 = 5;
    private static final int ID_6 = 6;
    private static final int ID_7 = 7;
    private static final int ID_8 = 8;
    private static final int ID_9 = 9;
    private static final int ID_10 = 10;
    private static final int ID_11 = 11;
    private static final int ID_15 = 15;
    private static final int ID_100 = 100;
    private static final Set<Integer> READ_ONLY_WORKERS = new HashSet<>(Arrays.asList(ID_1, ID_2, ID_3));

    private static final String EMPTY = "";
    private static final String WHITESPACE = " ";
    private static final String SINGLE_INPUT = "1";
    private static final String RANGE_INPUT = "1-10";
    private static final String MULTI_INPUT = "1, 2, 5";
    private static final String MIXED_INPUT = "1, 3-5, 8-11, 15, 100";
    private static final String DUPLICATED_INPUT = "1, 1-3, 1-5, 2";
    private static final String EMPTY_ENTRIES = "1, , ,5";
    private static final String INVALID_INPUT_CHARACTERS = "1, abc, 3";
    private static final String RANGE_MISSING_UPPERBOUND = "1-";
    private static final String NEGATIVE_INTEGERS_INPUT = "-1,-4, 2-5";
    private static final String NEGATIVE_RANGES_INPUT = "-10-12";


    /**
     * Helper method for asserting whether modification is allowed for a worker based on
     * the provided read-only worker set.
     */
    private void performModTest(AdminInfo adminInfo, int workerId, Set<Integer> readOnlyWorkers, boolean expected) {

        boolean actual = ReadOnlyUtils.isModificationAllowed(adminInfo, workerId, readOnlyWorkers);

        if (expected) {
            assertTrue(actual);
        } else {
            assertFalse(actual);
        }
    }

    /**
     * Tests if modification is allowed using AdminCLI.
     */
    @Test
    public void testModificationAllowed_AdminCLI() {
        LOG.info("testModificationAllowed_AdminCLI");
        performModTest(new AdminInfo("CLI user", null, null), ID_1, READ_ONLY_WORKERS, true);
    }

    /**
     * Tests if modification is allowed on a read-only worker.
     */
    @Test
    public void testModificationDenied() {
        LOG.info("testModificationDenied");
        performModTest(new AdminInfo("Non-CLI user", null, null), ID_1, READ_ONLY_WORKERS, false);
    }

    /**
     * Tests if modification is allowed on a worker that is not on the read-only list.
     */
    @Test
    public void testModificationAllowed() {
        LOG.info("testModificationAllowed");

        performModTest(new AdminInfo(null, null, null), ID_4, READ_ONLY_WORKERS, true);
    }

    /**
     * Tests if modification is allowed, with an empty read-only list.
     */
    @Test
    public void testModificationAllowedWithEmptySet() {
        LOG.info("testModificationAllowedWithEmptySet");
        performModTest(new AdminInfo(null, null, null), ID_1, new HashSet<>(), true);
    }

    /**
     * Test parsing a list containing a single numeric id.
     */
    @Test
    public void testParseSingleNumericId() {
        LOG.info("testParseSingleNumericId");
        Set<Integer> actual = ReadOnlyUtils.parseReadOnlyWorkersRange(SINGLE_INPUT);

        assertEquals(1, actual.size());
        assertTrue(actual.contains(ID_1));
    }
    /**
     * Test parsing a list containing multiple single numeric ids.
     */
    @Test
    public void testParseMultiNumericId() {
        LOG.info("testParseMultiNumericId");
        Set<Integer> actual = ReadOnlyUtils.parseReadOnlyWorkersRange(MULTI_INPUT);
        Set<Integer> expected = Set.of(ID_1, ID_2, ID_5);

        assertEquals(expected, actual);
    }

    /**
     * Tests that ranges are parsed inclusively (from - to).
     */
    @Test
    public void testParseRangeInclusive() {
        LOG.info("testParseRangeInclusive");
        Set<Integer> actual = ReadOnlyUtils.parseReadOnlyWorkersRange(RANGE_INPUT);
        Set<Integer> expected = Set.of(ID_1, ID_2, ID_3, ID_4, ID_5, ID_6, ID_7, ID_8, ID_9, ID_10);

        assertEquals(expected, actual);
    }
    /**
     * Test parsing a list containing a mix of ranges and single numeric ids.
     */
    @Test
    public void testParseMixedIdsAndRanges() {
        LOG.info("testParseMixedIdsAndRanges");
        Set<Integer> actual = ReadOnlyUtils.parseReadOnlyWorkersRange(MIXED_INPUT);
        Set<Integer> expected = Set.of(ID_1, ID_3, ID_4, ID_5, ID_8, ID_9, ID_10, ID_11, ID_15, ID_100);

        assertEquals(expected, actual);
    }

    /**
     * Tests that an empty input string results in an empty set.
     */
    @Test
    public void testEmptyInputReturnsEmptySet() {
        LOG.info("testEmptyInputReturnsEmptySet");
        Set<Integer> actual = ReadOnlyUtils.parseReadOnlyWorkersRange(EMPTY);

        assertNotNull(actual);
        assertTrue(actual.isEmpty());
    }

    /**
     * Tests that whitespace only input is treated as empty.
     */
    @Test
    public void testWhiteSpaceInputReturnsEmptySet() {
        LOG.info("testWhiteSpaceInputReturnsEmptySet");
        Set<Integer> actual = ReadOnlyUtils.parseReadOnlyWorkersRange(WHITESPACE);

        assertNotNull(actual);
        assertTrue(actual.isEmpty());
    }

    /**
     * Tests that empty entries in the input string are ignored.
     */
    @Test
    public void testEmptyEntriesAreIgnored() {
        LOG.info("testEmptyEntriesAreIgnored");
        Set<Integer> actual = ReadOnlyUtils.parseReadOnlyWorkersRange(EMPTY_ENTRIES);
        Set<Integer> expected = Set.of(ID_1, ID_5);

        assertEquals(expected, actual);
    }

    /**
     * Tests that duplicates in a list are ignored.
     */
    @Test
    public void testDuplicatesAreIgnored() {
        LOG.info("testDuplicatesAreIgnored");
        Set<Integer> actual = ReadOnlyUtils.parseReadOnlyWorkersRange(DUPLICATED_INPUT);
        Set<Integer> expected = Set.of(ID_1, ID_2, ID_3, ID_4, ID_5);

        assertEquals(expected, actual);
    }

    /**
     * Tests that invalid input is ignored.
     */
    @Test
    public void testIgnoreInvalidValues() {
        LOG.info("testIgnoreInvalidValues");
        Set<Integer> actual = ReadOnlyUtils.parseReadOnlyWorkersRange(INVALID_INPUT_CHARACTERS);
        Set<Integer> expected = Set.of(ID_1, ID_3);

        assertEquals(expected,actual);
    }

    /**
     * Tests that a range missing an upper bound returns an empty set.
     */
    @Test
    public void testRangeMissingUpperBoundReturnsEmpty() {
        LOG.info("testRangeMissingUpperBoundReturnsEmpty");
        Set<Integer> actual = ReadOnlyUtils.parseReadOnlyWorkersRange(RANGE_MISSING_UPPERBOUND);

        assertNotNull(actual);
        assertTrue(actual.isEmpty());
    }

    /**
     * Tests that input containing negative integers gets ignored.
     */
    @Test
    public void testIgnoreNegativeIntegersInput() {
        LOG.info("testIgnoreNegativeIntegersInput");
        Set<Integer> actual = ReadOnlyUtils.parseReadOnlyWorkersRange(NEGATIVE_INTEGERS_INPUT);
        Set<Integer> expected = Set.of(ID_2, ID_3, ID_4, ID_5);

        assertEquals(expected,actual);
    }

    /**
     * Tests that input containing a negative range returns an empty set.
     */
    @Test
    public void testNegativeRangeIntegersInputReturnsEmpty() {
        LOG.info("testIgnoreNegativeIntegersInput");
        Set<Integer> actual = ReadOnlyUtils.parseReadOnlyWorkersRange(NEGATIVE_RANGES_INPUT);

        assertNotNull(actual);
        assertTrue(actual.isEmpty());
    }

}
