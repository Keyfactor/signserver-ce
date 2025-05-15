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

import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import org.apache.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.signserver.server.AllowlistUtils.isPathAllowed;

/**
 * Unit tests for AllowlistUtils.
 */
public class AllowlistUtilsTest {

    private static final Logger LOG = Logger.getLogger(AllowlistUtilsTest.class);

    /**
     * Tests different cases for isPathAllowed using absolute paths.
     */
    @Test
    public void testIsPathAllowed_absolutePaths() {
        LOG.info("isPathAllowed");

        assertTrue("Pos: file in path1",                       isPathAllowed(Path.of("/mnt/path1/archive"),          whereAllowedAre("/mnt/path1")));
        assertTrue("Pos: file in path1 (. folder)",            isPathAllowed(Path.of("/mnt/path1/./archive"),        whereAllowedAre("/mnt/path1")));
        assertTrue("Pos: file in path1 (.. folder)",           isPathAllowed(Path.of("/var/../mnt/path1/./archive"), whereAllowedAre("/mnt/path1")));

        assertTrue("Pos: file in path2",                       isPathAllowed(Path.of("/mnt/path2/archive"),          whereAllowedAre("/mnt/path1", "/mnt/path2")));
        assertTrue("Pos: file in path2 (. folder)",            isPathAllowed(Path.of("/mnt/path2/./archive"),        whereAllowedAre("/mnt/path1", "/mnt/path2")));
        assertTrue("Pos: file in path2 (.. folder)",           isPathAllowed(Path.of("/var/../mnt/path2/./archive"), whereAllowedAre("/mnt/path1", "/mnt/path2")));

        assertFalse("Neg: file above path1",                   isPathAllowed(Path.of("/mnt"),                        whereAllowedAre("/mnt/path1")));
        assertFalse("Neg: file above path1",                   isPathAllowed(Path.of("/mnt/"),                       whereAllowedAre("/mnt/path1")));
        assertFalse("Neg: file above path1, in other",         isPathAllowed(Path.of("/mnt/archive"),                whereAllowedAre("/mnt/path1")));
        assertFalse("Neg: file above path1, in other",         isPathAllowed(Path.of("/mnt/archive/"),               whereAllowedAre("/mnt/path1")));
        assertFalse("Neg: file above path1 (..)",              isPathAllowed(Path.of("/mnt/path1/.."),               whereAllowedAre("/mnt/path1")));
        assertFalse("Neg: file above path1 (../)",             isPathAllowed(Path.of("/mnt/path1/../"),              whereAllowedAre("/mnt/path1")));
        assertFalse("Neg: file above path1, in other (..)",    isPathAllowed(Path.of("/mnt/path1/../archive/"),      whereAllowedAre("/mnt/path1")));
        assertFalse("Neg: file above path1, in other (../.)",  isPathAllowed(Path.of("/mnt/path1/../archive/."),     whereAllowedAre("/mnt/path1")));
        assertFalse("Neg: file above path1, in other (.././)", isPathAllowed(Path.of("/mnt/path1/../archive/./"),    whereAllowedAre("/mnt/path1")));

        assertFalse("Neg: similar looking path",               isPathAllowed(Path.of("/mnt/path11/archive"),         whereAllowedAre("/mnt/path1")));
        assertFalse("Neg: similar looking path",               isPathAllowed(Path.of("/mnt/path11/archive/."),       whereAllowedAre("/mnt/path1")));
        assertFalse("Neg: similar looking path",               isPathAllowed(Path.of("/mnt/path11/archive/./"),      whereAllowedAre("/mnt/path1")));
        assertFalse("Neg: similar looking path",               isPathAllowed(Path.of("/mnt/path11/archive/../"),     whereAllowedAre("/mnt/path1")));
        assertFalse("Neg: similar looking path",               isPathAllowed(Path.of("/mnt/path11/./"),              whereAllowedAre("/mnt/path1")));


        // Windows paths
        assertTrue("Pos: file in path1",                       isPathAllowed(Path.of("C:/mnt/path1/archive"),          whereAllowedAre("C:/mnt/path1")));
        assertTrue("Pos: file in path1 (. folder)",            isPathAllowed(Path.of("C:/mnt/path1/./archive"),        whereAllowedAre("C:/mnt/path1")));
        assertTrue("Pos: file in path1 (.. folder)",           isPathAllowed(Path.of("C:/var/../mnt/path1/./archive"), whereAllowedAre("C:/mnt/path1")));

        assertTrue("Pos: file in path2",                       isPathAllowed(Path.of("C:/mnt/path2/archive"),          whereAllowedAre("C:/mnt/path1", "C:/mnt/path2")));
        assertTrue("Pos: file in path2 (. folder)",            isPathAllowed(Path.of("C:/mnt/path2/./archive"),        whereAllowedAre("C:/mnt/path1", "C:/mnt/path2")));
        assertTrue("Pos: file in path2 (.. folder)",           isPathAllowed(Path.of("C:/var/../mnt/path2/./archive"), whereAllowedAre("C:/mnt/path1", "C:/mnt/path2")));

        assertFalse("Neg: file above path1",                   isPathAllowed(Path.of("C:/mnt"),                        whereAllowedAre("C:/mnt/path1")));
        assertFalse("Neg: file above path1",                   isPathAllowed(Path.of("C:/mnt/"),                       whereAllowedAre("C:/mnt/path1")));
        assertFalse("Neg: file above path1, in other",         isPathAllowed(Path.of("C:/mnt/archive"),                whereAllowedAre("C:/mnt/path1")));
        assertFalse("Neg: file above path1, in other",         isPathAllowed(Path.of("C:/mnt/archive/"),               whereAllowedAre("C:/mnt/path1")));
        assertFalse("Neg: file above path1 (..)",              isPathAllowed(Path.of("C:/mnt/path1/.."),               whereAllowedAre("C:/mnt/path1")));
        assertFalse("Neg: file above path1 (../)",             isPathAllowed(Path.of("C:/mnt/path1/../"),              whereAllowedAre("C:/mnt/path1")));
        assertFalse("Neg: file above path1, in other (..)",    isPathAllowed(Path.of("C:/mnt/path1/../archive/"),      whereAllowedAre("C:/mnt/path1")));
        assertFalse("Neg: file above path1, in other (../.)",  isPathAllowed(Path.of("C:/mnt/path1/../archive/."),     whereAllowedAre("C:/mnt/path1")));
        assertFalse("Neg: file above path1, in other (.././)", isPathAllowed(Path.of("C:/mnt/path1/../archive/./"),    whereAllowedAre("C:/mnt/path1")));

        assertFalse("Neg: similar looking path",               isPathAllowed(Path.of("C:/mnt/path11/archive"),         whereAllowedAre("C:/mnt/path1")));
        assertFalse("Neg: similar looking path",               isPathAllowed(Path.of("C:/mnt/path11/archive/."),       whereAllowedAre("C:/mnt/path1")));
        assertFalse("Neg: similar looking path",               isPathAllowed(Path.of("C:/mnt/path11/archive/./"),      whereAllowedAre("C:/mnt/path1")));
        assertFalse("Neg: similar looking path",               isPathAllowed(Path.of("C:/mnt/path11/archive/../"),     whereAllowedAre("C:/mnt/path1")));
        assertFalse("Neg: similar looking path",               isPathAllowed(Path.of("C:/mnt/path11/./"),              whereAllowedAre("C:/mnt/path1")));
    }

    /**
     * Tests different cases for isPathAllowed using relative paths.
     */
    @Test
    public void testIsPathAllowed_relativePaths() {
        LOG.info("testIsPathAllowed_relPaths");

        assertTrue("Pos: file in path1", isPathAllowed(Path.of("archive/file.txt"), whereAllowedAre("archive")));

        assertTrue("Pos: file in path1",                       isPathAllowed(Path.of("path1/archive"),               whereAllowedAre("path1")));
        assertTrue("Pos: file in path1 (. folder)",            isPathAllowed(Path.of("path1/./archive"),             whereAllowedAre("path1")));
        assertTrue("Pos: file in path1 (.. folder)",           isPathAllowed(Path.of("other/../path1/./archive"),    whereAllowedAre("path1")));

        assertTrue("Pos: file in path2",                       isPathAllowed(Path.of("path2/archive"),               whereAllowedAre("path1", "path2")));
        assertTrue("Pos: file in path2 (. folder)",            isPathAllowed(Path.of("path2/./archive"),             whereAllowedAre("path1", "path2")));
        assertTrue("Pos: file in path2 (.. folder)",           isPathAllowed(Path.of("other/../path2/./archive"),    whereAllowedAre("path1", "path2")));

        assertFalse("Neg: file above path1",                   isPathAllowed(Path.of("/mnt"),                        whereAllowedAre("path1")));
        assertFalse("Neg: file above path1",                   isPathAllowed(Path.of("/mnt/"),                       whereAllowedAre("path1")));
        assertFalse("Neg: file above path1, in other",         isPathAllowed(Path.of("/mnt/archive"),                whereAllowedAre("path1")));
        assertFalse("Neg: file above path1, in other",         isPathAllowed(Path.of("/mnt/archive/"),               whereAllowedAre("path1")));
        assertFalse("Neg: file above path1 (..)",              isPathAllowed(Path.of("path1/.."),                    whereAllowedAre("path1")));
        assertFalse("Neg: file above path1 (../)",             isPathAllowed(Path.of("path1/../"),                   whereAllowedAre("path1")));
        assertFalse("Neg: file above path1, in other (..)",    isPathAllowed(Path.of("path1/../archive/"),           whereAllowedAre("path1")));
        assertFalse("Neg: file above path1, in other (../.)",  isPathAllowed(Path.of("path1/../archive/."),          whereAllowedAre("path1")));
        assertFalse("Neg: file above path1, in other (.././)", isPathAllowed(Path.of("path1/../archive/./"),         whereAllowedAre("path1")));

        assertFalse("Neg: similar looking path",               isPathAllowed(Path.of("path11/archive"),              whereAllowedAre("path1")));
        assertFalse("Neg: similar looking path",               isPathAllowed(Path.of("path11/archive/."),            whereAllowedAre("path1")));
        assertFalse("Neg: similar looking path",               isPathAllowed(Path.of("path11/archive/./"),           whereAllowedAre("path1")));
        assertFalse("Neg: similar looking path",               isPathAllowed(Path.of("path11/archive/../"),          whereAllowedAre("path1")));
        assertFalse("Neg: similar looking path",               isPathAllowed(Path.of("path11/./"),                   whereAllowedAre("path1")));
    }

    /**
     * Tests different cases for isPathAllowed including blank paths (=using current working directory).
     */
    @Test
    public void testIsPathAllowed_blanks() {
        assertFalse("Neg: empty allow list",                   isPathAllowed(Path.of("/mnt"),                        whereAllowedAre()));
        assertFalse("Neg: blank allowed file",                 isPathAllowed(Path.of("/mnt"),                        whereAllowedAre("")));
        assertFalse("Neg: empty path (actually CWD)",          isPathAllowed(Path.of(""),                            whereAllowedAre("path1")));
        assertFalse("Neg: empty path (actually CWD)",          isPathAllowed(Path.of(""),                            whereAllowedAre()));
    }


    /**
     * Constructs allowList of normalized Path:s.
     * @param paths to normalize and put in allowed list
     * @return set of normalized paths
     */
    private static Set<Path> whereAllowedAre(String... paths) {
        Set<Path> result = new HashSet<>();
        for (var path : paths) {
            result.add(Path.of(path).normalize());
        }
        return result;
    }

}
