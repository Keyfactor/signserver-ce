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
import java.util.Set;

/**
 * A helper class that handles allowlists.
 */
public class AllowlistUtils {

    /**
     * Helper method to check if the provided path is included in the correct allowlist.<br>
     * PDF Archiving:<br>
     * The ARCHIVETODISK_PATH_BASE property can be set to any directory that is a child of the allowed paths
     * configured in the archiving allowlist.
     * If the final normalized path is outside any of the pdfsigner.archive.path.allowed.x
     * paths, the archiving will be rejected.<br>
     * Examples:
     * <table border="solid">
     *     <tr>
     *         <td>ARCHIVETODISK_PATH_BASE = /home/user/archiving/</td>
     *         <td>pdfsigner.archive.path.allowed.x = /home/user/archiving/</td>
     *         <td>ALLOWED</td>
     *     </tr>
     *     <tr>
     *         <td>ARCHIVETODISK_PATH_BASE = /home/user/archiving/subdirectory/</td>
     *         <td>pdfsigner.archive.path.allowed.x = /home/user/archiving/</td>
     *         <td>ALLOWED</td>
     *     </tr>
     *     <tr>
     *         <td>ARCHIVETODISK_PATH_BASE = /home/user/secret/</td>
     *         <td>pdfsigner.archive.path.allowed.x = /home/user/archiving/</td>
     *         <td>NOT ALLOWED</td>
     *     </tr>
     *     <tr>
     *         <td>ARCHIVETODISK_PATH_BASE = /home/user/secret/<br>ARCHIVETODISK_FILENAME_PATTERN = ../../server.log</td>
     *         <td>pdfsigner.archive.path.allowed.x = /home/user/archiving/</td>
     *         <td>NOT ALLOWED</td>
     *     </tr>
     * </table>
     *
     * <br>Custom images as visible signatures for PDFs:<br>
     * The VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH (PDFSigner) and VISIBLE_SIGNATURE_IMAGE_PATH (AdES with PAdES signature
     * format) properties can be set to any directory that is a child of the allowed paths configured in the custom
     * image allowlist. If the final normalized path is outside any of the pdfsigner.image.path.allowed.x paths, the
     * signer will be deemed misconfigured.
     * <br>Examples:<br>
     * <table border="solid">
     *     <tr>
     *         <td>PDFSigner</td>
     *     </tr>
     *     <tr>
     *         <td>VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH = /home/user/images/myimage.png</td>
     *         <td>pdfsigner.image.path.allowed.x = /home/user/images/</td>
     *         <td>ALLOWED</td>
     *     </tr>
     *     <tr>
     *         <td>VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH = /home/user/images/myimage.png</td>
     *         <td>pdfsigner.image.path.allowed.x = /home/user/images/specificimages/</td>
     *         <td>NOT ALLOWED</td>
     *     </tr>
     * </table>
     * <br>
     * <table border="solid">
     *     <tr>
     *         <td>AdESSigner with PAdES</td>
     *     </tr>
     *     <tr>
     *         <td>VISIBLE_SIGNATURE_IMAGE_PATH = /home/user/images/myimage.png</td>
     *         <td>pdfsigner.image.path.allowed.x = /home/user/images/</td>
     *         <td>ALLOWED</td>
     *     </tr>
     *     <tr>
     *         <td>VISIBLE_SIGNATURE_IMAGE_PATH = /home/user/images/myimage.png</td>
     *         <td>pdfsigner.image.path.allowed.x = /home/user/images/specificimages/</td>
     *         <td>NOT ALLOWED</td>
     *     </tr>
     * </table>
     *
     * @param path The path to check. It will be normalized and verified to see if it starts with any path in the provided allowList.
     * @param allowList Collection of paths that should be normalized before being passed in.
     * @return True if the provided path starts with any of the entries in the allowList, otherwise false.
     */
    public static boolean isPathAllowed(Path path, Set<Path> allowList) {
        path = path.normalize();
        for (Path allowedPath : allowList) {
            if (path.startsWith(allowedPath)) {
                return true;
            }
        }
        return false;
    }
}
