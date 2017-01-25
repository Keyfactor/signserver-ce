/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2008  The JMRTD team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id:PassportService.java 352 2008-05-19 06:55:21Z martijno $
 */
package org.signserver.module.mrtdsodsigner.jmrtd;

/** Constants for Passport files, datagroups etc.
 * 
 * @version $Id$
 */
public class PassportConstants {

    /** Data group 1 contains the MRZ. */
    public static final short EF_DG1 = 0x0101;

    /** Data group 2 contains face image data. */
    public static final short EF_DG2 = 0x0102;

    /** Data group 3 contains finger print data. */
    public static final short EF_DG3 = 0x0103;

    /** Data group 4 contains iris data. */
    public static final short EF_DG4 = 0x0104;

    /** Data group 5 contains displayed portrait. */
    public static final short EF_DG5 = 0x0105;

    /** Data group 6 is RFU. */
    public static final short EF_DG6 = 0x0106;

    /** Data group 7 contains displayed signature. */
    public static final short EF_DG7 = 0x0107;

    /** Data group 8 contains data features. */
    public static final short EF_DG8 = 0x0108;

    /** Data group 9 contains structure features. */
    public static final short EF_DG9 = 0x0109;

    /** Data group 10 contains substance features. */
    public static final short EF_DG10 = 0x010A;

    /** Data group 11 contains additional personal details. */
    public static final short EF_DG11 = 0x010B;

    /** Data group 12 contains additional document details. */
    public static final short EF_DG12 = 0x010C;

    /** Data group 13 contains optional details. */
    public static final short EF_DG13 = 0x010D;

    /** Data group 14 is RFU. */
    public static final short EF_DG14 = 0x010E;

    /** Data group 15 contains the public key used for Active Authentication. */
    public static final short EF_DG15 = 0x010F;

    /** Data group 16 contains person(s) to notify. */
    public static final short EF_DG16 = 0x0110;

    /** The security document. */
    public static final short EF_SOD = 0x011D;

    /** File indicating which data groups are present. */
    public static final short EF_COM = 0x011E;

    /**
     * File with the EAC CVCA references. Note: this can be overridden by a file
     * identifier in the DG14 file (TerminalAuthenticationInfo). So check that
     * one first. Also, this file does not have a header tag, like the others.
     */
    public static final short EF_CVCA = 0x011C;

    /** Short file identifiers for the DGs */

    public static final byte SF_DG1 = 0x01;

    public static final byte SF_DG2 = 0x02;

    public static final byte SF_DG3 = 0x03;

    public static final byte SF_DG4 = 0x04;

    public static final byte SF_DG5 = 0x05;

    public static final byte SF_DG6 = 0x06;

    public static final byte SF_DG7 = 0x07;

    public static final byte SF_DG8 = 0x08;

    public static final byte SF_DG9 = 0x09;

    public static final byte SF_DG10 = 0x0a;

    public static final byte SF_DG11 = 0x0b;

    public static final byte SF_DG12 = 0x0c;

    public static final byte SF_DG13 = 0x0d;

    public static final byte SF_DG14 = 0x0e;

    public static final byte SF_DG15 = 0x0f;

    public static final byte SF_DG16 = 0x10;

    public static final byte SF_COM = 0x1E;

    public static final byte SF_SOD = 0x1D;

    public static final byte SF_CVCA = 0x1C;

}
