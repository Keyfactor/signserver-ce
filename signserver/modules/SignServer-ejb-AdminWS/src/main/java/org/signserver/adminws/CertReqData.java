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
package org.signserver.adminws;

/**
 * Representation of AbstractCertReqData suitable for serialization over WS.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CertReqData {
    private byte[] binary;
    private String armored;
    private String contentType;
    private String fileSuffix;

    public CertReqData() {
    }

    public CertReqData(byte[] binary, String armored, String contentType, String fileSuffix) {
        this.binary = binary;
        this.armored = armored;
        this.contentType = contentType;
        this.fileSuffix = fileSuffix;
    }

    public byte[] getBinary() {
        return binary;
    }

    public void setBinary(byte[] binary) {
        this.binary = binary;
    }

    public String getArmored() {
        return armored;
    }

    public void setArmored(String armored) {
        this.armored = armored;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getFileSuffix() {
        return fileSuffix;
    }

    public void setFileSuffix(String fileSuffix) {
        this.fileSuffix = fileSuffix;
    }
    
}
