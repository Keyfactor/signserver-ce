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
package org.signserver.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.util.Properties;

/**
 * A Generic work request class where request data is stored in properties.
 *
 * Could be used by any worker.
 *
 * @author markus
 * $Id$
 */
public class GenericPropertiesResponse extends ProcessResponse {

    private static final long serialVersionUID = 1L;

    private Properties properties;

    /**
     * Default constructor used during de-serialization.
     */
    public GenericPropertiesResponse() {
        this(new Properties());
    }

    /**
     * Creates a GenericSignResponse, works as a simple VO.
     *
     * @param requestID
     * @param requestData
     * @see org.signserver.common.ProcessRequest
     */
    public GenericPropertiesResponse(final Properties properties) {
        this.properties = properties;
    }

    /**
     * @return The request data.
     */
    public Properties getProperties() {
        return properties;
    }

    public void parse(DataInput in) throws IOException {
        in.readInt();
        final int length = in.readInt();
        final byte[] data  = new byte[length];
        in.readFully(data);
        properties.load(new ByteArrayInputStream(data));
    }

    public void serialize(DataOutput out) throws IOException {
        out.writeInt(RequestAndResponseManager
                .RESPONSETTYPE_GENERICPROPERTIESRESPONSE);

        final ByteArrayOutputStream bout = new ByteArrayOutputStream();
        properties.store(bout, null);
        final byte[] data = bout.toByteArray();
        out.writeInt(data.length);
        out.write(data);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final GenericPropertiesResponse other = (GenericPropertiesResponse) obj;
        if (this.properties != other.properties
                && (this.properties == null
                    || !this.properties.equals(other.properties))) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 19 * hash
                + (this.properties != null ? this.properties.hashCode() : 0);
        return hash;
    }

    @Override
    public String toString() {
        return "GenericPropertiesResponse{" + properties + "}";
    }

}
