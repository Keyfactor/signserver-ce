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
package org.signserver.rest.api.io.request;

import org.signserver.rest.api.entities.DataEncoding;
import java.util.HashMap;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 *
 * @author Markus Kilås
 */
@Schema(
    name = "ProcessRequest",
    description = "POJO that represents a process request."
)
public class ProcessRequest {

    @Schema(
        required = true,
        description = "The input data to be processed (i.e. signed)."
    )
    private String data;

    @Schema(
        required = false,
        description = "Additional encoding of the input data."
    )
    private DataEncoding encoding;

    @Schema(
        required = false,
        description = "Additional request metadata for the worker."
    )
    private HashMap<String, String> metaData;

    public ProcessRequest() {
    }

    public ProcessRequest(HashMap<String, String> metaData, String data, DataEncoding encoding) {
        this.metaData = metaData;
        this.data = data;
        this.encoding = encoding;
    }

    public HashMap<String, String> getMetaData() {
        return metaData;
    }

    public void setMetaData(HashMap<String, String> metaData) {
        this.metaData = metaData;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public DataEncoding getEncoding() {
        return encoding;
    }

    public void setEncoding(DataEncoding encoding) {
        this.encoding = encoding;
    }
}
