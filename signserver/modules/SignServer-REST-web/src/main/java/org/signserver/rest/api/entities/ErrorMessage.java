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
package org.signserver.rest.api.entities;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 *
 * @author Markus Kilås
 */
public class ErrorMessage {
    private final String error;

    public ErrorMessage(String error) {
        this.error = error;
    }

    public String getError() {
        return error;
    }
    
    public static class ErrorMessage400 {
        @Schema(example = "Bad request from the client")
        private String error;
    }
    
    public static class ErrorMessage403 {
        @Schema(example = "Access is forbidden!")
        private String error;
    }
    
    public static class ErrorMessage404 {
        @Schema(example = "No such worker")
        private String error;
    }

    public static class ErrorMessage405 {
        @Schema(example = "Method not allowed.")
        private String error;
    }
    
    public static class ErrorMessage409 {
        @Schema(example = "Worker already exists.")
        private String error;
    }
    
    public static class ErrorMessage500 {
        @Schema(example = "The server were unable to process the request. See server-side logs for more details.")
        private String error;
    }
    
    public static class ErrorMessage503 {
        @Schema(example = "Crypto Token not available")
        private String error;
    }

}
