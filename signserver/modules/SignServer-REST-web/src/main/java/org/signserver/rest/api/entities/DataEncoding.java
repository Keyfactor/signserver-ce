/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Enum.java to edit this template
 */
package org.signserver.rest.api.entities;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * Choice of encoding for the input data.
 */
@Schema(
    name = "DataEncoding",
    description = "Choice of additional encoding of the data."
)
public enum DataEncoding {
    
    /** No additional encoding of the string. **/
    NONE,
    
    /** The bytes are base64 encoded. **/
    BASE64
}
