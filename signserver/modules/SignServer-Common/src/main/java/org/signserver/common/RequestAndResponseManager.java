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
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Set;

import org.apache.log4j.Logger;
import org.signserver.groupkeyservice.common.DocumentIDRemoveGroupKeyRequest;
import org.signserver.groupkeyservice.common.FetchKeyRequest;
import org.signserver.groupkeyservice.common.FetchKeyResponse;
import org.signserver.groupkeyservice.common.PregenerateKeysRequest;
import org.signserver.groupkeyservice.common.PregenerateKeysResponse;
import org.signserver.groupkeyservice.common.RemoveGroupKeyResponse;
import org.signserver.groupkeyservice.common.SwitchEncKeyRequest;
import org.signserver.groupkeyservice.common.SwitchEncKeyResponse;
import org.signserver.groupkeyservice.common.TimeRemoveGroupKeyRequest;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;

/**
 * Class used to parse and generate list available  and their IProcessRequest and IProcessResponse
 * from byte[] data.
 * 
 * It have a standard set of available request/response classes but
 * it is possible to dynamically register and unregister other classes
 * through static methods. 
 *
 * @author Philip Vendil 9 dec 2007
 * @version $Id$
 */
public class RequestAndResponseManager {

    /** Logger for this class. */
    private static final Logger log = Logger.getLogger(RequestAndResponseManager.class);
    
    // Signer Request types
    public static final int REQUESTTYPE_GENERICSIGNREQUEST = 1;
    public static final int REQUESTTYPE_MRTDSIGNREQUEST = 2;
    public static final int REQUESTTYPE_SODSIGNREQUEST = 3;
    
    // Group Key Service request types
    public static final int REQUESTTYPE_GKS_SWITCHENCKEY = 101;
    public static final int REQUESTTYPE_GKS_PREGENKEYS = 102;
    public static final int REQUESTTYPE_GKS_FETCHKEY = 103;
    public static final int REQUESTTYPE_GKS_TIMEREMKEYS = 104;
    public static final int REQUESTTYPE_GKS_IDREMKEYS = 105;
    
    // Validation Service request types
    public static final int REQUESTTYPE_VALIDATE = 201;
    
    // Validation request types
    public static final int REQUESTTYPE_GENERICVALIDATION = 301;
    
    // Signer Response types
    public static final int RESPONSETYPE_GENERICSIGNRESPONSE = 1;
    public static final int RESPONSETYPE_MRTDSIGNRESPONSE = 2;
    public static final int RESPONSETYPE_SODSIGNRESPONSE = 3;
    
    // Group Key Service request types
    public static final int RESPONSETYPE_GKS_SWITCHENCKEY = 101;
    public static final int RESPONSETYPE_GKS_PREGENKEYS = 102;
    public static final int RESPONSETYPE_GKS_FETCHKEY = 103;
    public static final int RESPONSETYPE_GKS_REMOVEKEY = 104;
    
    // Validation Service request types
    public static final int RESPONSETYPE_VALIDATE = 201;
    
    // Validation response types
    public static final int RESPONSETYPE_GENERICVALIDATION = 301;
    
    // Generic Properties type
    public static final int REQUESTTYPE_GENERICPROPERTIESREQUEST = 401;
    public static final int RESPONSETTYPE_GENERICPROPERTIESRESPONSE = 401;
    private static final HashMap<Integer, String> AVAILABLE_REQUEST_TYPES = new HashMap<Integer, String>();
    private static final HashMap<Integer, String> AVAILABLE_RESPONSE_TYPES = new HashMap<Integer, String>();

    static {
        AVAILABLE_REQUEST_TYPES.put(REQUESTTYPE_GENERICSIGNREQUEST, GenericSignRequest.class.getName());
        AVAILABLE_REQUEST_TYPES.put(REQUESTTYPE_MRTDSIGNREQUEST, MRTDSignRequest.class.getName());
        AVAILABLE_REQUEST_TYPES.put(REQUESTTYPE_SODSIGNREQUEST, SODSignRequest.class.getName());
        AVAILABLE_REQUEST_TYPES.put(REQUESTTYPE_GKS_FETCHKEY, FetchKeyRequest.class.getName());
        AVAILABLE_REQUEST_TYPES.put(REQUESTTYPE_GKS_IDREMKEYS, DocumentIDRemoveGroupKeyRequest.class.getName());
        AVAILABLE_REQUEST_TYPES.put(REQUESTTYPE_GKS_PREGENKEYS, PregenerateKeysRequest.class.getName());
        AVAILABLE_REQUEST_TYPES.put(REQUESTTYPE_GKS_SWITCHENCKEY, SwitchEncKeyRequest.class.getName());
        AVAILABLE_REQUEST_TYPES.put(REQUESTTYPE_GKS_TIMEREMKEYS, TimeRemoveGroupKeyRequest.class.getName());
        AVAILABLE_REQUEST_TYPES.put(REQUESTTYPE_VALIDATE, ValidateRequest.class.getName());
        AVAILABLE_REQUEST_TYPES.put(REQUESTTYPE_GENERICVALIDATION, GenericValidationRequest.class.getName());

        AVAILABLE_RESPONSE_TYPES.put(RESPONSETYPE_GENERICSIGNRESPONSE, GenericSignResponse.class.getName());
        AVAILABLE_RESPONSE_TYPES.put(RESPONSETYPE_MRTDSIGNRESPONSE, MRTDSignResponse.class.getName());
        AVAILABLE_RESPONSE_TYPES.put(RESPONSETYPE_SODSIGNRESPONSE, SODSignResponse.class.getName());
        AVAILABLE_RESPONSE_TYPES.put(RESPONSETYPE_GKS_FETCHKEY, FetchKeyResponse.class.getName());
        AVAILABLE_RESPONSE_TYPES.put(RESPONSETYPE_GKS_PREGENKEYS, PregenerateKeysResponse.class.getName());
        AVAILABLE_RESPONSE_TYPES.put(RESPONSETYPE_GKS_REMOVEKEY, RemoveGroupKeyResponse.class.getName());
        AVAILABLE_RESPONSE_TYPES.put(RESPONSETYPE_GKS_SWITCHENCKEY, SwitchEncKeyResponse.class.getName());
        AVAILABLE_RESPONSE_TYPES.put(RESPONSETYPE_VALIDATE, ValidateResponse.class.getName());
        AVAILABLE_RESPONSE_TYPES.put(RESPONSETYPE_GENERICVALIDATION, GenericValidationResponse.class.getName());

        // Properties type
        AVAILABLE_REQUEST_TYPES.put(REQUESTTYPE_GENERICPROPERTIESREQUEST,
                GenericPropertiesRequest.class.getName());
        AVAILABLE_RESPONSE_TYPES.put(RESPONSETTYPE_GENERICPROPERTIESRESPONSE,
                GenericPropertiesResponse.class.getName());
    }

    /**
     * Method used to parse all available process request and
     * return the appropriate deserialized type.
     * @param data the request data to parse.
     * @return a IProcessRequest or null if request wasn't supported.
     * @throws IOException 
     */
    public static ProcessRequest parseProcessRequest(byte[] data) throws IOException {
        ProcessRequest retval = null;
        String classPath = AVAILABLE_REQUEST_TYPES.get(getRequestOrResponeType(data));
        if (classPath != null) {
            try {
                Class<?> c = RequestAndResponseManager.class.getClassLoader().loadClass(classPath);
                retval = (ProcessRequest) c.newInstance();

                retval.parse(new DataInputStream(new ByteArrayInputStream(data)));
            } catch (Exception e) {
                log.error("Error deserializing IProcessRequest from byte array  : " + e.getMessage(), e);
                throw new IOException("Error deserializing IProcessRequest from byte array : " + e.getMessage());
            }
        } else {
            throw new IOException("Error unsupported IProcessRequest in request");
        }

        return retval;
    }

    /**
     * Method used to parse all available process responses and
     * return the appropriate deserialized type.
     * @param data the request data to parse.
     * @return a IProcessResponse or null if response wasn't supported.
     * @throws IOException 
     */
    public static ProcessResponse parseProcessResponse(byte[] data) throws IOException {
        ProcessResponse retval = null;
        String classPath = AVAILABLE_RESPONSE_TYPES.get(getRequestOrResponeType(data));
        if (classPath != null) {
            try {
                Class<?> c = RequestAndResponseManager.class.getClassLoader().loadClass(classPath);
                retval = (ProcessResponse) c.newInstance();

                retval.parse(new DataInputStream(new ByteArrayInputStream(data)));
            } catch (Exception e) {
                log.error("Error deserializing IProcessResponse from byte array  : " + e.getMessage(), e);
                throw new IOException("Error deserializing IProcessResponse from byte array  : " + e.getMessage());
            }
        } else {
            throw new IOException("Error unsupported IProcessResponse in request");
        }

        return retval;
    }

    /**
     * Help method used to transform a process request to a byte array.
     * @param request to serialize 
     * @return a serialized representation of the request
     * @throws IOException if error occurred during serialization
     */
    public static byte[] serializeProcessRequest(ProcessRequest request) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        request.serialize(dos);
        return baos.toByteArray();
    }

    /**
     * Help method used to transform a process response to a byte array.
     * @param response to serialize 
     * @return a serialized representation of the response
     * @throws IOException if error occurred during serialization
     */
    public static byte[] serializeProcessResponse(ProcessResponse response) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        response.serialize(dos);
        return baos.toByteArray();
    }

    /**
     * Method used to dynamically register a custom an available process request.
     * 
     * @param requestTypeId a unique id related that should be the first integer in the
     * data byte array.
     * @param classPath class path to the process request that should be generated.
     */
    public static void registerCustomProcessRequest(int requestTypeId, String classPath) {
        AVAILABLE_REQUEST_TYPES.put(requestTypeId, classPath);
    }

    /**
     * Method used to dynamically register a custom an available process response.
     * 
     * @param responseTypeId a unique id related that should be the first integer in the
     * data byte array.
     * @param classPath class path to the process response that should be generated.
     */
    public static void registerCustomProcessResponse(int responseTypeId, String classPath) {
        AVAILABLE_RESPONSE_TYPES.put(responseTypeId, classPath);
    }

    /**
     * Method to remove a custom process request from available custom process request
     * 
     * @param requestTypeId unique id of process request to remove.
     */
    public static void unregisterCustomProcessRequest(int requestTypeId) {
        AVAILABLE_REQUEST_TYPES.remove(requestTypeId);
    }

    /**
     * Method to remove a custom process response from available custom process response
     * 
     * @param responseTypeId unique id of process response to remove.
     */
    public static void unregisterCustomProcessResponse(int responseTypeId) {
        AVAILABLE_RESPONSE_TYPES.remove(responseTypeId);
    }

    /**
     * 
     * @return a set of available process request id's.
     */
    public static Set<Integer> availableProcessRequestTypes() {
        return AVAILABLE_REQUEST_TYPES.keySet();
    }

    /**
     * 
     * @return a set of available process response id's.
     */
    public static Set<Integer> availableProcessResponseTypes() {
        return AVAILABLE_RESPONSE_TYPES.keySet();
    }

    private static int getRequestOrResponeType(byte[] data) throws IOException {
        int retval = 0;
        if (data != null) {
            DataInputStream dais = new DataInputStream(new ByteArrayInputStream(data));
            retval = dais.readInt();
        }
        return retval;
    }
}
