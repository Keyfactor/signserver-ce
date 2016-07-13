/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.common.data;

import org.signserver.common.ProcessRequest;

/**
 *
 * @author user
 */
public class TBNLegacyRequest extends TBNRequest {

    private final ProcessRequest legacyRequest;

    public TBNLegacyRequest(ProcessRequest legacyRequest) {
        this.legacyRequest = legacyRequest;
    }

    public ProcessRequest getLegacyRequest() {
        return legacyRequest;
    }
    
}
