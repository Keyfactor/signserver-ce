/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.common.signedrequest;

/**
 *
 * @author user
 */
public class SignedRequestException extends Exception {

    public SignedRequestException(String message) {
        super(message);
    }

    public SignedRequestException(String message, Throwable cause) {
        super(message, cause);
    }

    public SignedRequestException(Throwable cause) {
        super(cause);
    }
    
}
