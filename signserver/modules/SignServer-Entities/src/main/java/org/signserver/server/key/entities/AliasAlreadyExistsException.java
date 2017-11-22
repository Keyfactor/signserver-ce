/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.key.entities;

/**
 *
 * @author markus
 */
public class AliasAlreadyExistsException extends Exception {
    
    private String alias;

    public AliasAlreadyExistsException(String keyAlias) {
        super("Duplicate alias: " + keyAlias);
        this.alias = keyAlias;
    }

    public String getAlias() {
        return alias;
    }
    
}
