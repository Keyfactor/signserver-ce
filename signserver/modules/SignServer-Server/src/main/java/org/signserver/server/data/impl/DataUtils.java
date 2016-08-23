/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.data.impl;

import java.util.Iterator;
import java.util.ServiceLoader;

/**
 *
 * @author user
 */
public class DataUtils {
    
    public static DataFactory createDataFactory() {
        final DataFactory result;
        Iterator<DataFactory> iterator = ServiceLoader.load(DataFactory.class).iterator();
        if (iterator.hasNext()) {
            result = iterator.next();
        } else {
            result = new DefaultDataFactory();
        }
        return result;
    }

}
