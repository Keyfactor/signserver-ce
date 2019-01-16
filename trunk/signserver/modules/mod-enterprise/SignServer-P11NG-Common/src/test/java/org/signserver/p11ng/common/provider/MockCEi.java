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
package org.signserver.p11ng.common.provider;

import java.util.Arrays;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CEi;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CK_NOTIFY;
import org.pkcs11.jacknji11.NativePointer;

/**
 * Mock implementation of the JackNJI cryptoki interface used by cache
 * interface unit tests.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class MockCEi extends CEi {
    // Logger for this class
    private final static Logger LOG = Logger.getLogger(MockCEi.class);
    
    private final long[] slotList;
    
    int findObjectsCalls = 0;
    int getAttributeValueCalls = 0;
    int unwrapKeyCalls = 0;
    
    public MockCEi(final long[] slotList) {
        super(null);
        this.slotList = slotList;
    }

    @Override
    public void Initialize() {
        // do nothing here
    }

    @Override
    public long[] GetSlotList(boolean tokenPresent) {
        return slotList;
    }

    @Override
    public long[] FindObjects(long session, CKA... templ) {
        findObjectsCalls++;
        
        String alias = null;
        byte[] subject = null;
        byte[] id = null;
        
        // This is hardcoded for unwrapkey unit tests 
        if (templ.length == 1 && templ[0].type == CKA.CLASS) {
            return new long[]{1368L, 1369L};
        }
        
        for (final CKA cka : templ) {
            if (cka.type == CKA.LABEL) {
                alias = cka.getValueStr();
            } else if (cka.type == CKA.SUBJECT) {
                subject = cka.getValue();
            } else if (cka.type == CKA.ID) {
                id = cka.getValue();
            }
            }
        
        // return the hash code of the alias string or subject as a dummy object ID
        // to be able to determine that the FindObjects result is releated
        // to the expected arguments
        if (alias != null) {
            return new long[] {alias.hashCode()};
        } else if (subject != null) {
            return new long[] {Arrays.hashCode(subject)};
        } else if (id != null) {
            return new long[] {Arrays.hashCode(id)};
        } else {
            LOG.error("No CKA type variant found for computing dummy ID");
            return null;
        }
    }

    @Override
    public CKA GetAttributeValue(long session, long object, long cka) {
        getAttributeValueCalls++;
        
        // return the the object ID as dummy value to be able to distinguish
        // results using different call inputs when testing caching
        return new CKA(CKA.ID, object);
    }
    
    @Override
    public void DestroyObject(long session, long object) {
        // do nothing here
    }

    @Override
    public long UnwrapKey(long session, CKM mechanism, long unwrappingKey, byte[] wrappedKey, CKA... templ) {
        unwrapKeyCalls++;
        return unwrappingKey + 31;
    }

    //  Overriding is required for unwrap key unit tests
    @Override
    public long OpenSession(long slotID, long flags, NativePointer application, CK_NOTIFY notify) {
        return -1;
    }

}
