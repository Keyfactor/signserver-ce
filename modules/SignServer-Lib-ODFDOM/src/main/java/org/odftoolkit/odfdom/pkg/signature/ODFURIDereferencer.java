/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 *
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
 * Copyright 2009 IBM. All rights reserved.
 *
 * Use is subject to license terms.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0. You can also
 * obtain a copy of the License at http://odftoolkit.org/docs/license.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ************************************************************************/
package org.odftoolkit.odfdom.pkg.signature;

import java.io.InputStream;

import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;

import org.odftoolkit.odfdom.doc.OdfDocument;

/**
 * Implementation of URI Dereferencer for ODF
 * 
 * @author aziz.goktepe (aka rayback_2)
 *
 * patch originally created for SignServer project {@link http://www.signserver.org}
 */
public class ODFURIDereferencer implements URIDereferencer {

    OdfDocument odfDoc;
    URIDereferencer defaultURIDereferencer;

    public ODFURIDereferencer(OdfDocument pOdfDocument,
            URIDereferencer pDefaultURIDereferencer) {
        odfDoc = pOdfDocument;
        defaultURIDereferencer = pDefaultURIDereferencer;
    }

    @Override
    public Data dereference(URIReference arg0, XMLCryptoContext arg1)
            throws URIReferenceException {

        String partPath = arg0.getURI().toString();

        // see if our document contains this part, if not dereference using
        // default dereferencer
        if (!odfDoc.getPackage().contains(partPath)) {
            return defaultURIDereferencer.dereference(arg0, arg1);
        }

        try {
            // return part content as octet stream data
            InputStream is = odfDoc.getPackage().getInputStream(partPath);
            OctetStreamData retData = new OctetStreamData(is);

            return retData;

        } catch (Exception e) {
            throw new URIReferenceException(e);
        }
    }
}
