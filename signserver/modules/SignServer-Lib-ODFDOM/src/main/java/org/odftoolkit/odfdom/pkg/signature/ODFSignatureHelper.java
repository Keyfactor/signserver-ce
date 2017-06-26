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

import java.security.Provider;

import javax.xml.crypto.dsig.XMLSignatureFactory;

/**
 * Helper class for signature creation/verification
 * 
 * @author aziz.goktepe (aka rayback_2)
 *
 * patch originally created for SignServer project {@link http://www.signserver.org}
 */
public class ODFSignatureHelper {

    /**
     * retrieve xml signature factory (jsr105provider)
     *
     * @return XMLSignatureFactory object
     * @throws Exception
     */
    public static XMLSignatureFactory CreateXMLSignatureFactory()
            throws Exception {
        final String providerName = System.getProperty("jsr105Provider",
                "org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI");
        try {
            return XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());
        } catch (InstantiationException e) {
            throw new Exception("Problem with JSR105 provider", e);
        } catch (IllegalAccessException e) {
            throw new Exception("Problem with JSR105 provider", e);
        } catch (ClassNotFoundException e) {
            throw new Exception("Problem with JSR105 provider", e);
        }
    }
}
