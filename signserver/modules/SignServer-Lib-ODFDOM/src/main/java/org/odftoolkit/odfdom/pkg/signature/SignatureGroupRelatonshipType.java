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

/**
 * Enum to specify how all signatures in same DocumentSignatureGroup are related to each other
 * 
 * @author aziz.goktepe (aka rayback_2)
 *
 * patch originally created for SignServer project {@link http://www.signserver.org}
 */
public enum SignatureGroupRelatonshipType {

    AllSignaturesSignSameFileEntries, //all signatures in signature group are signing same set of file entries
    AllSignaturesSignedBySameKey, //all signatures in a signature group are signed by same private key
    SingleDocumentSignatureInGroup, //there's only one signature in this group. Since it can relate to itself in any and all ways, we need separate enum entry for it.
    Unknown
}
