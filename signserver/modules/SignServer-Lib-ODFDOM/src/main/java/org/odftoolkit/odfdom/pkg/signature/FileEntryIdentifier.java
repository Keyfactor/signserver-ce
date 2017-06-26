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


/*
 * identifies a part by full path and media type 
 * NOTE : whereas part path alone is sufficient media type is used in reference generation (text/xml parts are transformed using c14n, others not), so included it is
 * 
 * @author aziz.goktepe (aka rayback_2)
 *
 * patch originally created for SignServer project {@link http://www.signserver.org}
 */
class FileEntryIdentifier {

    String fullPath;
    String mediaType;

    public String getFullPath() {
        return fullPath;
    }

    public String getMediaType() {
        return mediaType;
    }

    public FileEntryIdentifier(String pFullPath, String pMediaType) {
        fullPath = pFullPath;
        mediaType = pMediaType;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof FileEntryIdentifier) {
            FileEntryIdentifier partIdent = (FileEntryIdentifier) obj;
            return this.getMediaType().equals(partIdent.getMediaType()) && this.getFullPath().equals(partIdent.getFullPath());
        }

        return false;
    }
}
