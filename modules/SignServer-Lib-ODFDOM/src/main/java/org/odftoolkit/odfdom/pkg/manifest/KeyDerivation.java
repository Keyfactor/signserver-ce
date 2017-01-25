/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 * 
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
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
package org.odftoolkit.odfdom.pkg.manifest;


public class KeyDerivation {

    private String _name;
    private String _salt;
    int _iterationCount=0;

    public KeyDerivation() {
    }

    public KeyDerivation(String name, String salt, int iterationCount) {
        _name=name;
        _salt=salt;
        _iterationCount=iterationCount;
    }

    public void setName(String name) {
        _name=name;
    }

    public String getName() {
        return _name;
    }

    public void setSalt(String salt) {
        _salt=salt;
    }

    public String getSalt() {
        return _salt;
    }

    public void setIterationCount(int iterationCount) {
        _iterationCount=iterationCount;
    }
    
    public int getIterationCount() {
        return _iterationCount;
    }

}
