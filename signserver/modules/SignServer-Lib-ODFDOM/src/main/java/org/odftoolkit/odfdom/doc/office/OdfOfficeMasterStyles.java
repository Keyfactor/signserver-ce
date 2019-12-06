
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

   

package org.odftoolkit.odfdom.doc.office;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.doc.draw.OdfDrawLayerSet;
import org.odftoolkit.odfdom.doc.style.OdfStyleHandoutMaster;
import org.odftoolkit.odfdom.doc.style.OdfStyleMasterPage;
import org.odftoolkit.odfdom.OdfElement;
import org.odftoolkit.odfdom.dom.element.office.OfficeMasterStylesElement;
import org.w3c.dom.Node;

/**
 * Convenient functionalty for the parent ODF OpenDocument element
 *
 */
public class OdfOfficeMasterStyles extends OfficeMasterStylesElement
{
    
	private static final long serialVersionUID = 6598785919980862801L;
	private OdfDrawLayerSet mLayerSet;
    private OdfStyleHandoutMaster mHandoutMaster;
    private HashMap< String, OdfStyleMasterPage > mMasterPages;
    
    public OdfOfficeMasterStyles( OdfFileDom ownerDoc )
    {
        super( ownerDoc );
    }

    public OdfStyleHandoutMaster getHandoutMaster()
    {
        return mHandoutMaster;
    }

    public OdfDrawLayerSet getLayerSet()
    {
        return mLayerSet;
    }
    
    public OdfStyleMasterPage getMasterPage( String name )
    {
        if( mMasterPages != null )
            return mMasterPages.get(name);
        else
            return null;
    }

    public Iterator< OdfStyleMasterPage > getMasterPages()
    {
        if( mMasterPages != null )
            return mMasterPages.values().iterator();
        else
            return new ArrayList< OdfStyleMasterPage >().iterator();
    }            
    
    /** override this method to get notified about element insertion
     */
    @Override
	protected void onOdfNodeInserted( OdfElement node, Node refNode )
    {
        if( node instanceof OdfDrawLayerSet )
        {
            mLayerSet = (OdfDrawLayerSet)node;
        }
        else if( node instanceof OdfStyleHandoutMaster )
        {
            mHandoutMaster = (OdfStyleHandoutMaster)node;
        }
        else if( node instanceof OdfStyleMasterPage )
        {
            OdfStyleMasterPage masterPage = (OdfStyleMasterPage)node;
            
            if( mMasterPages == null )
                mMasterPages = new HashMap< String, OdfStyleMasterPage >();
            
            mMasterPages.put( masterPage.getStyleNameAttribute(), masterPage );
        }
    }
            
    /** override this method to get notified about element insertion
     */
    @Override
	protected void onOdfNodeRemoved( OdfElement node )
    {
        if( node instanceof OdfDrawLayerSet )
        {
            if( mLayerSet == (OdfDrawLayerSet)node )
                mLayerSet = null;
        }
        else if( node instanceof OdfStyleHandoutMaster )
        {
            if( mHandoutMaster == (OdfStyleHandoutMaster)node )
                mHandoutMaster = null;
        }
        else if( node instanceof OdfStyleMasterPage )
        {
            if( mMasterPages != null )
            {
                OdfStyleMasterPage masterPage = (OdfStyleMasterPage)node;
                mMasterPages.remove( masterPage.getStyleNameAttribute() );            
            }
        }
    }    
}
