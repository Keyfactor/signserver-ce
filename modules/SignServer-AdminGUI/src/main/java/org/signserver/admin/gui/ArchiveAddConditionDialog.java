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
package org.signserver.admin.gui;

/**
 * Dialog to add archive query conditions.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ArchiveAddConditionDialog extends AddConditionDialog {
    public ArchiveAddConditionDialog(java.awt.Frame parent, boolean modal) {
        super(ArchiveColumn.values(), parent, modal);
    }
}
