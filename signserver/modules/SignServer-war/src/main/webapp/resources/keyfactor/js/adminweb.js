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
/*
 * Contains JavaScript for the SignServer AdminWeb.
 * version: $Id: adminweb.js 9404 2018-06-26 05:56:14Z oskareriksson $ 
 */

/** Sets "checked" for a collection of checkboxes to the same as a source */
function toggleCheckboxes(source, checkboxes) {
    for (var i = 0; i < checkboxes.length; i++) {
        checkboxes[i].checked = source.checked;
    }
}

/** Display hidden elements (should remain hidden if JavaScript is disabled) */
document.getElementsByTagName('html')[0].className='jsEnabled';
