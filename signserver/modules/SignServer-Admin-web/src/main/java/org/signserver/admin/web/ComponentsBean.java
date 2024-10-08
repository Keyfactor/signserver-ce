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
package org.signserver.admin.web;

import jakarta.enterprise.context.RequestScoped;
import jakarta.faces.component.UIComponent;
import jakarta.inject.Named;

import java.io.Serializable;

@Named("components")
@RequestScoped
public class ComponentsBean implements Serializable {

    private UIComponent buttonSubmit;
    private UIComponent buttonEdit;
    private UIComponent itemSelect;
    private UIComponent buttonNext;
    private UIComponent buttonAdd;

    public UIComponent getButtonSubmit() {
        return buttonSubmit;
    }

    public void setButtonSubmit(UIComponent buttonSubmit) {
        this.buttonSubmit = buttonSubmit;
    }

    public UIComponent getItemSelect() {
        return itemSelect;
    }

    public void setItemSelect(UIComponent itemSelect) {
        this.itemSelect = itemSelect;
    }

    public UIComponent getButtonNext() {
        return buttonNext;
    }

    public void setButtonNext(UIComponent buttonNext) {
        this.buttonNext = buttonNext;
    }

    public UIComponent getButtonAdd() {
        return buttonAdd;
    }

    public void setButtonAdd(UIComponent buttonAdd) {
        this.buttonAdd = buttonAdd;
    }

    public UIComponent getButtonEdit() {
        return buttonEdit;
    }

    public void setButtonEdit(UIComponent buttonEdit) {
        this.buttonEdit = buttonEdit;
    }
}