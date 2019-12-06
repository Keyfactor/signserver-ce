/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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


import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.RequiredValidator;
import javax.faces.validator.ValidatorException;

import org.apache.log4j.Logger;

/**
 * Extended variant of RequiredValidator that only execute the validator if the
 * request was submitted with the in an attribute specified submit button
 * client ID.
 * 
 * 
 * Example usage:
<h:inputText value="#{someBean.componentForWhichValidationIsNotAllwaysRequired}">
    <f:validator validatorId="optionallyRequiredValidator" />
    <f:attribute name="requiredIfSubmittedWith" value="#{components.submitButton.clientId}" />
</h:inputText>
<h:commandButton 
    action="#{someBean.someMethodThatDoesntValidateRequired}">
</h:commandButton>
<h:commandButton 
    action="#{someBean.someMethodThatValidatesRequired}" binding="#{components.submitButton}"/>
 * 
 * @version $Id$
 */
@FacesValidator("optionallyRequiredValidator")
public class OptionallyRequiredValidator extends RequiredValidator {
    
    private static final Logger LOG = Logger.getLogger(OptionallyRequiredValidator.class);

    @Override
    public void validate(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        Object requiredIfSubmittedWith = component.getAttributes().get("requiredIfSubmittedWith");
        if (requiredIfSubmittedWith == null) {
            throw new IllegalArgumentException("Validator lack 'requiredIfSubmittedWith' attribute.");
        }
        
        Object andCheckboxSelected = component.getAttributes().get("andCheckboxSelected");
        
        // Find the right check box, if one
        boolean validate = true;
        if (andCheckboxSelected != null) {
            // Check if the check box is on
            validate = "on".equals(FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().get(andCheckboxSelected.toString()));
        }
        
        boolean required = false;
        if (validate) {
            // Check if any of the requiredIfSubmittedWith parameters exists
            for (String with : requiredIfSubmittedWith.toString().split(",")) {
                if (!with.trim().isEmpty()) {
                    required = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().containsKey(with.trim());   
                }
                if (required) {
                    break;
                }
            }
        }
        
        if (LOG.isTraceEnabled()) {
            LOG.trace(component.getClientId() + " validate: " + validate + " required: " + required + ", requiredIfSubmittedWith=" + requiredIfSubmittedWith + "andCheckboxSelected=" + andCheckboxSelected);
        }
        
        if(required) {
            super.validate(context, component, value);
        }
    }
}
