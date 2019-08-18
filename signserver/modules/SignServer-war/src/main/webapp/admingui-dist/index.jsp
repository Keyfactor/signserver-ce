<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="stylesheet" href="../publicweb.css" type="text/css"/>
        <link rel="shortcut icon" href="../favicon.png"/>
        <title>SignServer - AdminGUI Download</title>
    </head>
    <body>
        <div id="container1">
            <%@include file="../WEB-INF/jspf/header.jspf" %>
            <jsp:useBean class="org.signserver.web.SettingsBean" id="settings"/>

            <h2>AdminGUI Download</h2>
            
            <div style="border: thin solid gray; background-color: lightgray; float:left; padding: 0.5em; border-radius: 4px; -webkit-border-radius: 4px;">
                Note: The AdminGUI is deprecated and will be removed in a future version.<br/>
                Please, use the AdminWeb instead.
            </div>
            <div style="clear:both"/>
            <p>&nbsp</p>

            <p>
                If enabled, a binary distribution (zip-file) with the SignServer 
                AdminGUI desktop application can be downloaded from this page.
            </p>

            <c:choose>
                <c:when test="${settings.webAdminGUIDistAvailable}">
                    <b><a href="signserver-admingui.zip">signserver-admingui.zip</a> [<c:out value="${settings.webAdminGUIDistSize}"/>]</b>
                </c:when>
                <c:otherwise>
                    <p><b>Download not available</b></p>
                </c:otherwise>
            </c:choose>
                    
            
            <p>&nbsp;</p>        
            <p>&nbsp;</p>
            <p>
                <a href="../">Back</a>
            </p>

            <%@include file="../WEB-INF/jspf/footer.jspf" %>
        </div>
    </body>
</html>
