<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="stylesheet" href="publicweb.css" type="text/css"/>
        <link rel="shortcut icon" href="/signserver/favicon.png"/>
        <title>SignServer</title>
    </head>
    <body>
        <div id="container1">
            <%@include file="WEB-INF/jspf/header.jspf" %>
            <jsp:useBean class="org.signserver.web.SettingsBean" id="settings"/>

            <h4 style="margin-top: 4em;">Local Resources</h4>
            <ul class="resourcesList">
                <li><a href="demo/">Signing and Validation Demo</a></li>
                <li><a href="healthcheck/signserverhealth">Health Check</a></li>
                <c:if test="${settings.webDocEnabled}">
                    <li><a href="doc/">Documentation</a></li>
                </c:if>
                <c:if test="${settings.webAdminGUIDistEnabled}">
                    <li><a href="admingui-dist/">AdminGUI Download</a></li>
                </c:if>
            </ul>

            <h4>Online Resources</h4>
            <ul class="resourcesList">
                <li><a href="http://www.signserver.org">SignServer Web Site</a></li>
            </ul>

            <%@include file="WEB-INF/jspf/footer.jspf" %>
        </div>
    </body>
</html>
