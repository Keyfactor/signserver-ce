<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="stylesheet" href="../publicweb.css" type="text/css"/>
        <link rel="shortcut icon" href="../favicon.png"/>
        <title>SignServer - ClientCLI Download</title>
    </head>
    <body>
        <div id="container1">
            <%@include file="../WEB-INF/jspf/header.jspf" %>
            <jsp:useBean class="org.signserver.web.SettingsBean" id="settings"/>

            <h2>ClientCLI Download</h2>

            <p>
                If enabled, a binary distribution (zip-file) with the SignServer 
                ClientCLI command line signing client can be downloaded from this page.
            </p>

            <c:choose>
                <c:when test="${settings.webClientCLIDistAvailable}">
                    <b><a href="signserver-clientcli.zip">signserver-clientcli.zip</a> [<c:out value="${settings.webClientCLIDistSize}"/>]</b>
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
