<%-- 
    Author     : Marcus Lundblad
    Version    : $Id$
--%>
<%@page contentType="text/html" pageEncoding="UTF-8" isErrorPage="true" import="java.io.*" session="false" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="stylesheet" href="<c:out value='${pageContext.servletContext.contextPath}'/>/../javax.faces.resource/css/default.css.xhtml?ln=<%=org.signserver.web.common.ThemeHelper.getInstance().getTheme()%>" type="text/css"/>
        <link rel="stylesheet" href="<c:out value='${pageContext.servletContext.contextPath}'/>/../javax.faces.resource/css/cssLayout.css.xhtml?ln=<%=org.signserver.web.common.ThemeHelper.getInstance().getTheme()%>" type="text/css"/>
        <link rel="shortcut icon" href="${pageContext.servletContext.contextPath}'/>/../../javax.faces.resource/images/favicon.png.xhtml?ln=<%=org.signserver.web.common.ThemeHelper.getInstance().getTheme()%>"/>
        <title>SignServer - Error report</title>
    </head>
    <body>
        <%@include file="../WEB-INF/jspf/header.jspf" %>
        <div id="container1">

            <h2>HTTP Status 413 - Request entity too large</h2>

            <p>
                The request sent by the client was too large:<br/>
                <b><c:out value="${requestScope['javax.servlet.error.message']}"/></b>
            </p>
            
            <p>&nbsp;</p>
            
            <p>&nbsp;</p>

            <%@include file="../WEB-INF/jspf/footer.jspf" %>
        </div>
    </body>
</html>
