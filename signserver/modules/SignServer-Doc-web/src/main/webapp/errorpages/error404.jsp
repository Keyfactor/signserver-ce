<%-- 
    Author     : Markus Kilås
    Version    : $Id$
--%>
<%@page contentType="text/html" pageEncoding="UTF-8" isErrorPage="true" import="java.io.*" session="false" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="stylesheet" href="<c:out value='${pageContext.servletContext.contextPath}'/>/publicweb.css" type="text/css"/>
        <link rel="shortcut icon" href="<c:out value='${pageContext.servletContext.contextPath}'/>/favicon.png"/>
        <title>SignServer - Error report</title>
    </head>
    <body>
        <div id="container1">
            <%@include file="../WEB-INF/jspf/header.jspf" %>

            <h2>HTTP Status 404 - <c:out value="${requestScope['javax.servlet.error.message']}"/></h2>

            <p>
                The requested resource could not be found:<br/>
                <b><c:out value="${requestScope['javax.servlet.error.message']}"/></b>
            </p>

            <%@include file="../WEB-INF/jspf/footer.jspf" %>
        </div>
    </body>
</html>
