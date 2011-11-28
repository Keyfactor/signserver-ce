<%-- 
    Author     : Markus Kilås
    Version    : $Id$
--%>
<%@page contentType="text/html" pageEncoding="UTF-8" isErrorPage="true" import="java.io.*" %>
<% Object message = request.getAttribute("javax.servlet.error.message"); %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="stylesheet" href="publicweb.css" type="text/css"/>
        <title>SignServer - Error report</title>
    </head>
    <body>
        <div id="container1">
            <%@include file="../WEB-INF/jspf/header.jspf" %>

            <h2 style="margin-top: 4em;">HTTP Status 503 - Service Temporally Unavailable</h2>

            <p>
                The server is currently unable to handle the request:<br/>
                <b><%=message %></b>
            </p>
                        
            <p>&nbsp;</p>
            
            <p>
                More information might be available in the server logs.
            </p>

            <%@include file="../WEB-INF/jspf/footer.jspf" %>
        </div>
    </body>
</html>
