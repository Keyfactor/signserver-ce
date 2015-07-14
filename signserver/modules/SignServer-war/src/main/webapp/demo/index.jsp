<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="stylesheet" href="../publicweb.css" type="text/css"/>
        <link rel="shortcut icon" href="/signserver/favicon.png"/>
        <title>SignServer</title>
    </head>
    <body>
        <div id="container1">
            <%@include file="../WEB-INF/jspf/header.jspf" %>
            <%@include file="../WEB-INF/jspf/demo_menu.jspf" %>

            <h2 style="margin-top: 4em;">Signing and Validation Demo</h2>

            <p>
                The demo web pages shows how calls to the different
                signers and validators can be made using HTTP. The pages also serves as an
                easy way of testing the installation and with small adjustments
                could also be used in production to allow users to submit
                content from a web browser.
            </p>

            <p>
                Please see the documentation for how to setup the different
                signers and validators.
            </p>

            <%@include file="../WEB-INF/jspf/footer.jspf" %>
        </div>
    </body>
</html>
