<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="stylesheet" href="../publicweb.css" type="text/css"/>
        <link rel="stylesheet" href="demo.css" type="text/css"/>
        <script type="text/javascript" src="demo.js"></script>
        <link rel="shortcut icon" href="../favicon.png"/>
        <title>Office Open XML Signing Demo - SignServer</title>
    </head>
    <body>
        <div id="container1">
            <%@include file="../WEB-INF/jspf/header.jspf" %>
            <%@include file="../WEB-INF/jspf/demo_menu.jspf" %>


            <h3>Office Open XML Signing Demo</h3>
            <p>
                Simply upload an Office Open XML document (ex: created using MS Office 2007; docx,xlsx,pptx) to the OOXMLSigner and you will get back the same document, but signed by the signserver. This is a central organization signature.
            </p>
            <p>
                <b>NOTE:</b> You might need to save the output to a file and change file extension accordingly.
            </p>
            <form id="recievefile" action="../worker/OOXMLSigner" method="post" enctype="multipart/form-data">
                <table width="100%" border="0" cellspacing="3" cellpadding="3">
                    <tr id="Row1">
                        <td valign="top" align="right">Select document to upload and sign</td>
                        <td valign="top">
                            <input id="fileInput" type="file" name="filerecievefile"/>
                        </td>
                    </tr>
                    <tr id="Row2">
                        <td valign="top" align="right">Additional meta data (set in the REQUEST_METADATA request parameter):</td>
                        <td valign="top">
                            <textarea name="REQUEST_METADATA" cols="40" rows="5"></textarea>
                        </td>
                    </tr>
                    <tr id="Row3">
                        <td valign="top" align="right">
                            &nbsp;
                        </td>
                        <td valign="top">
                            <input id="submitButton" type="submit" name="buttonrecievefile" value="Submit"/>
                        </td>
                    </tr>
                </table>
            </form>

            <h2>Verification of signature</h2>
            <p>
                You can display the signature very nicely in MS Office 2007.
            </p>
            <p>
                If you want to verify the signed documents nicely you must download the CA certificate from your CA and install it in Windows certificate store (for Windows users).
            </p>

            <%@include file="../WEB-INF/jspf/footer.jspf" %>
        </div>
    </body>
</html>
