<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="stylesheet" href="../publicweb.css" type="text/css"/>
        <link rel="stylesheet" href="demo.css" type="text/css"/>
        <script type="text/javascript" src="demo.js"></script>
        <link rel="shortcut icon" href="/signserver/favicon.png"/>
        <title>PDF Signing Demo - SignServer</title>
    </head>
    <body>
        <div id="container1">
            <%@include file="../WEB-INF/jspf/header.jspf" %>
            <%@include file="../WEB-INF/jspf/demo_menu.jspf" %>


            <h3>PDF Signing Demo</h3>
            <p>
                Simply upload a PDF document (small please) to the PDF signer
                and you will get back the same PDF, but signed by SignServer.
                This is a central organization signature.
            </p>
            <form id="recievefile" action="../worker/PDFSigner" method="post" enctype="multipart/form-data" accept-charset="ISO-8859-1">
                <table width="100%" border="0" cellspacing="3" cellpadding="3">
                    <tr id="Row2">
                        <td valign="top" align="right">Select PDF file to upload and sign</td>
                        <td valign="top">
                            <input id="fileInput" type="file" name="filerecievefile"/>
                        </td>
                    </tr>
                    <tr id="Row1">
                        <td valign="top" align="right">Password (if required):</td>
                        <td valign="top">
                            <input type="password" name="REQUEST_METADATA.pdfPassword"/>
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
                You can display the signature very nicely in Acrobat reader with signing plug-ins. If verified correctly you will get a green check in the signature field.
            </p>
            <p>
                If you want to verify the signed PDFs nicely you must download the CA certificate from your CA and install it in acrobat reader.
            </p>
            <ul>
                <li>You can download Acrobat Reader from Adobe (note that the GNU/Linux version has been discontinued).</li>
                <li>Download the root CA certificate and install in Acrobat reader (v8) in <i>Document->Manage Trusted Identities->Display: Certificates->Add Contacts</i>. Edit Trust and enable at least <i>Signatures and as a trusted root</i></li>
            </ul>

            <%@include file="../WEB-INF/jspf/footer.jspf" %>
        </div>
    </body>
</html>
