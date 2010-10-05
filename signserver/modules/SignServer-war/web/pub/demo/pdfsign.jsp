<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="stylesheet" href="../publicweb.css" type="text/css"/>
        <title>PDF Signing Demo - SignServer</title>
        <style type="text/css">
            img {
                border: 0px;
            }

            div.header {
                font-size: 42px;
                font-weight: bold;
                margin-left: 2.5em;
                margin-top: 15px;
                font-style: italic;
            }

            fieldset {
                border-left: none;
                border-right: none;
                border-bottom: none;
                margin-top: 2em;
            }
        </style>
        <script type="text/javascript">
            function check()
            {
                if (document.recievefile.filerecievefile.value == '') {
                    alert("You must select a file");
                } else {
                    return true;
                }
                return false;
            }
        </script>
    </head>
    <body>
        <div id="container1">
            <%@include file="../WEB-INF/jspf/header.jspf" %>
            <%@include file="../WEB-INF/jspf/demo_menu.jspf" %>


            <h3 style="margin-top: 4em;">PDF Signing Demo</h3>
            <p>
                Simply upload a PDF document (small please) to the PDF signer
                and you will get back the same PDF, but signed by SignServer.
                This is a central organization signature.
            </p>
            <form id="recievefile" action="../process" method="post" enctype="multipart/form-data">
                <input type="hidden" name="workerName" value="PDFSigner"/>
                <table width="100%" border="0" cellspacing="3" cellpadding="3">
                    <tr id="Row2">
                        <td width="49%" valign="top" align="right">Select PDF file to upload and sign</td>
                        <td width="51%" valign="top">
                            <input type="file" name="filerecievefile"/>
                                <input type="submit" name="buttonrecievefile" onclick="return check()" value="Submit"/><br/><br/>
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
                <li>In Ubuntu you can enable the medibuntu repository and then <strong>apt-get install acroread acroread-plugins</strong>.</li>
                <li>You can also simply download Acrobat Reader from Adobe.</li>
                <li>Download the root CA certificate and install in Acrobat reader (v8) in <i>Document->Manage Trusted Identities->Display: Certificates->Add Contacts</i>. Edit Trust and enable at least <i>Signatures and as a trusted root</i></li>
            </ul>

            <%@include file="../WEB-INF/jspf/footer.jspf" %>
        </div>
    </body>
</html>
