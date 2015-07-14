<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="stylesheet" href="../publicweb.css" type="text/css"/>
        <link rel="shortcut icon" href="/signserver/favicon.png"/>
        <title>CMS Signing Demo - SignServer</title>
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


            <h3 style="margin-top: 4em;">CMS Signing Demo</h3>
            <form id="recievefile" action="../worker/CMSSigner"
                  method="post" enctype="multipart/form-data">

                <p>Simply upload a file to the CMS signer and you will get
                   	back the result signed in CMS format.</p>

                <table width="100%" border="0" cellspacing="3" cellpadding="3">
                    <tr id="Row1">
                        <td style="width: 50%" valign="top" align="right">
                            Select file to upload and sign
                        </td>
                        <td style="width: 50%" valign="top">
                            <input type="file" name="filerecievefile" />
                            <input type="submit" name="buttonrecievefile"
                                   onclick="return check()" value="Submit" /><br />
                            <br />
                        </td>
                    </tr>
                    <tr id="Row2">
                        <td style="width: 50%" valign="top" align="right">Detached signature:</td>
                        <td style="width: 50%" valign="top">
                            <input type="radio" name="REQUEST_METADATA.DETACHEDSIGNATURE" value="" checked="checked"/>Use default
                            <input type="radio" name="REQUEST_METADATA.DETACHEDSIGNATURE" value="TRUE"/>Detached
                            <input type="radio" name="REQUEST_METADATA.DETACHEDSIGNATURE" value="FALSE"/>Include content
                        </td>
                    </tr>
                    <tr id="Row2">
                        <td style="width: 50%" valign="top" align="right">Additional meta data (set in the REQUEST_METADATA request parameter):</td>
                        <td style="width: 50%" valign="top">
                            <textarea name="REQUEST_METADATA" cols="40" rows="5"></textarea>
                        </td>
                    </tr>
                    
                </table>
            </form>

            <%@include file="../WEB-INF/jspf/footer.jspf" %>
        </div>
    </body>
</html>