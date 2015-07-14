<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="stylesheet" href="../publicweb.css" type="text/css"/>
        <link rel="shortcut icon" href="/signserver/favicon.png"/>
        <title>XAdES Validation Demo - SignServer</title>
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


            <h3 style="margin-top: 4em;">XML Validation Demo</h3>
            <form id="recievefile" action="../worker/XAdESValidator"
                  method="post" enctype="multipart/form-data">

                <fieldset>
                    <input type="hidden" name="processType" value="validateDocument"/>
                </fieldset>

                <p>Simply upload a XML document signed with XAdES-BES to the XAdES validator and you will get
                    back the status of validity ("VALID" or "INVALID").</p>

                <table width="100%" border="0" cellspacing="3" cellpadding="3">
                    <tr id="Row2">
                        <td style="width: 50%" valign="top" align="right">
                            Select XML file to upload for validation
                        </td>
                        <td style="width: 50%" valign="top">
                            <input type="file" name="filerecievefile" />
                            <input type="submit" name="buttonrecievefile"
                                   onclick="return check()" value="Submit" /><br />
                            <br />
                        </td>
                    </tr>
                </table>
            </form>

            <%@include file="../WEB-INF/jspf/footer.jspf" %>
        </div>
    </body>
</html>
