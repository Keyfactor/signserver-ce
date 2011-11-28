<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="stylesheet" href="../publicweb.css" type="text/css"/>
        <title>Generic Signing Demo - SignServer</title>
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


            <h3 style="margin-top: 4em;">Generic Signing Demo</h3>
            <p>
                The forms below can be used to request signing from any of the
                generic signers. The content to be signed can be submitted
                by <a href="#submit-by-input">direct input</a> in a text field
                optionally Base64 encoded or by <a href="#submit-by-upload">
                file upload</a>. In any case the name of the worker that should
                process the request needs to be specified.
            </p>

            <p>
                The name of all workers/signers available if all demo signers
                are configured are: PDFSigner, ODFSigner, OOXMLSigner,
                XMLSigner and CMSSigner.
            </p>

            <a name="submit-by-input"/>
            <fieldset id="submit-by-input">
                <legend>Sign by Direct Input</legend>

                <form id="requestform" action="../process" method="post">
                    <p>
                        Worker name: <input type="text" name="workerName"/>
                    </p>
                    <p>
                        Data:<br/>
                        <textarea name="data" cols="80" rows="20"></textarea><br/>
                        Encoding:
                        <select name="encoding">
                            <option value="" selected="selected">None</option>
                            <option value="base64">Base64</option>
                        </select>
                    </p>
                    <p>
                        <input type="submit" name="buttonrecievefile" value="Submit" /><br />
                    </p>
                </form>

            </fieldset>

            <a name="submit-by-upload"/>
            <fieldset id="submit-by-upload" class="tabset_content front">
                <legend>Sign by File Upload</legend>

                <form id="recievefile" action="../process" method="post" enctype="multipart/form-data">
                    <p>
                        Worker name: <input type="text" name="workerName"/>
                    </p>
                    <p>
                        File: <input type="file" name="filerecievefile"/>
                    </p>
                    <p>
                        <input type="submit" name="buttonrecievefile" onclick="return check()" value="Submit"/>
                    </p>
                </form>
            </fieldset>

            <%@include file="../WEB-INF/jspf/footer.jspf" %>
        </div>
    </body>
</html>
