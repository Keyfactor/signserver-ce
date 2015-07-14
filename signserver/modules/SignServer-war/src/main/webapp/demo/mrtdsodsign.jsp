<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="stylesheet" href="../publicweb.css" type="text/css"/>
        <link rel="shortcut icon" href="/signserver/favicon.png"/>
        <title>MRTD SOD Signing Demo - SignServer</title>
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
            //<![CDATA[
            function getRadioCheckedValue(radio_name) {
                var oRadio = document.forms[0].elements[radio_name];
                for(var i = 0; i < oRadio.length; i++) {
                    if(oRadio[i].checked) {
                        return oRadio[i].value;
                    }
                }
                return '';
            }
            function ldsVersionChanged() {
                var ldsVersionValue = getRadioCheckedValue('ldsVersion');
                if (ldsVersionValue == "0108") {
                    document.getElementById('unicodeField').disabled = '';
                    if (document.getElementById('unicodeField').value == '') {
                        document.getElementById('unicodeField').value = '040000';
                    }
                } else {
                    document.getElementById('unicodeField').disabled = 'disabled';
                    document.getElementById('unicodeField').value = '';
                }
            }
        //]]>
    </script>
    </head>
    <body onload="ldsVersionChanged()">
        <div id="container1">
            <%@include file="../WEB-INF/jspf/header.jspf" %>
            <%@include file="../WEB-INF/jspf/demo_menu.jspf" %>


            <h3 style="margin-top: 4em;">MRTD SOD Signing Demo</h3>
            <p>Enter the data for the data groups to be stored on the passport.</p>
            <p>Note 1: Please provide the hashes of the respective data groups if the signer is configured to accept hashes instead of the actual data.</p>
            <p>Note 2: When submitting this form using a web browser it is not possible to enter binary data directly into the input fields. Then first base64 encode the data and choose the Base64 encoding option and the signer will decode the data before signing it.</p>

            <form id="requestform" action="../sod" method="post">
                <fieldset>
                    <input type="hidden" name="workerName" value="MRTDSODSigner"/>
                </fieldset>
                <p>
                    DG1: <input type="text" size="80" name="dataGroup1" value="Yy=="/><br/>
                    DG2: <input type="text" size="80" name="dataGroup2" value="Yy=="/><br/>
                    DG3: <input type="text" size="80" name="dataGroup3" value="Yy=="/><br/>
                    DG4: <input type="text" size="80" name="dataGroup4"/><br/>
                    DG5: <input type="text" size="80" name="dataGroup5"/><br/>
                    DG6: <input type="text" size="80" name="dataGroup6"/><br/>
                    DG7: <input type="text" size="80" name="dataGroup7"/><br/>
                    DG8: <input type="text" size="80" name="dataGroup8"/><br/>
                    DG9: <input type="text" size="80" name="dataGroup9"/><br/>
                    DG10: <input type="text" size="80" name="dataGroup10"/><br/>
                    DG11: <input type="text" size="80" name="dataGroup11"/><br/>
                    DG12: <input type="text" size="80" name="dataGroup12"/><br/>
                    DG13: <input type="text" size="80" name="dataGroup13"/><br/>
                    DG14: <input type="text" size="80" name="dataGroup14"/><br/>
                    DG15: <input type="text" size="80" name="dataGroup15"/><br/>
                    DG16: <input type="text" size="80" name="dataGroup16"/><br/>
                </p>
                <!-- if encoding = binary values will not be base64 decoded before use -->
                <!-- a good test value, base64 encoded is Yy== -->
                <p>
                    Encoding of datagroups:<br/>
                    <input type="radio" name="encoding" value="binary"/>None<br/>
                    <input type="radio" name="encoding" value="base64" checked="checked"/>Base64
                </p>

                <p>
                    Request LDS version:<br/>
                    <input type="radio" name="ldsVersion" value="" id="ldsNo" checked="checked" onchange="ldsVersionChanged()"/><label for="ldsNo">Unspecified</label><br/>
                    <input type="radio" name="ldsVersion" value="0107" id="lds0107" onchange="ldsVersionChanged()"/><label for="lds0107">V1.7</label><br/>
                    <input type="radio" name="ldsVersion" value="0108" id="lds0108" onchange="ldsVersionChanged()"/><label for="lds0108">V1.8</label><br/>
                    <label for="unicodeField">Unicode version:</label> <input type="text" size="6" name="unicodeVersion" id="unicodeField" value="040000"/>
                </p>
                <p>
                    Additional meta data (set in the REQUEST_METADATA request parameter):<br/>
                    <textarea name="REQUEST_METADATA" cols="40" rows="5"></textarea><br/>
                </p>
                <p>
                    <input type="submit" name="submit" value="Submit" /><br />
                </p>
            </form>

            <h2>Display signing certificate</h2>
            <p>View the current document signer certificate.</p>
            <p><a href="../sod?workerName=MRTDSODSigner&amp;displayCert=true">Display</a></p>

            <h2>Download signing certificate</h2>
            <p>Download the current document signer certificate in binary (der) format.</p>
            <p><a href="../sod?workerName=MRTDSODSigner&amp;downloadCert=true">Download</a></p>

            <%@include file="../WEB-INF/jspf/footer.jspf" %>
        </div>
    </body>
</html>
