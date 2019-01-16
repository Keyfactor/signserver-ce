<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="stylesheet" href="../publicweb.css" type="text/css"/>
        <link rel="stylesheet" href="demo.css" type="text/css"/>
        <script type="text/javascript" src="demo.js"></script>
        <link rel="shortcut icon" href="../favicon.png"/>
        <title>MRTD SOD Signing Demo - SignServer</title>
    </head>
    <body onload="ldsVersionChanged()">
        <div id="container1">
            <%@include file="../WEB-INF/jspf/header.jspf" %>
            <%@include file="../WEB-INF/jspf/demo_menu.jspf" %>


            <h3>MRTD SOD Signing Demo</h3>
            <p>Enter the data for the data groups to be stored on the passport.</p>
            <p>Note 1: Please provide the hashes of the respective data groups if the signer is configured to accept hashes instead of the actual data.</p>
            <p>Note 2: When submitting this form using a web browser it is not possible to enter binary data directly into the input fields. Then first base64 encode the data and choose the Base64 encoding option and the signer will decode the data before signing it.</p>

            <form id="requestform" action="../sodworker/MRTDSODSigner" method="post">
                <p>
                    DG1: <input type="text" size="80" name="dataGroup1" value="PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4="/><br/>
                    DG2: <input type="text" size="80" name="dataGroup2" value="BTfUgfc6dXM0MoBS2jr5YmztlwKOILhJ9hFcIs12UZc="/><br/>
                    DG3: <input type="text" size="80" name="dataGroup3" value="idxq5/Bqn0a1Za8D6rDs4L9gJNNlm346HQNXPP6wtZ0="/><br/>
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
                <!-- a good test value, base64 encoded is PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4= -->
                <p>
                    Encoding of datagroups:<br/>
                    <input type="radio" name="encoding" value="binary"/>None<br/>
                    <input type="radio" name="encoding" value="base64" checked="checked"/>Base64
                </p>

                <p>
                    Request LDS version:<br/>
                    <input type="radio" name="ldsVersion" value="" id="ldsNo" checked="checked"/><label for="ldsNo">Unspecified</label><br/>
                    <input type="radio" name="ldsVersion" value="0107" id="lds0107"/><label for="lds0107">V1.7</label><br/>
                    <input type="radio" name="ldsVersion" value="0108" id="lds0108"/><label for="lds0108">V1.8</label><br/>
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
