// JavaScript used by the demo web pages
// 
// We do client side validation as we want to be both user friendly and at
// the same time send the requests directly to the stock SignServer
// process servlet

// Install listeners when the page is ready
document.addEventListener('DOMContentLoaded', function () {

    // Check file upload
    var submitButton = document.getElementById('submitButton');
    if (submitButton) {
        submitButton.onclick = function () {
            var fileInput = document.getElementById('fileInput');

            if (fileInput && fileInput.value === '') {
                alert("You must select a file");
            } else {
                return true;
            }
            return false;
        };
    }
    
    // Check ldsVersion on MRTDSOD page
    var ldsVersion = document.getElementsByName('ldsVersion');
    if (ldsVersion) {
        ldsVersion.onchange = function () {
            ldsVersionChanged();
        }
    }

});

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
    if (ldsVersionValue === "0108") {
        document.getElementById('unicodeField').disabled = '';
        if (document.getElementById('unicodeField').value === '') {
            document.getElementById('unicodeField').value = '040000';
        }
    } else {
        document.getElementById('unicodeField').disabled = 'disabled';
        document.getElementById('unicodeField').value = '';
    }
}
