# Client for Desktop Signer

##  Basic Usage

**Import in HTML**

This client of Signer Desktop Client does not depends of any other library.

```html
<html>

    <head>
        <title>TITLE</title>

        <!-- Import client desktop signer -->
        <script src="SignerDesktopClient.min.js" type="text/javascript"></script>
    <head>

    <!-- Code -->
</html>    
```

**Start Connection**

```javascript
var tryAgainTimeout;
function callbackOpenClose(connectionStatus) {
    if (connectionStatus === 1) {
        console.log("Connected on Server");
        clearInterval(tryAgainTimeout);
    } else {
        console.log("Warn user to download/execute Agent-Desktop AND try again in 5000ms");

        // Try again in 5000ms
        tryAgainTimeout = setTimeout(function () {
            window.SignerDesktopClient.connect(callbackOpenClose, callbackOpenClose, callbackError);
        }, 5000);
    }
}

function callbackError(event) {
    console.log(event);
}

window.SignerDesktopClient.connect(callbackOpenClose, callbackOpenClose, callbackError);
```

**Lista All Certificates in Token**

```javascript
function listAllCertificates() {
    window.SignerDesktopClient.listCerts(password)
        .success(function (response) {        
            console.log(response);        
        })
        .error(function (error) {        
            console.log(error);        
        })
}
```

## Documentation

* [Full Documentation](https://rawgit.com/demoiselle/signer/master/agent-web/docs/index.html)