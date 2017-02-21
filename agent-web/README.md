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
function callback(connectionStatus) {
    if (connectionStatus === 1) {
        console.log("Connected on Server");
        clearInterval(tryAgainTimeout);
    } else {
        console.log("Warn user to download/execute Agent-Desktop AND try again in 5000ms");

        // Try again in 5000ms
        tryAgainTimeout = setTimeout(function () {
            window.SignerDesktopClient.connect(callback);
        }, 5000);
    }This client of Signer Desktop Client doesnt depends of any other library.
}

window.SignerDesktopClient.connect(callback);
```

**Lista All Certificates in Token**

```javascript
function listAllCertificates() {
    window.SignerDesktopClient.listCerts(password).then(function (response) {        
        console.log(response);        
    });
}
```

## Documentation

* [Full Documentation](https://rawgit.com/demoiselle/signer/master/agent-web/docs/index.html)