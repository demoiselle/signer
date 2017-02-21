# Client for Desktop Signer

##  Basic Usage

**Import in HTML**

This client to access local functions of Signer Desktop Client doesnt depends of any other library.

```html
<html>

    <head>
        <title>TITLE</title>

        <!-- Import client desktop signer -->
        <script src="SignerDesktopClient.min.js" type="text/javascript"></script>
    <head>

    <!-- HTML Code -->

    <!-- ... -->
</html>    
```

**Start Connection**

```javascript
function callback(connectionStatus) {    
    if (connectionStatus) {
        console.log("Connected on Server");
    } else {
        console.log("Download/Execute Agent-Desktop");

        // Try again in 3000ms
        setTimeout(callback, 3000);
    }
}

window.SignerDesktopClient.connect(callback);
```

## Documentation

* [Full Documentation](https://rawgit.com/demoiselle/signer/master/agent-web/docs/index.html)