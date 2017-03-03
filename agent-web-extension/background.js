/////////////////////////// 

function processOperation(data, sender, response) {

    console.log("data:::");
    console.log(data);

    var funcToExec = null;
    var finalCommandName = data.command + "Wrapper";

    for (f in window.SignerDesktopClient) {

        if (f == finalCommandName) {
            console.log(f);
            console.log(window.SignerDesktopClient[f]);
            console.log(typeof window.SignerDesktopClient[f]);

            funcToExec = window.SignerDesktopClient[f];
        }

    }

    if (funcToExec != null) {
        funcToExec(data).success(response);
    }

    // window.SignerDesktopClient.getFiles().success(response);
    return true;
}

chrome.runtime.onMessageExternal.addListener(processOperation);

function callbackOpenClose(connectionStatus) {
    if (connectionStatus === 1) {
        console.log("Connected on Server");
    } else {
        console.log("Warn user to download/execute Agent-Desktop AND try again in 3000ms");

        // Try again in 3000ms        
        window.SignerDesktopClient.connect(callbackOpenClose, callbackOpenClose, callbackError);
    }
}

function callbackError(event) {
    if (event.error !== undefined) {
        if (event.error !== null && event.error !== 'null') {
            console.log(event.error);
        } else {
            console.log(event);
        }
    }
}


// window.SignerDesktopClient.setUriServer("wss://localhost:9443");
window.SignerDesktopClient.setDebug(true);
window.SignerDesktopClient.connect(callbackOpenClose, callbackOpenClose, callbackError);
