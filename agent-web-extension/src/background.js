var desktopIsOn = false;

function processOperation(data, sender, response) {

    if (data.command === "desktopStatus") {
        response(desktopIsOn);
    } else {

        var funcToExec = null;
        var finalCommandName = data.command + "Wrapper";

        for (f in window.SignerDesktopClient) {
            if (f == finalCommandName) {
                console.log("Function called: " + f);
                funcToExec = window.SignerDesktopClient[f];
            }
        }

        if (funcToExec != null) {
            funcToExec(data).success(response).error(response);
        }
    }

    return true;
}

function browser() {
    if (chrome !== undefined) {
        return chrome;
    } else {
        return browser;
    }
}

browser().runtime.onMessageExternal.addListener(processOperation);

function callbackOpenClose(connectionStatus) {
    if (connectionStatus === 1) {
        console.log("Connected on Server");
        desktopIsOn = true;
    } else {
        console.log("Warn user to download/execute Agent-Desktop AND try again in 3000ms");

        desktopIsOn = false;

        // Try again in 3000ms        
        window.SignerDesktopClient.connect(callbackOpenClose, callbackOpenClose, callbackError);
    }
}

function callbackError(event) {
    console.log(event);
    if (event.error !== undefined) {
        if (event.error !== null && event.error !== 'null') {            
            // @todo mandar para o response atual            
            console.log(event.error);
        } else {
            console.log(event);
        }
    }
}

window.SignerDesktopClient.setDebug(true);
window.SignerDesktopClient.connect(callbackOpenClose, callbackOpenClose, callbackError);