angular.module('agent-desktop').factory('daService', ['$q', '$rootScope', function ($q, $rootScope) {

    // We return this object to anything injecting our service
    var service = {};
    // Keep all pending requests here until they get responses
    var callbacks = {};
    // Create a unique callback ID to map requests to responses
    var currentCallbackId = 0;
    // Create our websocket object with the address to the websocket
    var ws = new WebSocket("ws://localhost:9091");

    ws.onopen = function () {
        console.log("Socket has been opened!");
    };

    ws.onmessage = function (message) {
        listener(JSON.parse(message.data));
    };

    function sendRequest(request) {
        var defer = $q.defer();
        var callbackId = getCallbackId();
        callbacks[callbackId] = {
            time: new Date(),
            cb: defer
        };
        request.callback_id = callbackId;
        console.log('Sending request', request);
        ws.send(JSON.stringify(request));
        return defer.promise;
    }

    function listener(data) {
        var messageObj = data;
        console.log("Received data from websocket: ", messageObj);
        // If an object exists with callback_id in our callbacks object, resolve it
        if (callbacks.hasOwnProperty(messageObj.callback_id)) {
            console.log(callbacks[messageObj.callback_id]);
            $rootScope.$apply(callbacks[messageObj.callback_id].cb.resolve(messageObj.data));
            delete callbacks[messageObj.callbackID];
        }
    }
    // This creates a new callback ID for a request
    function getCallbackId() {
        currentCallbackId += 1;
        if (currentCallbackId > 10000) {
            currentCallbackId = 0;
        }
        return currentCallbackId;
    }

    // Define a "getter" for getting customer data
    service.signer = function (alias, provider, content) {
        var signerCommand = {
            command: 'signer',
            param: {
                type: 'raw',
                format: 'text',
                compacted: false,
                alias: alias,
                provider: provider,
                content: content
            }
        }
        console.log(signerCommand);
        var promise = sendRequest(signerCommand);
        return promise;
    }

    service.status = function () {
        var statusCommand = {
            command: 'status'
        }
        var promise = sendRequest(statusCommand);
        return promise;
    }

    service.listcerts = function () {
        var listcertsCommand = {
            command: 'listcerts'
        }
        var promise = sendRequest(listcertsCommand);
        return promise;
    }

    service.shutdown = function () {
        var shutdownCommand = {
            command: 'shutdown'
        }
        var promise = sendRequest(shutdownCommand);
        return promise;
    }

    return service;

}]);