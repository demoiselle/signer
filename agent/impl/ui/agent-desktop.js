angular.module('agent-desktop').factory('sadService', ['$q', '$rootScope', function ($q, $rootScope) {
    var service = {};
    var defer = null;
    var ws = new WebSocket("ws://localhost:9091/");
    ws.onmessage = function (response) {
        defer.resolve(JSON.parse(response.data));
    };
    function execute(request) {
        defer = $q.defer();
        ws.send(JSON.stringify(request));
        return defer.promise;
    }
    service.signer = function (alias, provider, content, signaturePolicy) {
        var signerCommand = {
            command: 'signer',
            type: 'raw',
            format: 'text',
            compacted: false,
            alias: alias,
            signaturePolicy: signaturePolicy,
            provider: provider,
            content: content
        }
        var promise = execute(signerCommand);
        return promise;
    }
    service.signer = function (alias, password, provider, content, signaturePolicy) {
        var signerCommand = {
            command: 'signer',
            type: 'raw',
            format: 'text',
            compacted: false,
            alias: alias,
            signaturePolicy: signaturePolicy,
            password: password,
            provider: provider,
            content: content
        }
        var promise = execute(signerCommand);
        return promise;
    }
    service.logoutpkcs11 = function () {
        var logoutPKCS11Command = {
            command: 'logoutpkcs11'
        }
        ws.send(JSON.stringify(logoutPKCS11Command));
    }
    service.status = function () {
        var statusCommand = {
            command: 'status'
        }
        var promise = execute(statusCommand);
        return promise;
    }
    service.listcerts = function (password) {
        var listcertsCommand = {
            command: 'listcerts',
            password: password
        }
        var promise = execute(listcertsCommand);
        return promise;
    }
    service.listpolicies = function () {
        var listpoliciesCommand = {
            command: 'listpolicies'
        }
        var promise = execute(listpoliciesCommand);
        return promise;
    }
    service.getfiles = function () {
        var getfileCommand = {
            command: 'getfiles'
        }
        var promise = execute(getfileCommand);
        return promise;
    }
    service.signerfile = function (alias, provider, content, signaturePolicy) {
        var signerCommand = {
            command: 'filesigner',
            type: 'raw',
            format: 'text',
            compacted: false,
            alias: alias,
            signaturePolicy: signaturePolicy,
            provider: provider,
            content: content
        }
        console.log(signerCommand);
        var promise = execute(signerCommand);
        return promise;
    }

    service.shutdown = function () {
        var shutdownCommand = {
            command: 'shutdown'
        }
        ws.send(JSON.stringify(shutdownCommand));
    }
    return service;
}]);
