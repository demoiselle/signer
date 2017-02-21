// http://usejsdoc.org/

/**
 * Implementação de Promisse, pois como não sabemos a biblioteca que será usada 
 * para o desenvolvimento não podemos depender de alguma. 
 * 
 * @class
 */
var Promise = (function() {
    var callback = null;

	/**
	 * Method.
	 * @param {string} x - X param.
	 * @param {string} y - Y param.
	 * @param {string} z  - Z param.
	 * @memberof Promise
	 */
    this.then = function(cb) {
        callback = cb;
    };

    this.resolve = function(value) {
        callback(value);
    };

});

/**
 * Object used to comunicate with local WebSocket.
 * 
 * @class
 */
var SignerDesktopClient = (function() {

    var ws;
    var defer = null;

    var services = {
		/**
         * Method.
         * @param {string} x - X param.
         * @param {string} y - Y param.
         * @param {string} z  - Z param.
         * @memberof SignerDesktopClient
         */
        execute: function(request) {
            defer = new Promise();
            ws.send(JSON.stringify(request));
            return defer;
        },

		/**
         * Method.
         * @param {string} x - X param.
         * @param {string} y - Y param.
         * @param {string} z  - Z param.
         * @memberof MySingleton
         */
        connect: function(callback) {
            if (ws == null || ws.readyState != 1) {
                ws = new WebSocket("ws://localhost:9091/");
                ws.onopen = function(msg) {
                    if (callback)
                        callback(msg.target.readyState);
                }
                ws.onclose = function(msg) {
                    if (callback)
                        callback(msg.target.readyState);
                }
                ws.onmessage = function(response) {
                    defer.resolve(JSON.parse(response.data));
                };
            }
        },

        isConnected: function() {
            if (ws != null)
                return ws.readyState == 1 ? true : false;
            return false;
        },

        signer: function(alias, provider, content, signaturePolicy) {
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
            var promise = services.execute(signerCommand);
            return promise;
        },

        signerWithPassword: function(alias, password, provider, content, signaturePolicy) {
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
            var promise = services.execute(signerCommand);
            return promise;
        },

        logoutpkcs11: function() {
            var logoutPKCS11Command = {
                command: 'logoutpkcs11'
            }
            ws.send(JSON.stringify(logoutPKCS11Command));
        },

        status: function() {
            var statusCommand = {
                command: 'status'
            }
            var promise = services.execute(statusCommand);
            return promise;
        },

        listcerts: function(password) {
            var listcertsCommand = {
                command: 'listcerts',
                password: password
            }
            var promise = services.execute(listcertsCommand);
            return promise;
        },

        listpolicies: function() {
            var listpoliciesCommand = {
                command: 'listpolicies'
            }
            var promise = services.execute(listpoliciesCommand);
            return promise;
        },

        getfiles: function() {
            var getfileCommand = {
                command: 'getfiles'
            }
            var promise = services.execute(getfileCommand);
            return promise;
        },

        signerfile: function(alias, provider, content, signaturePolicy) {
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
            var promise = services.execute(signerCommand);
            return promise;
        },

        shutdown: function() {
            var shutdownCommand = {
                command: 'shutdown'
            }
            ws.send(JSON.stringify(shutdownCommand));
        }

    };

    return services;
})();

// Define globally if it doesn't already exist
if (window.SignerDesktopClient === undefined) {
    console.log("SignerDesktopClient started.")
    window.SignerDesktopClient = SignerDesktopClient();
} else {
    console.log("SignerDesktopClient already defined.");
}