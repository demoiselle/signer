// http://usejsdoc.org/

/**
 * @classdesc Object used to comunicate with local WebSocket.
 * @class
 */
var SignerDesktopClient = (function() {

    var ws;
    var defer = null;
    var uriServer = "ws://localhost:9091/";
    var isDebug = false;

    /**
     * Set URI to use in communication.
     * 
     * @private
     * @param {string} message - Uri to use.
     * @memberof SignerDesktopClient
     */
    var log = function(message) {
        if (isDebug) {
            console.log(message);
        }
    };

    var services = {
		/**
         * Set URI to use in communication.
		 * 
         * @instance
		 * @default ws://localhost:9091/
         * @param {string} uri - Uri to use.
         * @memberof SignerDesktopClient
         */
        setUriServer: function(uri) {
            log("Setting URI to " + uri);
            uriServer = uri;
        },

		/**
         * Set debug true or false.
         * 
         * @instance
         * @param {boolean} isToDebug - 
         * @memberof SignerDesktopClient
         */
        setDebug: function(isToDebug) {
            log("Setting debug on to " + (isToDebug ? "ON" : "OFF"));
            isDebug = isToDebug;
        },

		/**
         * Method used to start connection with local WebSocket server.
         * 
         * @instance
         * @param {function} callback - Callback invoked on OPEN and CLOSE connection.
         * @memberof SignerDesktopClient
         */
        connect: function(callback) {
            if (ws == null || ws.readyState != 1) {
                log("Connecting on " + uriServer);
                ws = new WebSocket(uriServer);

                ws.onopen = function(msg) {
                    log("On Open");
                    if (callback)
                        callback(msg.target.readyState);
                }

                ws.onclose = function(msg) {
                    log("On Close");
                    if (callback)
                        callback(msg.target.readyState);
                }

                ws.onmessage = function(response) {
                    log("On Message");
                    defer.resolve(JSON.parse(response.data));
                };
            }
        },

		/**
         * Verify status of connection with WebSocket server.
         * 
         * @instance
		 * @return {boolean} - True for connection is up, false if is down.  
         * @memberof SignerDesktopClient
         */
        isConnected: function() {
            if (ws != null)
                return ws.readyState == 1 ? true : false;
            return false;
        },

        /**
		 * Signer content using some parameters.
         * 
         * @instance
		 * @param {string} alias - Alias of certificate to use in sign
		 * @param {string} provider - The provider (Token, SmartCard...)
		 * @param {string} content - The text to sign
		 * @param {string} signaturePolicy - he policy to use in signature 
		 * @return Promisse - The promisse when is finished. 
		 * @memberof SignerDesktopClient
		 */
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

        /**
		 * Signer content using some parameters and password.
         * 
         * @instance
		 * @param {string} alias - Alias of certificate to use in sign
		 * @param {string} password - The password of certificate
		 * @param {string} provider - The provider (Token, SmartCard...)
		 * @param {string} content - The text to sign
		 * @param {string} signaturePolicy - he policy to use in signature 
		 * @return Promisse - The promisse when is finished. 
		 * @memberof SignerDesktopClient
		 */
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

        /**
		 * Logout of access token.
         * 
         * @instance
		 * @memberof SignerDesktopClient
		 */
        logoutPKCS11: function() {
            var logoutPKCS11Command = {
                command: 'logoutpkcs11'
            }
            ws.send(JSON.stringify(logoutPKCS11Command));
        },

        /**
		 * Verify Desktop status. 
         * 
         * @instance
		 * @return Promisse - The promisse when is finished. 
		 * @memberof SignerDesktopClient
		 */
        status: function() {
            var statusCommand = {
                command: 'status'
            }
            var promise = services.execute(statusCommand);
            return promise;
        },

        /**
		 * List all certificates in Token.
         * 
         * @instance
		 * @param {string} password - Password of Token
		 * @return Promisse - The promisse when is finished.  
		 * @memberof SignerDesktopClient
		 */
        listCerts: function(password) {
            var listcertsCommand = {
                command: 'listcerts',
                password: password
            }
            var promise = services.execute(listcertsCommand);
            return promise;
        },

        /**
		 * List all policies on token.
         * 
         * @instance
		 * @return Promisse - The promisse when is finished.  
		 * @memberof SignerDesktopClient
		 */
        listPolicies: function() {
            var listpoliciesCommand = {
                command: 'listpolicies'
            }
            var promise = services.execute(listpoliciesCommand);
            return promise;
        },

        /**
		 * Get files to sign. 
         * 
         * @instance
		 * @return Promisse - The promisse when is finished.  
		 * @memberof SignerDesktopClient
		 */
        getFiles: function() {
            var getfileCommand = {
                command: 'getfiles'
            }
            var promise = services.execute(getfileCommand);
            return promise;
        },

        /**
		 * Sign file selected by method getFiles.
         * 
         * @instance
         * @param {string} alias - Alias of certificate to use in sign
		 * @param {string} provider - The provider (Token, SmartCard...)
		 * @param {string} content - The text to sign
		 * @param {string} signaturePolicy - he policy to use in signature 
		 * @return Promisse - The promisse when is finished.  
		 * @memberof SignerDesktopClient
		 */
        signerFile: function(alias, provider, content, signaturePolicy) {
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

        /**
		 * Shutdown Desktop Client
         * 
         * @instance
		 * @memberof SignerDesktopClient
		 */
        shutdown: function() {
            var shutdownCommand = {
                command: 'shutdown'
            }
            ws.send(JSON.stringify(shutdownCommand));
        },

        /**
		 * Generic method to sendo commands to Desktop Server.
         * 
         * @instance
		 * @param {json} request - Request JSON content all attributes to run.
         * @return Promisse - The promisse when is finished. 
		 * @memberof SignerDesktopClient
		 */
        execute: function(request) {
            log("Sending command [" + request.command + "] to URI [" + uri + "]");
            defer = new Promise();
            ws.send(JSON.stringify(request));
            return defer;
        }

    };

    return services;
})();

// Define globally if it doesn't already exist
if (window.SignerDesktopClient === undefined) {
    console.log("SignerDesktopClient started.")
    window.SignerDesktopClient = new SignerDesktopClient();
} else {
    console.log("SignerDesktopClient already defined.");
}