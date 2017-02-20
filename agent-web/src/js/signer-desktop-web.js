(function (window) {

	'use strict';

	function SignerDesktopClient() {
		var SignerDesktopClient = {};
		var ws;
		var defer = null;

		SignerDesktopClient.execute = function (request) {
			defer = $q.defer();
			ws.send(JSON.stringify(request));
			return defer.promise;
		};

		SignerDesktopClient.connect = function (callback) {

			if (ws == null || ws.readyState != 1) {

				ws = new WebSocket("ws://localhost:9091/");

				ws.onopen = function (msg) {
					if (callback)
						callback(msg.target.readyState);
				}

				ws.onclose = function (msg) {
					if (callback)
						callback(msg.target.readyState);
				}

				ws.onmessage = function (response) {
					defer.resolve(JSON.parse(response.data));
				};

			}

		};

		SignerDesktopClient.isConnected = function () {
			if (ws != null)
				return ws.readyState == 1 ? true : false;
			return false;
		};

		SignerDesktopClient.signer = function (alias, provider, content, signaturePolicy) {
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
		};

		SignerDesktopClient.signer = function (alias, password, provider, content, signaturePolicy) {
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
		};

		SignerDesktopClient.logoutpkcs11 = function () {
			var logoutPKCS11Command = {
				command: 'logoutpkcs11'
			}
			ws.send(JSON.stringify(logoutPKCS11Command));
		};

		SignerDesktopClient.status = function () {
			var statusCommand = {
				command: 'status'
			}
			var promise = execute(statusCommand);
			return promise;
		};

		SignerDesktopClient.listcerts = function (password) {
			var listcertsCommand = {
				command: 'listcerts',
				password: password
			}
			var promise = execute(listcertsCommand);
			return promise;
		};

		SignerDesktopClient.listpolicies = function () {
			var listpoliciesCommand = {
				command: 'listpolicies'
			}
			var promise = execute(listpoliciesCommand);
			return promise;
		};

		SignerDesktopClient.getfiles = function () {
			var getfileCommand = {
				command: 'getfiles'
			}
			var promise = execute(getfileCommand);
			return promise;
		};

		SignerDesktopClient.signerfile = function (alias, provider, content, signaturePolicy) {
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
			var promise = execute(signerCommand);
			return promise;
		};

		SignerDesktopClient.shutdown = function () {
			var shutdownCommand = {
				command: 'shutdown'
			}
			ws.send(JSON.stringify(shutdownCommand));
		};

		return SignerDesktopClient;
	}

	// define globally if it doesn't already exist
	if (typeof (SignerDesktopClient) === 'undefined') {
		console.log("SignerDesktopClient started.")
		window.SignerDesktopClient = SignerDesktopClient();
	} else {
		console.log("SignerDesktopClient already defined.");
	}

})(window);