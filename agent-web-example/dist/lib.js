(function (window) {

	'use strict';

	/**
	 * Implementação de Promisse, pois como não sabemos a biblioteca que será usada 
	 * para o desenvolvimento não podemos depender de alguma.
	 */
	function Promise() {
		var callback = null;
		this.then = function (cb) {
			callback = cb;
		};
		this.resolve = function (value) {
			callback(value);
		};
	}

	function SignerDesktopClient() {
		var services = {};
		var ws;
		var defer = null;

		services.execute = function (request) {
			// defer = $q.defer();
			defer = new Promise();
			ws.send(JSON.stringify(request));
			return defer;
		};

		services.connect = function (callback) {
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

		services.isConnected = function () {
			if (ws != null)
				return ws.readyState == 1 ? true : false;
			return false;
		};

		services.signer = function (alias, provider, content, signaturePolicy) {
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
		};

		services.signer = function (alias, password, provider, content, signaturePolicy) {
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
		};

		services.logoutpkcs11 = function () {
			var logoutPKCS11Command = {
				command: 'logoutpkcs11'
			}
			ws.send(JSON.stringify(logoutPKCS11Command));
		};

		services.status = function () {
			var statusCommand = {
				command: 'status'
			}
			var promise = services.execute(statusCommand);
			return promise;
		};

		services.listcerts = function (password) {
			var listcertsCommand = {
				command: 'listcerts',
				password: password
			}
			var promise = services.execute(listcertsCommand);
			return promise;
		};

		services.listpolicies = function () {
			var listpoliciesCommand = {
				command: 'listpolicies'
			}
			var promise = services.execute(listpoliciesCommand);
			return promise;
		};

		services.getfiles = function () {
			var getfileCommand = {
				command: 'getfiles'
			}
			var promise = services.execute(getfileCommand);
			return promise;
		};

		services.signerfile = function (alias, provider, content, signaturePolicy) {
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
		};

		services.shutdown = function () {
			var shutdownCommand = {
				command: 'shutdown'
			}
			ws.send(JSON.stringify(shutdownCommand));
		};

		return services;
	}

	// Define globally if it doesn't already exist
	if (window.SignerDesktopClient === undefined) {
		console.log("SignerDesktopClient started.")
		window.SignerDesktopClient = SignerDesktopClient();
	} else {
		console.log("SignerDesktopClient already defined.");
	}

})(window);