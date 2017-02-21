angular.module('agent-desktop', [])
    .controller('controller', ['$scope', '$http', '$timeout', function ($scope, $http, $timeout) {

        $scope.listaCertificados = null;
        $scope.listaPoliticas = [];
        $scope.politica = null;
        $scope.password = null;
        $scope.signed = null;
        $scope.erros = null;
        $scope.fileName = null;
        $scope.signedFileName = null;
        connectionStatus = -1;

        var tryAgainTimeout;
        function callbackOpenClose(connectionStatus) {
            if (connectionStatus === 1) {
                console.log("Connected on Server");
                clearInterval(tryAgainTimeout);
            } else {
                console.log("Warn user to download/execute Agent-Desktop AND try again in 5000ms");

                // Try again in 5000ms
                tryAgainTimeout = setTimeout(function () {
                    window.SignerDesktopClient.connect(callbackOpenClose, callbackOpenClose, callbackError);
                }, 5000);
            }
        }

        function callbackError(event) {
            console.log(event);
        }

        // window.SignerDesktopClient.setUriServer("ws://dasdasda");
        window.SignerDesktopClient.setDebug(true);
        window.SignerDesktopClient.connect(callbackOpenClose, callbackOpenClose, callbackError);

        $scope.listarCertificados = function () {
            window.SignerDesktopClient.listCerts($scope.password).success(function (response) {
                $timeout(function () {
                    $scope.listaCertificados = response;
                }, 100);
            });
        }

        var tratarErros = function (error) {
            console.log(error);
        };

        $scope.assinar = function (alias, provider, content) {
            window.SignerDesktopClient.signer(alias, $scope.password, provider, content, $scope.politica).success(function (response) {
                $timeout(function () {
                    $scope.signed = response.signed;
                }, 100);
            });
        }

        $scope.status = function () {
            window.SignerDesktopClient.status().success(function (response) {
                console.log(response);
            });
        }

        $scope.listarPoliticas = function () {
            window.SignerDesktopClient.listPolicies().success(function (response) {
                $timeout(function () {
                    $scope.listaPoliticas = response.policies;
                }, 100);
            }).error(tratarErros);
        }

        $scope.shutdown = function () {
            window.SignerDesktopClient.shutdown();
        }

        $scope.logout = function () {
            window.SignerDesktopClient.logoutPKCS11();
        }

        $scope.getfiles = function () {
            window.SignerDesktopClient.getFiles().success(function (response) {
                $timeout(function () {
                    $scope.fileName = response.fileName;
                }, 100);
            });
        }

        $scope.assinarArquivo = function (alias, provider, content) {
            if (content == null || alias == null) {
                alert("Informe o arquivo e a politica a ser utilizada");
                return;
            }

            window.SignerDesktopClient.signerFile(alias, provider, $scope.fileName, $scope.politica).success(function (response) {
                $timeout(function () {
                    $scope.signedFileName = response.signed;
                }, 100);
            });
        }

    }]);
