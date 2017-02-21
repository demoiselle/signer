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
        function callback(connectionStatus) {
            if (connectionStatus === 1) {
                console.log("Connected on Server");
                clearInterval(tryAgainTimeout);
            } else {
                console.log("Warn user to download/execute Agent-Desktop AND try again in 5000ms");

                // Try again in 5000ms
                tryAgainTimeout = setTimeout(function () {
                    window.SignerDesktopClient.connect(callback);
                }, 5000);
            }
        }

        window.SignerDesktopClient.connect(callback);

        $scope.listarCertificados = function () {
            // console.log("Listar");
            window.SignerDesktopClient.listCerts($scope.password).then(function (response) {
                $timeout(function () {
                    $scope.listaCertificados = response;
                }, 100);
                // console.log(response);
            });
        }

        $scope.tratarErros = function (responseWithErro) {

            $scope.erros = responseWithErro.erro;
            alert('Erro. ' + responseWithErro.erro);
        }

        $scope.assinar = function (alias, provider, content) {
            window.SignerDesktopClient.signer(alias, $scope.password, provider, content, $scope.politica).then(function (response) {
                if (response.erro) {
                    $scope.tratarErros(response);
                    return;
                }

                $timeout(function () {
                    $scope.signed = response.signed;
                }, 100);
            });
        }

        $scope.status = function () {
            window.SignerDesktopClient.status().then(function (response) {
                if (response.erro) {
                    $scope.tratarErros(response);
                    return;
                }
            });
        }

        $scope.listarPoliticas = function () {
            // console.log("Listar POLITICAS");
            window.SignerDesktopClient.listPolicies().then(function (response) {


                // console.log(response);

                if (response.erro) {
                    $scope.tratarErros(response);
                    return;
                }

                $timeout(function () {
                    $scope.listaPoliticas = response.policies;
                }, 100);
                // console.log($scope.listaPoliticas);
            });
        }

        $scope.shutdown = function () {
            window.SignerDesktopClient.shutdown();
        }

        $scope.logout = function () {
            window.SignerDesktopClient.logoutPKCS11();
        }

        $scope.getfiles = function () {
            window.SignerDesktopClient.getFiles().then(function (response) {
                if (response.erro) {
                    $scope.tratarErros(response);
                    return;
                }
                $timeout(function () {
                    $scope.fileName = response.fileName;
                }, 100);
                // console.log($scope.fileName);
            });
        }

        $scope.assinarArquivo = function (alias, provider, content) {
            if (content == null || alias == null) {
                alert("Informe o arquivo e a politica a ser utilizada");
                return;
            }
            window.SignerDesktopClient.signerFile(alias, provider, $scope.fileName, $scope.politica).then(function (response) {
                if (response.erro) {
                    $scope.tratarErros(response);
                    return;
                }
                $timeout(function () {
                    $scope.signedFileName = response.signed;
                }, 100);
            });
        }

    }]);
