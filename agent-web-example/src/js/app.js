angular.module('agent-desktop', [])
    .controller('controller', ['$scope', '$http', '$timeout', function($scope, $http, $timeout) {

        $scope.listaCertificados = null;
        $scope.listaPoliticas = [];
        $scope.politica = null;
        $scope.password = null;
        $scope.signed = null;
        $scope.erros = null;
        $scope.fileName = null;
        $scope.signedFileName = null;
        connectionStatus = -1;


        // console.log(window.SignerDesktopClient);

        callback = function(data) {
            connectionStatus = data;
            elementMessage = document.getElementById("serverstate");
            if (data == 1)
                elementMessage.innerHTML = "Conectado ao servidor";
            else {
                elementMessage.innerHTML = "<a href='agent-desktop.jnlp' download> Baixar/Executar Agent-Desktop </a>";
                setTimeout(tryAgain, 3000);
            }
        }

        function tryAgain() {
            window.SignerDesktopClient.connect(callback);
        }

        window.SignerDesktopClient.connect(callback);

        $scope.listarCertificados = function() {
            // console.log("Listar");
            window.SignerDesktopClient.listcerts($scope.password).then(function(response) {
                $timeout(function() {
                    $scope.listaCertificados = response;
                }, 100);
                // console.log(response);
            });
        }

        $scope.tratarErros = function(responseWithErro) {

            $scope.erros = responseWithErro.erro;
            alert('Erro. ' + responseWithErro.erro);
        }

        $scope.assinar = function(alias, provider, content) {
            window.SignerDesktopClient.signer(alias, $scope.password, provider, content, $scope.politica).then(function(response) {
                if (response.erro) {
                    $scope.tratarErros(response);
                    return;
                }

                $timeout(function() {
                    $scope.signed = response.signed;
                }, 100);
            });
        }

        $scope.status = function() {
            window.SignerDesktopClient.status().then(function(response) {
                if (response.erro) {
                    $scope.tratarErros(response);
                    return;
                }
            });
        }

        $scope.listarPoliticas = function() {
            // console.log("Listar POLITICAS");
            window.SignerDesktopClient.listpolicies().then(function(response) {


                // console.log(response);

                if (response.erro) {
                    $scope.tratarErros(response);
                    return;
                }

                $timeout(function() {
                    $scope.listaPoliticas = response.policies;
                }, 100);
                // console.log($scope.listaPoliticas);
            });
        }

        $scope.shutdown = function() {
            window.SignerDesktopClient.shutdown();
        }

        $scope.logout = function() {
            window.SignerDesktopClient.logoutpkcs11();
        }

        $scope.getfiles = function() {
            window.SignerDesktopClient.getfiles().then(function(response) {
                if (response.erro) {
                    $scope.tratarErros(response);
                    return;
                }
                $timeout(function() {
                    $scope.fileName = response.fileName;
                }, 100);
                // console.log($scope.fileName);
            });
        }

        $scope.assinarArquivo = function(alias, provider, content) {
            if (content == null || alias == null) {
                alert("Informe o arquivo e a politica a ser utilizada");
                return;
            }
            window.SignerDesktopClient.signerfile(alias, provider, $scope.fileName, $scope.politica).then(function(response) {
                if (response.erro) {
                    $scope.tratarErros(response);
                    return;
                }
                $timeout(function() {
                    $scope.signedFileName = response.signed;
                }, 100);
            });
        }

    }]);
