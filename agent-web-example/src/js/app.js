angular.module('agent', [])
    .controller('MainController', ['$scope', '$http', '$timeout', function($scope, $http, $timeout) {

        $scope.listCertificates = null;
        $scope.listAllPolicies = [];
        $scope.policy = null;

        $scope.signed = null;
        $scope.errors;
        $scope.fileName = null;
        $scope.serverIsOn = false;
        $scope.selectedCertificate = null;
        // $scope.signedFileName = null;

        var tryAgainTimeout;
        function callbackOpenClose(connectionStatus) {
            if (connectionStatus === 1) {
                console.log("Connected on Server");
                $scope.serverIsOn = true;

                // Load policies on open connection
                $scope.listAllPolicies();

                clearInterval(tryAgainTimeout);
            } else {
                console.log("Warn user to download/execute Agent-Desktop AND try again in 5000ms");
                $scope.serverIsOn = false;

                // Try again in 5000ms
                tryAgainTimeout = setTimeout(function() {
                    window.SignerDesktopClient.connect(callbackOpenClose, callbackOpenClose, callbackError);
                }, 5000);
            }
        }

        function callbackError(event) {
            $timeout(function() {
                $scope.errors = event;
            }, 100);
        }

        window.SignerDesktopClient.setUriServer("ws://10.32.128.25:9091");
        window.SignerDesktopClient.setDebug(true);
        window.SignerDesktopClient.connect(callbackOpenClose, callbackOpenClose, callbackError);

        $scope.listCerts = function() {
            window.SignerDesktopClient.listCerts().success(function(response) {
                $timeout(function() {
                    $scope.listCertificates = response;
                }, 100);
            });
        };

        $scope.setCertificate = function(cert) {
            console.log(cert.alias);
            $scope.selectedCertificate = cert;
        };

        $scope.signText = function(content) {
            window.SignerDesktopClient.signer($scope.selectedCertificate.alias, $scope.selectedCertificate.provider, content, $scope.policy)
                .success(function(response) {
                    $timeout(function() {
                        $scope.signed = response.signed;
                    }, 100);
                });
        };

        $scope.listAllPolicies = function() {
            window.SignerDesktopClient.listPolicies().success(function(response) {
                $timeout(function() {
                    $scope.listPolicies = response.policies;
                    $scope.policy = "AD_RB_CADES_2_2";
                }, 100);
            });
        };

        $scope.getfiles = function() {
            window.SignerDesktopClient.getFiles().success(function(response) {
                $timeout(function() {
                    $scope.fileName = response.fileName;
                }, 100);
            });
        };

        $scope.assinarArquivo = function(content) {
            // if (content == null || alias == null) {
            //     alert("Informe o arquivo e a policy a ser utilizada");
            //     return;
            // }

            window.SignerDesktopClient.signerFile($scope.selectedCertificate.alias, $scope.selectedCertificate.provider, $scope.fileName, $scope.policy).success(function(response) {
                $timeout(function() {
                    $scope.signedFileName = response.signed;
                }, 100);
            });
        };

        $scope.status = function() {
            window.SignerDesktopClient.status().success(function(response) {
                console.log(response);
            });
        };

        $scope.shutdown = function() {
            window.SignerDesktopClient.shutdown();
        };

        $scope.logout = function() {
            window.SignerDesktopClient.logoutPKCS11();
        };

    }]);
