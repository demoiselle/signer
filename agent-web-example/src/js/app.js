angular.module('agent', ['cfp.loadingBar', 'ui-notification'])


    .config(['NotificationProvider', function(NotificationProvider) {

        // https://github.com/alexcrack/angular-ui-notification
        NotificationProvider.setOptions({
            delay: 5000,
            startTop: 10,
            startRight: 10,
            verticalSpacing: 20,
            horizontalSpacing: 20,
            positionX: 'right',
            positionY: 'bottom'
        });

    }])
    .controller('MainController', ['$scope', '$http', '$timeout', 'cfpLoadingBar', 'Notification', function($scope, $http, $timeout, cfpLoadingBar, Notification) {

        $scope.listCertificates = null;
        $scope.listAllPolicies = [];
        $scope.policy = null;

        $scope.signed = null;
        $scope.fileName = null;
        $scope.serverIsOn = false;
        $scope.selectedCertificate = null;

        var tryAgainTimeout;
        function callbackOpenClose(connectionStatus) {
            if (connectionStatus === 1) {
                console.log("Connected on Server");
                $scope.serverIsOn = true;

                // Load policies on open connection
                $scope.listAllPolicies();

                clearInterval(tryAgainTimeout);
            } else {
                console.log("Warn user to download/execute Agent-Desktop AND try again in 3000ms");
                $scope.serverIsOn = false;

                // Try again in 3000ms
                tryAgainTimeout = setTimeout(function() {
                    window.SignerDesktopClient.connect(callbackOpenClose, callbackOpenClose, callbackError);
                }, 3000);
            }
        }

        function callbackError(event) {
            $timeout(function() {
                if (event.error !== undefined) {
                    if (event.error !== null && event.error !== 'null') {
                        Notification.error({ message: event.error });
                    } else {
                        Notification.error({ message: 'Unknown error' });
                    }
                }

                $scope.stopRequest();
            }, 100);
        }

        // https://github.com/chieffancypants/angular-loading-bar
        $scope.startRequest = function() {
            cfpLoadingBar.start();
        }

        $scope.stopRequest = function() {
            cfpLoadingBar.complete();
        }

        window.SignerDesktopClient.setUriServer("ws://localhost:9091");
        // window.SignerDesktopClient.setUriServer("wss://localhost:9443");
        window.SignerDesktopClient.setDebug(true);
        window.SignerDesktopClient.connect(callbackOpenClose, callbackOpenClose, callbackError);

        $scope.listCerts = function() {
            $scope.startRequest();
            window.SignerDesktopClient.listCerts().success(function(response) {
                $timeout(function() {
                    $scope.listCertificates = response;

                    $scope.stopRequest();
                }, 100);
            });
        };

        $scope.setCertificate = function(cert) {
            console.log(cert.alias);
            $scope.selectedCertificate = cert;
        };

        $scope.signText = function(content) {
            $scope.startRequest();
            window.SignerDesktopClient.signer($scope.selectedCertificate.alias, $scope.selectedCertificate.provider, content, $scope.policy)
                .success(function(response) {
                    $timeout(function() {
                        $scope.signed = response.signed;

                        $scope.stopRequest();
                    }, 100);
                });
        };

        $scope.listAllPolicies = function() {
            $scope.startRequest();
            window.SignerDesktopClient.listPolicies().success(function(response) {
                $timeout(function() {
                    $scope.listPolicies = response.policies;
                    $scope.policy = "AD_RB_CADES_2_2";

                    $scope.stopRequest();
                }, 100);
            });
        };

        $scope.getfiles = function() {
            $scope.startRequest();
            window.SignerDesktopClient.getFiles().success(function(response) {
                $timeout(function() {
                    $scope.fileName = response.fileName;

                    $scope.stopRequest();
                }, 100);
            });
        };

        $scope.assinarArquivo = function(content) {
            $scope.startRequest();

            // if (content == null || alias == null) {
            //     alert("Informe o arquivo e a policy a ser utilizada");
            //     return;
            // }

            window.SignerDesktopClient.signerFile($scope.selectedCertificate.alias, $scope.selectedCertificate.provider, $scope.fileName, $scope.policy).success(function(response) {
                $timeout(function() {
                    $scope.signedFileName = response.signed;

                    $scope.stopRequest();
                }, 100);
            });
        };

        $scope.status = function() {
            $scope.startRequest();

            window.SignerDesktopClient.status().success(function(response) {
                console.log(response);

                $scope.stopRequest();
            });
        };

        $scope.shutdown = function() {
            window.SignerDesktopClient.shutdown();
        };

        $scope.logout = function() {
            window.SignerDesktopClient.logoutPKCS11();
        };

    }]);
