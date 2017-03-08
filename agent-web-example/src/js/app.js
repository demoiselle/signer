angular.module('agent', ['cfp.loadingBar', 'ui-notification'])

    .config(['NotificationProvider', function (NotificationProvider) {

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

    .controller('MainController', ['$scope', '$http', '$timeout', 'cfpLoadingBar', 'Notification', function ($scope, $http, $timeout, cfpLoadingBar, Notification) {

        $scope.webExtensionIsOn = false;
        $scope.desktopClientIsOn = false;
        $scope.webExtSupported = true;

        // https://github.com/chieffancypants/angular-loading-bar
        $scope.startRequest = function () {
            cfpLoadingBar.start();
        };

        $scope.stopRequest = function () {
            cfpLoadingBar.complete();
        };

        $scope.webExtensionId = "ignkfmddfcgkkpkopkafjjbbpagofgka";

        $scope.signFile = function () {
            $scope.startRequest();
            $scope.sendMessageToWebExtension({ command: "signerFileUsingDefaults" },
                function (response) {
                    console.log(response);

                    Notification.success('Success, file p7s generate in ' + response.signed);

                    $scope.fileName = response.original;
                    $scope.signedFileName = response.signed;

                    $scope.stopRequest();
                }, function (error) {
                    console.log(error);

                    $scope.fileName = "";
                    $scope.signedFileName = "";

                    $scope.stopRequest(); 3
                }
            );
        };

        $scope.validateFile = function () {
            $scope.startRequest();
            $scope.sendMessageToWebExtension({ command: "validateFile" },
                function (response) {
                    console.log(response);

                    $timeout(function () {
                        $scope.valid = response.valid;

                        if ($scope.subject !== undefined) {
                            $scope.subject = response.by.subject;

                        }

                        $scope.message = response.message;
                    }, 100);

                    $scope.stopRequest();
                }, function (error) {
                    console.log(error);

                    $scope.stopRequest();
                }
            );
        };

        $scope.sendMessageToWebExtension = function (message, callbackSuccess, callbackError) {

            // https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage
            try {
                chrome.runtime.sendMessage($scope.webExtensionId, message, function (response) {
                    // Se o response vir UNDEFINED é erro
                    if (response !== undefined) {
                        callbackSuccess(response);
                    } else {
                        $scope.webExtensionIsOn = false;
                        $scope.desktopClientIsOn = false;
                        $scope.webExtSupported = true;
                        $scope.verifyAll();
                        callbackError("Verifique se a Extensão do Navegador esta instalada.")
                    }
                });
                return chrome;
            } catch (Exception) {
                $scope.webExtSupported = false;

                Notification.error('Este navegador não é suportado.');

                return null;
            }

        };

        $scope.verifyPreRequisites = function () {
            $scope.sendMessageToWebExtension({ command: "desktopStatus" },
                function (response) {
                    $timeout(function () {
                        $scope.webExtensionIsOn = true;
                        $scope.desktopClientIsOn = response;
                    }, 10);
                }, function (error) {
                    $timeout(function () {
                        $scope.webExtensionIsOn = false;
                        $scope.desktopClientIsOn = false;
                    }, 10);
                }
            );

        };

        $scope.verifyAll = function () {

            if (!$scope.webExtensionIsOn || !$scope.desktopClientIsOn)
                $scope.verifyPreRequisites();

            // Por enquanto se ativar isso da problema com as requisições do usuário
            $timeout($scope.verifyAll, 5000);
        };

        // $scope.verifyAll();
        $timeout($scope.verifyAll, 10);

    }]);
