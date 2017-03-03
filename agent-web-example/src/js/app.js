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

        $scope.webExtensionIsOn = true;
        $scope.desktopClientIsOn = true;

        // https://github.com/chieffancypants/angular-loading-bar
        $scope.startRequest = function () {
            cfpLoadingBar.start();
        };

        $scope.stopRequest = function () {
            cfpLoadingBar.complete();
        };

        $scope.webExtensionId = "ignkfmddfcgkkpkopkafjjbbpagofgka";

        // Função necessária para funcionar no Chrome e Firefox
        $scope.browser = function () {
            if (chrome !== undefined) {
                return chrome;
            } else {
                return browser;
            }
        };

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

                    $scope.stopRequest();
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
            $scope.browser().runtime.sendMessage($scope.webExtensionId, message, function (response) {
                // Se o response vir UNDEFINED é erro
                if (response !== undefined) {
                    callbackSuccess(response);
                } else {
                    callbackError("Verifique se a Extensão do Navegador esta instalada.")
                }
            });
        };

        $scope.getLastError = function () {
            console.log($scope.browser().lastError);
        };

        $scope.verifyDesktopClientIsOn = function () {
            $scope.sendMessageToWebExtension({ command: "desktopStatus" },
                function (response) {
                    $scope.desktopClientIsOn = true;
                }, function (error) {
                    $scope.desktopClientIsOn = false;
                }
            );
        };

        $scope.verifyWebExtensionIsOn = function () {
            $scope.sendMessageToWebExtension({ command: "status" },
                function (response) {
                    $timeout(function () {
                        $scope.webExtensionIsOn = (response.status === "OK");
                    }, 100);
                }, function (error) {
                    $timeout(function () {
                        $scope.webExtensionIsOn = false;
                    }, 100);
                }
            );
        };

        $scope.verifyAll = function () {
            $scope.verifyDesktopClientIsOn();
            $scope.verifyWebExtensionIsOn();

            // Por enquanto se ativar isso da problema com as requisições do usuário
            // $timeout($scope.verifyAll, 5000);
        };

        //$scope.verifyAll();

    }]);
