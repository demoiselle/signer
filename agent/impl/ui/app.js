angular.module('agent-desktop', []).controller('controller', function ($scope, $http, daService) {
    $scope.listaCertificados = null;
    $scope.listaPoliticas = [];
    $scope.politica = null;
    $scope.password = null;
    $scope.signed = null;
    $scope.erros = null;
    $scope.listarCertificados = function () {
        daService.listcerts($scope.password).then(function (response) {
            $scope.listaCertificados = response;
        });
    }
    $scope.tratarErros = function(responseWithErro) {

        $scope.erros = responseWithErro.erro;
        alert('Erro. ' + responseWithErro.erro);
    }
    $scope.assinar = function (alias, provider, content) {
        daService.signer(alias, $scope.password, provider, content, $scope.politica).then(function (response) {
            if (response.erro) {
                $scope.tratarErros(response);
                return; 
            }
             $scope.signed = response.signed;
        });
    }
    $scope.status = function () {
        daService.status().then(function (response) {
            if (response.erro) {
                $scope.tratarErros(response);
                return; 
            }
        });
    }
    $scope.listarPoliticas = function () {
        daService.listpolicies().then(function (response) {
            if (response.erro) {
                $scope.tratarErros(response);
                return; 
            }
            $scope.listaPoliticas = response.policies;
            console.log($scope.listaPoliticas);
        });
    }
    $scope.shutdown = function () {
        daService.shutdown();
    }
    $scope.logout = function () {
        daService.logoutpkcs11();
    }
});