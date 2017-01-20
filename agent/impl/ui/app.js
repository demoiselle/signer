angular.module('agent-desktop', []).controller('controller', function ($scope, $http, sadService) {
    $scope.listaCertificados = null;
    $scope.listaPoliticas = [];
    $scope.politica = null;
    $scope.password = null;
    $scope.signed = null;
    $scope.erros = null;
    $scope.fileName = null;
    $scope.signedFileName=null;
    connectionStatus = -1;



    callback = function(data){
        connectionStatus = data;
        elementMessage = document.getElementById("serverstate");
        if(data == 1)
            elementMessage.innerHTML = "Conectado ao servidor";
        else{
            elementMessage.innerHTML = "<a href='agent-desktop.jnlp' download> Baixar/Executar Agent-Desktop </a>";
            setTimeout(tryAgain, 3000);
        }
    }

    function tryAgain(){
        sadService.connect(callback);
    }

    sadService.connect(callback);

    $scope.listarCertificados = function () {
        console.log("Listar");        
        sadService.listcerts($scope.password).then(function (response) {
            $scope.listaCertificados = response;
            console.log(response);
        });
    }

    $scope.tratarErros = function(responseWithErro) {

        $scope.erros = responseWithErro.erro;
        alert('Erro. ' + responseWithErro.erro);
    }

    $scope.assinar = function (alias, provider, content) {
        sadService.signer(alias, $scope.password, provider, content, $scope.politica).then(function (response) {
            if (response.erro) {
                $scope.tratarErros(response);
                return; 
            }
             $scope.signed = response.signed;
        });
    }
    $scope.status = function () {
        sadService.status().then(function (response) {
            if (response.erro) {
                $scope.tratarErros(response);
                return; 
            }
        });
    }
    $scope.listarPoliticas = function () {
        sadService.listpolicies().then(function (response) {
            if (response.erro) {
                $scope.tratarErros(response);
                return; 
            }
            $scope.listaPoliticas = response.policies;
            console.log($scope.listaPoliticas);
        });
    }
    $scope.shutdown = function () {
        sadService.shutdown();
    }
    $scope.logout = function () {
        sadService.logoutpkcs11();
    }

    $scope.getfiles = function () {
        sadService.getfiles().then(function (response) {
            if (response.erro) {
                $scope.tratarErros(response);
                return;
            }
            $scope.fileName = response.fileName;
            console.log($scope.fileName);
        });
    }
    $scope.assinarArquivo = function (alias, provider, content) {
        if(content == null || alias == null){
            alert("Informe o arquivo e a politica a ser utilizada");
            return;
        }
        sadService.signerfile(alias, provider, $scope.fileName, $scope.politica).then(function (response) {
            if (response.erro) {
                $scope.tratarErros(response);
                return; 
            }
             $scope.signedFileName = response.signed;
        });
    }

});
