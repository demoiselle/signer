# Utilizando a API Javascript

## Dependências
A implementação depende do uso do framework Angular JS, para inserir esta dependência é necessária a 
existência de arquivo com suas funcionalidades na aplicação ou hiperlink apontando para o endereço
do mantenedor: https://ajax.googleapis.com/ajax/libs/angularjs/1.4.8/angular.min.js.

Para o desenvolvimento de interface http para interação com o componente  basta copiar o arquivo 
agent-desktop.js para uma área acessível a aplicação web e garantir seu carregamento na página 
que fará a interação com o usuário. 

### Exemplo dos cabeçalhos da aplicação
    <html>
    <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.4.8/angular.min.js"></script>
    <script src="agent-desktop.js"></script>
    <script src="seu_java_script.js"></script>
    <!-- Código HTML -->

    <!-- ... -->


## Usando a API

O exemplo a seguir apresenta a implementação dos métodos para a execução de algumas funcionalidades da aplicação


    angular.module('agent-desktop', []).controller('controller', function ($scope, $http, sadService) {
        $scope.listaCertificados = null;
        $scope.password = null;

        callback = function(connectionCode){console.log("Status: "+connectionCode);

        //Inicia a conexão com o servidor 
        sadService.connect(callback);

        $scope.listarCertificados = function () {
            sadService.listcerts($scope.password).then(function (response) {
                $scope.listaCertificados = response;
            });
        }

    });


Para executar o código relacione o método a algum evento de componente HTML

    <div id="main" ng-app="agent-desktop" ng-controller="controller">
        <button ng-click="listarCertificados()">Listar Certificados instalados</button>
    </div>


Os arquivos app.js e index.html fornecem um exemplo de aplicação que pode ser utilizado como referência
