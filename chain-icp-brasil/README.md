CHAIN-ICP-BRASIL
=================================

O Chain-ICP-Brasil fornece uma implementação para validação do 
conjunto de Autoridades Certificadoras da cadeia ICP-Brasil 
(Esse componente contém as cadeias da ICP-Brasil). 

O acionamento das funcionalidades é feito automaticamente pelos 
componentes de geração e validação de assinaturas como o 
policy-impl-cades quando a dependência é especificada no arquivo 
POM.XML 

Para atualização do arquivo com as cadeias siga as instruções em :
 /src/scripts_keytool/leiame.txt

# Design (especulação)

Todas as implementações (providers) dependem do arquivo ACcompactado.zip.
Um acesso a este arquivo pode ser encapsulado em repositório específico. 
Inclusive a obtenção de cópia atualizada, se for necessário. A partir 
desta funcionalidade demais providers podem ser implementados.