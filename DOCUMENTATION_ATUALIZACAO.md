# Guia de Atualização de Artefatos de Produção (ICP-Brasil)

Este guia descreve como manter as cadeias de certificados e as políticas de assinatura atualizadas para o ambiente de produção.

## Requisitos Prévios

Para executar a automação, você precisa ter instalado no seu ambiente:

1.  **Go (Golang)**: Utilizado para os scripts de download e processamento.
2.  **Java & Keytool**: Necessário para manipular o keystore BKS.
3.  **OpenSSL**: Utilizado pelos scripts para validação de certificados.
4.  **Bouncy Castle Provider**: O arquivo `bcprov-jdk15on-1.65.jar` deve estar presente em `chain-icp-brasil/src/scripts_keytool/`.

## Automação Total (Recomendado)

Foi criado um script mestre que executa todas as etapas de download, validação e movimentação de arquivos.

Para rodar a atualização completa:

```bash
./atualizar-artefatos-producao.sh
```

Este script realiza as seguintes operações:
1.  **Baixa as Políticas**: Executa `02-baixar-politicas.go` para baixar arquivos `.der` e `.xml` do repositório da ICP-Brasil, validando o SHA256.
2.  **Baixa as Cadeias**: Executa `01-baixar-cadeias.go` para baixar o arquivo `ACcompactadox.zip` do ITI e extrair os certificados para a pasta `novascadeias`.
3.  **Gera o Keystore**: Executa `importar-certificados.go` para criar um novo arquivo `cadeiasicpbrasil.bks` contendo todas as cadeias válidas.
4.  **Distribui os Artefatos**: Move os arquivos baixados e o keystore gerado para as pastas de `src/main/resources` correspondentes.

---

## Detalhes das Etapas Manuais (Caso necessário)

### 1. Atualização de Políticas
Se precisar atualizar apenas as políticas ou adicionar uma nova URL:
1.  Edite o arquivo `policy-engine/automacao-atualizacao/politicas.txt`.
2.  Execute:
    ```bash
    cd policy-engine/automacao-atualizacao
    go run 02-baixar-politicas.go
    ```

### 2. Atualização de Cadeias de Certificados
Se desejar processar certificados locais manualmente:
1.  Coloque os arquivos `.crt` ou `.cer` na pasta `chain-icp-brasil/src/scripts_keytool/novascadeias`.
2.  Execute a geração do keystore:
    ```bash
    cd chain-icp-brasil/src/scripts_keytool
    go run importar-certificados.go
    ```
3.  O arquivo gerado `cadeiasicpbrasil.bks` deve ser copiado para `chain-icp-brasil/src/main/resources/`.

---

## Verificação e Build

Após a atualização dos artefatos, é essencial validar se o projeto continua funcionando corretamente:

1.  **Rebuild do Projeto**:
    ```bash
    mvn clean install -DskipTests
    ```
2.  **Execução dos Testes de Integração**:
    Como os artefatos de produção mudaram, rode os testes de integração (especialmente os que usam certificados reais):
    ```bash
    mvn verify -Pit
    ```

## Contato e Suporte
Em caso de falha no download ou certificados corrompidos no repositório do ITI, verifique os logs gerados:
- `policy-engine/automacao-atualizacao/baixar-politicas.log`
- `chain-icp-brasil/src/scripts_keytool/import.log`
