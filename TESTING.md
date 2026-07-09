# Guia de Execução de Testes - Demoiselle Signer

Este guia descreve como executar os testes unitários e de integração do projeto, com foco especial nos testes que acessam dispositivos de hardware (Tokens/Smartcards).

## 1. Pré-requisitos

- **Java 8** (ou superior, compatível até Java 25).
- **Maven 3.9+**.
- **Dispositivo de Hardware (Opcional)**: Para os testes de integração de token, o dispositivo deve estar conectado e os drivers PKCS#11 instalados no sistema.

---

## 2. Testes Unitários (Rápido)

Os testes unitários não dependem de hardware ou rede. Eles validam a lógica interna e simulam certificados.

**Comando para rodar todos os testes unitários:**
```bash
mvn clean test
```

**Rodar um teste unitário específico (Ex: AuthorityKeyIdentifierTest):**
```bash
mvn test -pl core -Dtest=AuthorityKeyIdentifierTest
```

---

## 3. Testes de Integração (Token e Dispositivos)

Estes testes acessam o hardware real e dependem do perfil `it` do Maven.

### 3.1 Configuração (`test-config.json`)
Antes de rodar, crie o arquivo de configuração na raiz do projeto:

```bash
cp test-config.sample.json test-config.json
```

Edite o `test-config.json` e informe o seu PIN:
```json
{
  "token": {
    "nome": "NOME_DO_SEU_DRIVER",
    "pin": "SUA_SENHA_AQUI",
    "indice": 0
  }
}
```

### 3.2 Execução
**Comando para rodar todos os testes de integração:**
```bash
mvn clean verify -Pit
```

**Rodar especificamente o teste de leitura do Token:**
```bash
mvn verify -Pit -pl core -Dit.test=AuthorityKeyIdentifierIT
```

---

## 4. Testes Multi-JDK (Go)

Se você tiver **Go** e **SDKMAN** instalados, pode rodar a suíte completa em várias versões do Java simultaneamente:

```bash
go run run-all-lts-tests.go
```

---

## 5. Solução de Problemas

- **ClassCastException (Bouncy Castle)**: Se encontrar erros de cast entre `DLTaggedObject` e `DERTaggedObject`, certifique-se de que está utilizando a versão `4.6.1-SNAPSHOT` ou superior, que utiliza classes `ASN1` genéricas.
- **Token não encontrado**: Verifique se o driver `.so` (Linux) ou `.dll` (Windows) está listado em `core/src/main/resources/drivers.properties`.
- **Erro de Compilação**: Como o projeto utiliza o `parent` e o `bom`, sempre execute um `mvn install -DskipTests` na raiz antes de rodar testes de módulos isolados.

---

## 6. Resultados
Os logs detalhados dos testes de integração de token são salvos em:
`tests/results/token_certificates.txt`
`tests/results/authority_key_id_token_test.txt`
