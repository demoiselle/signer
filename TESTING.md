# Guia de Execução de Testes - Demoiselle Signer

Este guia descreve como executar os testes unitários do projeto. 

**Nota Importante**: Os testes de integração End-to-End (E2E) que dependem de hardware físico (Tokens/Smartcards) foram movidos para um repositório dedicado para facilitar a manutenção e o isolamento do ambiente.

---

## 1. Pré-requisitos

- **Java 8** (ou superior, compatível até Java 25).
- **Maven 3.9+**.

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

## 3. Testes de Integração (E2E)

Os testes que acessam hardware real e validam assinaturas completas com tokens físicos agora residem no repositório de automação de testes. 

Para executá-los, consulte a documentação no projeto de testes correspondente.

---

## 4. Testes Multi-JDK (Go)

Se você tiver **Go** e **SDKMAN** instalados, pode rodar a suíte de testes unitários em várias versões do Java simultaneamente:

```bash
go run run-all-lts-tests.go
```

---

## 5. Solução de Problemas

- **ClassCastException (Bouncy Castle)**: Se encontrar erros de cast entre `DLTaggedObject` e `DERTaggedObject`, certifique-se de que está utilizando a versão `4.6.1` ou superior, que utiliza classes `ASN1` genéricas.
- **Erro de Compilação**: Como o projeto utiliza o `parent` e o `bom`, sempre execute um `mvn install -DskipTests` na raiz antes de rodar testes de módulos isolados.

---

## 6. Resultados
Os resultados dos testes unitários podem ser visualizados nos relatórios padrão do Maven em `target/surefire-reports`.
