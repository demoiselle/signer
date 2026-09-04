# Requirements Document

## Introduction

Esta feature adiciona validação de consistência do hash declarado no atributo `SignaturePolicyIdentifier` (OID 1.2.840.113549.1.9.16.2.15) durante a verificação de assinaturas CAdES no `CAdESChecker`.

O serviço VALIDAR do ITI já realiza essa verificação. O objetivo é que o demoiselle-signer detecte assinaturas que foram geradas com o bug de sobrescrita do `signPolicyHashAlg` (corrigido na spec `hash-algoritmo-politica-fix`), onde o algoritmo declarado não corresponde ao tamanho real do hash presente na assinatura.

**Problema de fundo:** Assinaturas geradas com o bug contêm, por exemplo, um OID de SHA-256 (espera 32 bytes) mas um hash de 64 bytes (tamanho de SHA-512), ou vice-versa. Essas assinaturas são rejeitadas pelo ITI e devem ser sinalizadas como inválidas pelo nosso verificador.

## Glossary

| Termo | Definição |
|-------|-----------|
| `sigPolicyId` | OID que identifica a política de assinatura usada |
| `sigPolicyHash` | Estrutura ASN.1 contendo o algoritmo de hash e o valor do hash da política |
| `hashAlgorithm` | OID do algoritmo de hash declarado no `sigPolicyHash` (ex: SHA-256 = 2.16.840.1.101.3.4.2.1) |
| `hashValue` | Bytes do hash da política contidos no `sigPolicyHash` |
| `SignaturePolicyIdentifier` | Atributo assinado (OID 1.2.840.113549.1.9.16.2.15) que referencia a política usada na assinatura |
| Política (.der) | Arquivo binário ASN.1 da política de assinatura, disponível localmente via `PolicyFactory` |

## Requirements

### 1. Validação de Consistência Tamanho-Algoritmo

Como um sistema que verifica assinaturas digitais, eu quero validar que o tamanho do `hashValue` no atributo `SignaturePolicyIdentifier` é compatível com o algoritmo de hash declarado, para que assinaturas geradas com inconsistência algorítmica sejam detectadas como inválidas.

#### Acceptance Criteria

1.1 WHEN o atributo `SignaturePolicyIdentifier` está presente na assinatura AND o `hashAlgorithm` declarado é SHA-256 (OID 2.16.840.1.101.3.4.2.1) THEN the system SHALL verificar que o `hashValue` possui exatamente 32 bytes.

1.2 WHEN o atributo `SignaturePolicyIdentifier` está presente na assinatura AND o `hashAlgorithm` declarado é SHA-384 (OID 2.16.840.1.101.3.4.2.2) THEN the system SHALL verificar que o `hashValue` possui exatamente 48 bytes.

1.3 WHEN o atributo `SignaturePolicyIdentifier` está presente na assinatura AND o `hashAlgorithm` declarado é SHA-512 (OID 2.16.840.1.101.3.4.2.3) THEN the system SHALL verificar que o `hashValue` possui exatamente 64 bytes.

1.4 WHEN o `hashAlgorithm` declarado é SHA-1 (OID 1.3.14.3.2.26) THEN the system SHALL verificar que o `hashValue` possui exatamente 20 bytes.

1.5 WHEN o tamanho do `hashValue` não corresponde ao tamanho esperado para o `hashAlgorithm` declarado THEN the system SHALL registrar um ERRO de validação (não warning) no `SignatureInformations` com código específico e mensagem indicando o algoritmo declarado, tamanho esperado e tamanho real.

1.6 WHEN o `hashAlgorithm` declarado não é reconhecido (OID desconhecido) THEN the system SHALL registrar um WARNING de validação indicando que não foi possível verificar a consistência do hash da política.

### 2. Validação do Hash contra a Política Local

Como um sistema que verifica assinaturas digitais, eu quero opcionalmente recalcular o hash da política e comparar com o `hashValue` declarado na assinatura, para que falsificações ou corrupções do hash da política sejam detectadas.

#### Acceptance Criteria

2.1 WHEN o atributo `SignaturePolicyIdentifier` está presente AND a política referenciada está disponível localmente via `PolicyFactory` THEN the system SHALL carregar o arquivo .der da política, calcular o hash usando o algoritmo declarado no `sigPolicyHash`, e comparar com o `hashValue` declarado.

2.2 WHEN o hash recalculado da política local não corresponde ao `hashValue` declarado na assinatura THEN the system SHALL registrar um ERRO de validação com código específico e mensagem indicando hash esperado vs hash encontrado.

2.3 WHEN a política referenciada na assinatura não está disponível localmente (não encontrada no `PolicyFactory`) THEN the system SHALL apenas logar em nível DEBUG que não foi possível verificar o hash da política contra o arquivo local, sem gerar erro ou warning.

2.4 WHEN ocorrer uma exceção ao calcular o hash da política local (ex: algoritmo não disponível, erro de I/O) THEN the system SHALL logar o erro em nível WARN sem gerar erro de validação, permitindo que a verificação continue.

### 3. Integração com Códigos de Validação

Como um desenvolvedor que consome os resultados de verificação, eu quero códigos de erro estruturados para os novos tipos de falha, para que eu possa tratar programaticamente cada cenário.

#### Acceptance Criteria

3.1 WHEN a validação de consistência tamanho-algoritmo falha THEN the system SHALL usar um novo código `POLICY_HASH_SIZE_MISMATCH` no enum `ValidationMessageCode`.

3.2 WHEN a validação do hash recalculado contra a política local falha THEN the system SHALL usar um novo código `POLICY_HASH_VALUE_MISMATCH` no enum `ValidationMessageCode`.

3.3 WHEN o algoritmo de hash do `sigPolicyHash` não é reconhecido THEN the system SHALL usar um novo código `POLICY_HASH_UNKNOWN_ALGORITHM` no enum `ValidationMessageCode`.

3.4 THE system SHALL definir novas mensagens no `signer_core_messages.properties` para cada novo código de validação, seguindo o padrão de parametrização existente (ex: `{0}` para valores dinâmicos).

### 4. Compatibilidade e Não-Regressão

Como um sistema em produção, eu quero que a nova validação não quebre assinaturas válidas existentes, para que o comportamento do verificador seja preservado para assinaturas corretamente geradas.

#### Acceptance Criteria

4.1 WHEN o atributo `SignaturePolicyIdentifier` está presente AND o `hashValue` possui tamanho compatível com o `hashAlgorithm` declarado THEN the system SHALL continuar o fluxo de verificação normalmente sem registrar erro relacionado ao hash da política.

4.2 WHEN o atributo `SignaturePolicyIdentifier` não está presente na assinatura THEN the system SHALL não executar a validação de hash da política (comportamento inalterado).

4.3 WHEN o atributo `SignaturePolicyIdentifier` está presente mas o `sigPolicyHash` não pode ser parseado (ASN.1 malformado) THEN the system SHALL registrar um WARNING e continuar a verificação sem lançar exceção.

4.4 THE system SHALL manter compatibilidade com Java 8 em toda a implementação.
