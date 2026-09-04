# Hash Algoritmo Politica Fix - Bugfix Design

## Overview

O método `prepareAlgAndLength()` em `CAdESSigner.java` sobrescreve incorretamente o campo `signPolicyHashAlg` do objeto `SignaturePolicy` com o OID do algoritmo de hash derivado do algoritmo de assinatura do certificado. Esse campo indica o algoritmo usado para calcular o hash do **arquivo .der da política**, e não o hash usado na assinatura do documento. A correção consiste em remover as linhas que sobrescrevem esse campo, preservando o valor original carregado do .der da política.

O bug afeta todas as políticas CAdES ICP-Brasil (AD-RB, AD-RT, AD-RV, AD-RC, AD-RA) quando o algoritmo de assinatura do certificado utiliza um hash diferente do hash da política (ex: SHA512withRSA com política que define SHA-256 para seu hash).

## Glossary

- **Bug_Condition (C)**: A condição que dispara o bug — quando o algoritmo de assinatura do certificado possui um hash (ex: SHA-512) diferente do hash definido na política para o arquivo .der (ex: SHA-256), e `prepareAlgAndLength()` sobrescreve `signPolicyHashAlg`
- **Property (P)**: O comportamento desejado — `signPolicyHashAlg` deve permanecer com o valor original carregado do .der da política, independente do algoritmo de assinatura escolhido
- **Preservation**: O comportamento de seleção de algoritmo de assinatura (`AlgAndLength`), configuração do `pkcs1`, validação de tamanho de chave e lançamento de exceções deve permanecer inalterado
- **signPolicyHashAlg**: Campo de `SignaturePolicy` que armazena o `AlgorithmIdentifier` do hash usado para proteger/verificar o arquivo .der da política — definido na estrutura ASN.1 `SignaturePolicy ::= SEQUENCE { signPolicyHashAlg AlgorithmIdentifier, ... }`
- **signPolicyHash**: O valor do hash do arquivo .der da política, calculado usando o algoritmo indicado em `signPolicyHashAlg`
- **prepareAlgAndLength()**: Método em `CAdESSigner.java` (linha ~1001) que seleciona o algoritmo de assinatura e valida o tamanho da chave
- **IdSigningPolicy**: Classe que monta o atributo `SignaturePolicyIdentifier` (id-aa-ets-sigPolicyId) usando `signPolicyHashAlg` e `signPolicyHash` da `SignaturePolicy`
- **SignerAlgorithmEnum**: Enum que mapeia algoritmos de assinatura (ex: SHA512withRSA) para seus respectivos OIDs de hash (ex: 2.16.840.1.101.3.4.2.3 para SHA-512)

## Bug Details

### Bug Condition

O bug manifesta-se quando `prepareAlgAndLength()` é executado e o algoritmo de assinatura selecionado possui um hash diferente do hash definido no `signPolicyHashAlg` original da política. O método obtém o OID do hash do `SignerAlgorithmEnum` correspondente ao algoritmo de assinatura e sobrescreve o `signPolicyHashAlg` da `SignaturePolicy`. Posteriormente, `IdSigningPolicy.getValue()` usa esse valor corrompido para montar o atributo `SignaturePolicyIdentifier`, gerando uma assinatura com `hashAlgorithm` incorreto.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type {signatureAlgorithm: String, signaturePolicy: SignaturePolicy}
  OUTPUT: boolean

  LET policyHashOID = input.signaturePolicy.signPolicyHashAlg.algorithm.value
  LET signerEnum = SignerAlgorithmEnum.getSignerAlgorithmEnum(input.signatureAlgorithm)
  LET sigAlgHashOID = signerEnum.getOIDAlgorithmHash()

  RETURN sigAlgHashOID != policyHashOID
         AND algorithmConstraintSet IS NOT NULL
         AND signerAlgorithmConstraints IS NOT NULL
END FUNCTION
```

### Examples

- **SHA512withRSA + Política SHA-256**: Certificado usa SHA512withRSA (hash OID: 2.16.840.1.101.3.4.2.3). Política PA_AD_RB_v2_3.der define `signPolicyHashAlg` = SHA-256 (OID: 2.16.840.1.101.3.4.2.1). **Atual**: `signPolicyHashAlg` é sobrescrito para SHA-512. **Esperado**: permanece SHA-256.
- **SHA512withECDSA + Política SHA-256**: Certificado usa SHA512withECDSA (hash OID: 2.16.840.1.101.3.4.2.3). Política PA_AD_RB_v2_4.der define `signPolicyHashAlg` = SHA-256. **Atual**: sobrescrito para SHA-512. **Esperado**: permanece SHA-256.
- **SHA256withRSA + Política SHA-256**: Certificado usa SHA256withRSA (hash OID: 2.16.840.1.101.3.4.2.1). Política define SHA-256. **Atual**: sobrescreve para SHA-256 (coincidência — sem efeito visível). **Esperado**: não sobrescreve, mas resultado é o mesmo.
- **Branch else (sem algoritmo informado)**: Seleciona `listOfAlgAndLength.get(1)` e sobrescreve `signPolicyHashAlg` com o hash desse algoritmo. **Atual**: sobrescrito. **Esperado**: não modifica `signPolicyHashAlg`.

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- A seleção do `AlgAndLength` correspondente ao algoritmo informado como parâmetro deve continuar funcionando (iteração pela lista e match por OID)
- A configuração do algoritmo no `pkcs1` (via `this.pkcs1.setAlgorithm(...)`) deve continuar funcionando no branch else
- A validação de que o algoritmo informado é permitido pela política deve continuar lançando `SignerException` quando não encontrado
- A seleção do segundo algoritmo da lista (`listOfAlgAndLength.get(1)`) no branch else deve permanecer
- O fallback quando `algorithmConstraintSet` é nulo deve permanecer (retorna `AlgAndLength` com algoritmo configurado ou DEFAULT)
- A validação do tamanho mínimo da chave (`minKeyLength`) deve permanecer
- A montagem do atributo `SignaturePolicyIdentifier` por `IdSigningPolicy.getValue()` deve continuar usando `signPolicyHashAlg`, `signPolicyHash` e `sigPolicyQualifiers` da `SignaturePolicy`

**Scope:**
Todas as operações de `prepareAlgAndLength()` que NÃO envolvem a modificação de `signPolicyHashAlg` devem ser completamente inalteradas. A correção é cirúrgica: apenas a remoção das linhas que sobrescrevem `signPolicyHashAlg`.

## Hypothesized Root Cause

Com base na análise do código-fonte, a causa raiz é claramente identificada:

1. **Confusão semântica entre dois conceitos de "hash"**: O desenvolvedor original confundiu o algoritmo de hash usado para **assinar o documento** (derivado do `SignerAlgorithmEnum`, ex: SHA-512 para SHA512withRSA) com o algoritmo de hash usado para **proteger o arquivo .der da política** (campo `signPolicyHashAlg` da `SignaturePolicy`). São conceitos completamente independentes.

2. **Sobrescrita explícita no branch `if` (algoritmo informado)** — linhas 1042-1046:
   ```java
   String varOIDAlgorithmHash = varSignerAlgorithmEnum.getOIDAlgorithmHash();
   ObjectIdentifier varObjectIdentifier = signaturePolicy.getSignPolicyHashAlg().getAlgorithm();
   varObjectIdentifier.setValue(varOIDAlgorithmHash);
   AlgorithmIdentifier varAlgorithmIdentifier = signaturePolicy.getSignPolicyHashAlg();
   varAlgorithmIdentifier.setAlgorithm(varObjectIdentifier);
   signaturePolicy.setSignPolicyHashAlg(varAlgorithmIdentifier);
   ```

3. **Sobrescrita explícita no branch `else` (sem algoritmo informado)** — linhas 1055-1060:
   ```java
   String varOIDAlgorithmHash = varSignerAlgorithmEnum.getOIDAlgorithmHash();
   ObjectIdentifier varObjectIdentifier = signaturePolicy.getSignPolicyHashAlg().getAlgorithm();
   varObjectIdentifier.setValue(varOIDAlgorithmHash);
   AlgorithmIdentifier varAlgorithmIdentifier = signaturePolicy.getSignPolicyHashAlg();
   varAlgorithmIdentifier.setAlgorithm(varObjectIdentifier);
   signaturePolicy.setSignPolicyHashAlg(varAlgorithmIdentifier);
   ```

4. **Mutabilidade direta do objeto**: O código obtém referências diretas aos objetos internos da `SignaturePolicy` e os modifica in-place, corrompendo o estado para todas as operações subsequentes (incluindo `IdSigningPolicy.getValue()`).

## Correctness Properties

Property 1: Bug Condition - signPolicyHashAlg preservado após prepareAlgAndLength

_For any_ chamada a `prepareAlgAndLength()` onde o algoritmo de assinatura (do certificado ou selecionado da lista) possui um OID de hash diferente do `signPolicyHashAlg` original da política, o método corrigido SHALL preservar intacto o valor de `signPolicyHashAlg` da `SignaturePolicy`, sem modificá-lo.

**Validates: Requirements 2.1, 2.2, 2.3**

Property 2: Preservation - Seleção de algoritmo e configuração do pkcs1

_For any_ chamada a `prepareAlgAndLength()` com qualquer combinação de algoritmo informado/não-informado e lista de algoritmos da política, o método corrigido SHALL produzir o mesmo `AlgAndLength` retornado, a mesma configuração de `pkcs1.algorithm`, e lançar as mesmas exceções que o método original, preservando todo o comportamento de seleção de algoritmo de assinatura.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4**

## Fix Implementation

### Changes Required

Assumindo que a análise de causa raiz está correta (causa confirmada por inspeção direta do código):

**File**: `policy-impl-cades/src/main/java/org/demoiselle/signer/policy/impl/cades/pkcs7/impl/CAdESSigner.java`

**Function**: `prepareAlgAndLength()`

**Specific Changes**:

1. **Remover sobrescrita no branch `if` (algoritmo informado como parâmetro)**: Remover as 5 linhas que obtêm o OID do hash do `SignerAlgorithmEnum` e sobrescrevem `signPolicyHashAlg`:
   ```java
   // REMOVER estas linhas (dentro do if que encontrou o algoritmo na lista):
   String varOIDAlgorithmHash = varSignerAlgorithmEnum.getOIDAlgorithmHash();
   ObjectIdentifier varObjectIdentifier = signaturePolicy.getSignPolicyHashAlg().getAlgorithm();
   varObjectIdentifier.setValue(varOIDAlgorithmHash);
   AlgorithmIdentifier varAlgorithmIdentifier = signaturePolicy.getSignPolicyHashAlg();
   varAlgorithmIdentifier.setAlgorithm(varObjectIdentifier);
   signaturePolicy.setSignPolicyHashAlg(varAlgorithmIdentifier);
   ```

2. **Remover sobrescrita no branch `else` (sem algoritmo informado)**: Remover as mesmas 5 linhas duplicadas no branch else:
   ```java
   // REMOVER estas linhas (no else após configurar pkcs1):
   String varOIDAlgorithmHash = varSignerAlgorithmEnum.getOIDAlgorithmHash();
   ObjectIdentifier varObjectIdentifier = signaturePolicy.getSignPolicyHashAlg().getAlgorithm();
   varObjectIdentifier.setValue(varOIDAlgorithmHash);
   AlgorithmIdentifier varAlgorithmIdentifier = signaturePolicy.getSignPolicyHashAlg();
   varAlgorithmIdentifier.setAlgorithm(varObjectIdentifier);
   signaturePolicy.setSignPolicyHashAlg(varAlgorithmIdentifier);
   ```

3. **Manter validação do `SignerAlgorithmEnum`**: A verificação `if (varSignerAlgorithmEnum == null)` deve permanecer em ambos os branches, pois valida que o algoritmo é reconhecido pelo sistema (útil para o throw de `SignerException`).

4. **Manter declaração de `varSignerAlgorithmEnum`**: A variável `varSignerAlgorithmEnum` pode ser mantida se for utilizada para validação, ou removida se não for mais necessária. Recomenda-se mantê-la para preservar a validação null-check.

5. **Nenhuma alteração em `IdSigningPolicy.java`**: O `IdSigningPolicy.getValue()` continuará funcionando corretamente pois lerá o `signPolicyHashAlg` original (não mais corrompido).

### Resultado esperado do método corrigido (branch if):
```java
if (this.pkcs1.getAlgorithm() != null) {
    String varSetedAlgorithmOID = AlgorithmNames.getOIDByAlgorithmName(this.pkcs1.getAlgorithm());
    for (AlgAndLength algLength : listOfAlgAndLength) {
        if (algLength.getAlgID().getValue().equalsIgnoreCase(varSetedAlgorithmOID)) {
            algAndLength = algLength;
            SignerAlgorithmEnum varSignerAlgorithmEnum = SignerAlgorithmEnum.getSignerAlgorithmEnum(this.pkcs1.getAlgorithm());
            if (varSignerAlgorithmEnum == null) {
                throw new SignerException(cadesMessagesBundle.getString("error.no.algorithm.policy"));
            }
            // signPolicyHashAlg NÃO é mais modificado aqui
        }
    }
}
```

### Resultado esperado do método corrigido (branch else):
```java
} else {
    algAndLength = listOfAlgAndLength.get(1);
    this.pkcs1.setAlgorithm(AlgorithmNames.getAlgorithmNameByOID(algAndLength.getAlgID().getValue()));
    SignerAlgorithmEnum varSignerAlgorithmEnum = SignerAlgorithmEnum.getSignerAlgorithmEnum(this.pkcs1.getAlgorithm());
    if (varSignerAlgorithmEnum == null) {
        throw new SignerException(cadesMessagesBundle.getString("error.no.algorithm.policy"));
    }
    // signPolicyHashAlg NÃO é mais modificado aqui
}
```

## Testing Strategy

### Validation Approach

A estratégia de testes segue uma abordagem em duas fases: primeiro, demonstrar o bug no código não-corrigido com contraexemplos concretos, depois verificar que a correção funciona e preserva o comportamento existente.

### Exploratory Bug Condition Checking

**Goal**: Demonstrar contraexemplos que evidenciam o bug ANTES de implementar a correção. Confirmar a causa raiz.

**Test Plan**: Criar testes unitários que configuram uma `SignaturePolicy` com `signPolicyHashAlg` = SHA-256 (OID 2.16.840.1.101.3.4.2.1), executam `prepareAlgAndLength()` com algoritmo SHA512withRSA, e verificam se `signPolicyHashAlg` foi modificado. Executar no código não-corrigido para observar a falha.

**Test Cases**:
1. **SHA512withRSA com política SHA-256 (branch if)**: Configurar `pkcs1.algorithm` = "SHA512withRSA" e verificar que `signPolicyHashAlg` foi sobrescrito para SHA-512 (vai falhar no código não-corrigido)
2. **SHA512withECDSA com política SHA-256 (branch if)**: Mesmo cenário com ECDSA (vai falhar no código não-corrigido)
3. **Branch else com política SHA-256**: Não informar algoritmo, deixar selecionar da lista; verificar que `signPolicyHashAlg` foi sobrescrito (vai falhar no código não-corrigido)
4. **SHA256withRSA com política SHA-256 (caso coincidente)**: Verificar que mesmo com match, o código ainda executa a sobrescrita desnecessária (passa mas por coincidência)

**Expected Counterexamples**:
- `signPolicyHashAlg.algorithm.value` muda de "2.16.840.1.101.3.4.2.1" (SHA-256) para "2.16.840.1.101.3.4.2.3" (SHA-512) após `prepareAlgAndLength()`
- Causa confirmada: linhas 1042-1046 e 1055-1060 em `CAdESSigner.java`

### Fix Checking

**Goal**: Verificar que para todas as entradas onde a condição de bug é verdadeira, o método corrigido preserva `signPolicyHashAlg`.

**Pseudocode:**
```
FOR ALL input WHERE isBugCondition(input) DO
  LET originalHashAlg = signaturePolicy.signPolicyHashAlg.algorithm.value
  result := prepareAlgAndLength_fixed(input)
  ASSERT signaturePolicy.signPolicyHashAlg.algorithm.value == originalHashAlg
END FOR
```

### Preservation Checking

**Goal**: Verificar que para todas as entradas, o método corrigido retorna o mesmo `AlgAndLength`, configura o mesmo `pkcs1.algorithm`, e lança as mesmas exceções que o original.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  LET resultOriginal = prepareAlgAndLength_original(input)  // ignoring signPolicyHashAlg side-effect
  LET resultFixed = prepareAlgAndLength_fixed(input)
  ASSERT resultOriginal.algID == resultFixed.algID
  ASSERT resultOriginal.minKeyLength == resultFixed.minKeyLength
  ASSERT pkcs1.algorithm_original == pkcs1.algorithm_fixed
END FOR
```

**Testing Approach**: Property-based testing é recomendado para preservation checking porque:
- Gera automaticamente muitas combinações de algoritmos e políticas
- Captura edge cases que testes manuais podem não cobrir
- Garante que o retorno (`AlgAndLength`) e as exceções são idênticos ao comportamento original

**Test Plan**: Observar o comportamento do código não-corrigido para retorno de `AlgAndLength` e configuração de `pkcs1` (ignorando o side-effect em `signPolicyHashAlg`), depois escrever testes property-based que verificam que esses comportamentos são preservados.

**Test Cases**:
1. **Seleção de AlgAndLength preservada**: Para qualquer algoritmo informado que esteja na lista da política, o `AlgAndLength` retornado deve ser o mesmo
2. **Configuração de pkcs1 preservada**: No branch else, `pkcs1.algorithm` deve ser configurado com o algoritmo correspondente ao segundo item da lista
3. **Exceções preservadas**: Algoritmo não reconhecido continua lançando `SignerException`
4. **Fallback preservado**: Quando `algorithmConstraintSet` é nulo, retorno de `AlgAndLength` com algoritmo configurado/DEFAULT permanece

### Unit Tests

- Testar `prepareAlgAndLength()` com SHA512withRSA + política SHA-256: verificar `signPolicyHashAlg` inalterado
- Testar `prepareAlgAndLength()` com SHA256withRSA + política SHA-256: verificar `signPolicyHashAlg` inalterado
- Testar `prepareAlgAndLength()` sem algoritmo informado: verificar `signPolicyHashAlg` inalterado e `pkcs1` configurado
- Testar `prepareAlgAndLength()` com algoritmo não permitido: verificar exceção lançada
- Testar `prepareAlgAndLength()` com `algorithmConstraintSet` nulo: verificar fallback
- Testar `IdSigningPolicy.getValue()` após `prepareAlgAndLength()`: verificar `hashAlgorithm` correto no `SignaturePolicyIdentifier`

### Property-Based Tests

- Gerar combinações aleatórias de {algoritmo de assinatura} x {signPolicyHashAlg da política} e verificar que `signPolicyHashAlg` nunca é modificado
- Gerar listas de `AlgAndLength` aleatórias e verificar que a seleção/retorno do `AlgAndLength` permanece consistente
- Gerar cenários com/sem algoritmo informado e verificar que exceções são lançadas nos mesmos casos

### Integration Tests

- Assinar um documento com SHA512withRSA usando política PA_AD_RB_v2_3.der e verificar que o atributo `SignaturePolicyIdentifier` contém `hashAlgorithm` = SHA-256
- Assinar um documento com SHA256withRSA usando política PA_AD_RB_v2_4.der e verificar que `hashAlgorithm` = SHA-256
- Verificar assinatura gerada contra validador CAdES (se disponível no ambiente de teste)
- Testar assinatura com todas as políticas AD-RB, AD-RT, AD-RV, AD-RC, AD-RA com SHA512withRSA

---

## Extension: Recálculo e Verificação do Hash da Política

Extensão aditiva e independente da correção descrita acima. Atualmente o valor do `signPolicyHash` usado no atributo `SignaturePolicyIdentifier` é lido diretamente do arquivo .der em `IdSigningPolicy.getValue()` (`signaturePolicy.getSignPolicyHash().getDerOctetString()`), sem recálculo nem verificação. Esta extensão faz `SignaturePolicy` recalcular o hash da política conforme a regra ETSI, compará-lo com o valor do .der, e decidir qual valor entregar ao atributo com fallback seguro e warning.

### Glossário adicional

- **Policy_Der_Bytes**: os bytes/estrutura DER originais da `SignaturePolicy`, capturados durante `parse()`, necessários para reconstruir a SEQUENCE e recalcular o hash
- **Recomputed_Hash**: o octet string resultante do recálculo do hash da política sobre a SEQUENCE `{ signPolicyHashAlg, signPolicyInfo }` (sem `signPolicyHash`), usando o algoritmo de `signPolicyHashAlg`
- **Der_Hash**: o valor do `signPolicyHash` presente no arquivo .der (`signaturePolicy.getSignPolicyHash().getDerOctetString()`) — usado como fallback
- **Validated_Hash**: o octet string efetivamente entregue ao atributo — igual a `Recomputed_Hash` quando bate, ou igual a `Der_Hash` no fallback

### Regra ETSI de cálculo do hash

Conforme o comentário de cabeçalho de `SignaturePolicy` e a estrutura ASN.1:

```
SignaturePolicy ::= SEQUENCE {
    signPolicyHashAlg AlgorithmIdentifier,
    signPolicyInfo    SignPolicyInfo,
    signPolicyHash    SignPolicyHash OPTIONAL
}
```

> "The hash is calculated without the outer type and length fields."

O hash é calculado sobre a estrutura `SignaturePolicy` **excluindo** o campo `signPolicyHash`, ou seja, sobre a SEQUENCE reconstruída contendo apenas `signPolicyHashAlg` + `signPolicyInfo`, e conforme o comentário, sem os campos externos de type/length. O algoritmo de digest é o indicado por `signPolicyHashAlg`.

### Onde guardar os bytes DER no parse()

Hoje `SignaturePolicy.parse(ASN1Primitive derObject)` lê os elementos da SEQUENCE (`getObjectAt(0/1/2)`) mas descarta a estrutura DER. A mudança:

- Em `parse()`, além de popular `signPolicyHashAlg`, `signPolicyInfo` e `signPolicyHash`, guardar referências aos primitivos DER dos dois primeiros elementos (`derSequence.getObjectAt(0)` e `derSequence.getObjectAt(1)`) — suficientes para reconstruir a SEQUENCE sem o `signPolicyHash`. Alternativamente, guardar o próprio `ASN1Sequence`/`ASN1Primitive` original.
- Adicionar campo(s) privado(s) (ex: `private transient ASN1Encodable signPolicyHashAlgPrimitive;` e `private transient ASN1Encodable signPolicyInfoPrimitive;`, ou `private transient ASN1Primitive originalDer;`).

### Reconstrução da SEQUENCE sem signPolicyHash

No método de cálculo:

```
FUNCTION buildHashInputSequence()
  seqToHash := new DERSequence([ signPolicyHashAlgPrimitive, signPolicyInfoPrimitive ])
  RETURN seqToHash.getEncoded("DER")   // bytes DER da SEQUENCE reconstruída
END FUNCTION
```

O conteúdo a passar ao `MessageDigest` deve seguir a regra ETSI ("without the outer type and length fields"). A implementação deve documentar explicitamente se aplica o digest sobre o encoding DER da SEQUENCE reconstruída ou sobre seu conteúdo interno sem os octetos de type/length externos, e validar essa escolha contra políticas ICP-Brasil reais (ver Testing Strategy) — a variante correta é aquela cujo `Recomputed_Hash` bate com o `Der_Hash` das políticas oficiais.

### Mapeamento OID -> MessageDigest

O algoritmo de digest vem de `signPolicyHashAlg.getAlgorithm().getValue()` (OID). É necessário mapear o OID para o nome de algoritmo aceito por `java.security.MessageDigest`:

```
FUNCTION oidToDigestName(oid)
  SWITCH oid
    CASE "2.16.840.1.101.3.4.2.1": RETURN "SHA-256"
    CASE "2.16.840.1.101.3.4.2.2": RETURN "SHA-384"
    CASE "2.16.840.1.101.3.4.2.3": RETURN "SHA-512"
    CASE "1.3.14.3.2.26":          RETURN "SHA-1"
    DEFAULT: RETURN null   // desconhecido -> aciona fallback
  END SWITCH
END FUNCTION
```

Se o OID não for mapeável ou `MessageDigest.getInstance(name)` lançar `NoSuchAlgorithmException`, aciona o fallback (warning + `Der_Hash`).

### Lógica de comparação / fallback / warning

```
FUNCTION getValidatedPolicyHashOctetString()
  OUTPUT: ASN1OctetString

  TRY
    digestName := oidToDigestName(signPolicyHashAlg.algorithm.value)
    IF digestName == null THEN
      LOG.warn("algoritmo de hash da politica desconhecido; usando valor do .der")
      RETURN signPolicyHash.getDerOctetString()   // fallback
    END IF

    recomputed := computePolicyHash()              // Recomputed_Hash
    derValue   := signPolicyHash.getDerOctetString().getOctets()

    IF Arrays.equals(recomputed, derValue) THEN
      RETURN new DEROctetString(recomputed)         // usa recalculado
    ELSE
      LOG.warn("hash recalculado da politica difere do valor do .der; usando valor do .der")
      RETURN signPolicyHash.getDerOctetString()     // fallback
    END IF
  CATCH Exception e
    LOG.warn("falha ao recalcular hash da politica; usando valor do .der", e)
    RETURN signPolicyHash.getDerOctetString()       // fallback, nunca lanca
  END TRY
END FUNCTION
```

O `computePolicyHash()` retorna o octet string recalculado (útil também para testes/inspeção); o `getValidatedPolicyHashOctetString()` aplica a lógica completa. Nenhuma exceção do recálculo pode escapar para o fluxo de assinatura.

### Mudança de consumo em IdSigningPolicy

Em `IdSigningPolicy.getValue()`, o segundo atributo passa a consumir o método validado em vez de ler o octet string do .der diretamente:

```java
// Antes:
OtherHashAlgAndValue sigPolicyHash = new OtherHashAlgAndValue(
    new AlgorithmIdentifier(new ASN1ObjectIdentifier(signaturePolicy.getSignPolicyHashAlg().getAlgorithm().getValue())),
    signaturePolicy.getSignPolicyHash().getDerOctetString());

// Depois:
OtherHashAlgAndValue sigPolicyHash = new OtherHashAlgAndValue(
    new AlgorithmIdentifier(new ASN1ObjectIdentifier(signaturePolicy.getSignPolicyHashAlg().getAlgorithm().getValue())),
    signaturePolicy.getValidatedPolicyHashOctetString());
```

O `hashAlgorithm` (a partir de `signPolicyHashAlg`), o `sigPolicyId` e os `sigPolicyQualifiers` permanecem inalterados. Apenas o valor do octet string do hash passa pela lógica de recálculo/verificação.

### Correctness Properties (Extensão)

Property 3: Bug Condition - Uso do hash recalculado quando bate

_For any_ política onde o hash recalculado (`Recomputed_Hash`, calculado pela regra ETSI sobre a SEQUENCE `{ signPolicyHashAlg, signPolicyInfo }` com o algoritmo de `signPolicyHashAlg`) for igual ao `signPolicyHash` do .der (`Der_Hash`), `getValidatedPolicyHashOctetString()` SHALL retornar o valor recalculado, e o atributo `SignaturePolicyIdentifier` SHALL usá-lo.

**Validates: Requirements 5.1, 5.2, 5.3, 5.4**

Property 4: Preservation - Fallback seguro com warning em erro/divergência

_For any_ política onde o recálculo falhe (algoritmo desconhecido/indisponível, exceção durante o cálculo) OU onde `Recomputed_Hash` difira de `Der_Hash`, `getValidatedPolicyHashOctetString()` SHALL retornar o valor original do .der (`Der_Hash`), SHALL emitir um WARNING via logger, e SHALL NUNCA lançar exceção nem produzir hash inválido — preservando o comportamento atual do atributo.

**Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5**

### Fix Implementation (Extensão)

**Arquivo 1**: `policy-engine/src/main/java/org/demoiselle/signer/policy/engine/asn1/etsi/SignaturePolicy.java`

1. **Guardar DER no parse()**: adicionar campos privados para os primitivos DER de `signPolicyHashAlg` e `signPolicyInfo` (ou o `ASN1Sequence` original), populados em `parse(ASN1Primitive derObject)`.
2. **`computePolicyHash()`** (público): reconstrói a SEQUENCE `{ signPolicyHashAlg, signPolicyInfo }`, resolve o `MessageDigest` a partir do OID de `signPolicyHashAlg`, e retorna os bytes do digest (`Recomputed_Hash`). Documentar a variante ETSI adotada (com/sem type/length externos) confirmada empiricamente.
3. **`getValidatedPolicyHashOctetString()`** (público): aplica a lógica compara/fallback/warning descrita acima e retorna o `ASN1OctetString` a usar. Usa logger (SLF4J, padrão do projeto) para o WARNING. Nunca lança exceção.
4. **Mapeamento OID -> nome do digest**: método auxiliar privado `oidToDigestName(String oid)`.

**Arquivo 2**: `policy-impl-cades/src/main/java/org/demoiselle/signer/policy/impl/cades/pkcs7/attribute/impl/IdSigningPolicy.java`

5. **Consumir o método validado**: substituir `signaturePolicy.getSignPolicyHash().getDerOctetString()` por `signaturePolicy.getValidatedPolicyHashOctetString()` na montagem do `OtherHashAlgAndValue`. Nenhuma outra alteração.

### Testing Strategy (Extensão)

#### Exploratory Bug Condition Checking

**Goal**: Demonstrar/validar que o hash recalculado bate com o `signPolicyHash` do .der para políticas ICP-Brasil reais, confirmando a variante ETSI correta.

**Test Plan**: Carregar políticas oficiais (PA_AD_RB e variantes) via o mesmo caminho de `PolicyFactory.loadPolicy()`, chamar `computePolicyHash()` e comparar com `getSignPolicyHash().getDerOctetString()`. Antes da implementação, esse teste falha porque o método não existe / o recálculo não bate até a variante correta ser adotada.

**Test Cases**:
1. **PA_AD_RB real**: `computePolicyHash()` deve bater com o `signPolicyHash` do .der (confirma a regra ETSI adotada)
2. **Demais políticas AD-RB/AD-RT/AD-RV/AD-RC/AD-RA**: mesmo recálculo bate
3. **Algoritmo desconhecido (simulado)**: com `signPolicyHashAlg` de OID não mapeável, `getValidatedPolicyHashOctetString()` retorna o `Der_Hash` e loga warning (não lança)

**Expected Counterexamples (código não-corrigido)**: método `computePolicyHash()`/`getValidatedPolicyHashOctetString()` inexistente; nenhum recálculo/verificação ocorre.

#### Fix Checking

**Goal**: Para toda política onde `Recomputed_Hash == Der_Hash`, o valor entregue é o recalculado.

```
FOR ALL policy WHERE recompute(policy) == derHash(policy) DO
  ASSERT getValidatedPolicyHashOctetString(policy) == recompute(policy)
END FOR
```

#### Preservation Checking

**Goal**: Para toda política onde o recálculo falha ou diverge, o valor entregue é o `Der_Hash`, com warning e sem exceção.

```
FOR ALL policy WHERE recompute(policy) FAILS OR recompute(policy) != derHash(policy) DO
  result := getValidatedPolicyHashOctetString(policy)
  ASSERT result == derHash(policy)
  ASSERT no exception thrown
  ASSERT warning logged
END FOR
```

**Testing Approach**: PBT recomendado — gerar políticas sintéticas com `signPolicyHashAlg` variando (OIDs válidos e inválidos) e `signPolicyHash` alterado/inalterado, verificando a decisão bate/fallback e a ausência de exceção.

#### Unit Tests

- `computePolicyHash()` produz o digest correto para uma política conhecida
- `oidToDigestName()` mapeia SHA-256/384/512/SHA-1 e retorna null para OID desconhecido
- `getValidatedPolicyHashOctetString()` retorna recalculado quando bate
- `getValidatedPolicyHashOctetString()` retorna `Der_Hash` + warning quando diverge
- `getValidatedPolicyHashOctetString()` retorna `Der_Hash` + warning quando o algoritmo é desconhecido, sem lançar
- `IdSigningPolicy.getValue()` monta o atributo consumindo o método validado

#### Property-Based Tests

- Para qualquer OID desconhecido/indisponível, o resultado é sempre `Der_Hash` e nenhuma exceção é lançada
- Para qualquer alteração no `signPolicyHash` que cause divergência, o resultado é `Der_Hash` com warning
- Para políticas reais onde bate, o resultado é sempre o recalculado

#### Integration Tests

- Assinar documento com política ICP-Brasil real e verificar que o `sigPolicyHash` do atributo corresponde ao valor recalculado (quando bate)
- Assinar com política cujo `signPolicyHash` foi adulterado e verificar fallback para o valor do .der + warning, sem falha na assinatura
- Verificar que a correção de `signPolicyHashAlg` (seções 1-3) permanece intacta em conjunto com esta extensão
