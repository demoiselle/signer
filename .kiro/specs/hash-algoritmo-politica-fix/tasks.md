# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - signPolicyHashAlg sobrescrito após prepareAlgAndLength
  - **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the bug exists
  - **Scoped PBT Approach**: Scope the property to concrete failing cases: SHA512withRSA com política SHA-256 (branch if) e seleção automática da lista (branch else)
  - Criar classe de teste em `policy-impl-cades/src/test/java/org/demoiselle/signer/policy/impl/cades/pkcs7/impl/CAdESSignerPrepareAlgBugConditionTest.java`
  - Configurar `SignaturePolicy` com `signPolicyHashAlg` = SHA-256 (OID: 2.16.840.1.101.3.4.2.1)
  - Configurar lista de `AlgAndLength` com algoritmos SHA512withRSA e SHA256withRSA
  - **Caso 1 (branch if)**: Configurar `pkcs1.algorithm` = "SHA512withRSA", executar `prepareAlgAndLength()`, assertar que `signPolicyHashAlg.algorithm.value` == "2.16.840.1.101.3.4.2.1" (SHA-256 original)
  - **Caso 2 (branch else)**: Não informar algoritmo, executar `prepareAlgAndLength()`, assertar que `signPolicyHashAlg.algorithm.value` == "2.16.840.1.101.3.4.2.1" (SHA-256 original)
  - **Caso 3 (branch if, ECDSA)**: Configurar `pkcs1.algorithm` = "SHA512withECDSA", assertar preservação de `signPolicyHashAlg`
  - Run test on UNFIXED code - expect FAILURE (this confirms the bug exists)
  - **EXPECTED OUTCOME**: Test FAILS — `signPolicyHashAlg` é sobrescrito de SHA-256 para SHA-512, confirmando o bug
  - Document counterexamples: `signPolicyHashAlg.algorithm.value` muda de "2.16.840.1.101.3.4.2.1" para "2.16.840.1.101.3.4.2.3"
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.1, 1.2, 1.3_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Seleção de algoritmo e configuração do pkcs1
  - **IMPORTANT**: Follow observation-first methodology
  - Criar classe de teste em `policy-impl-cades/src/test/java/org/demoiselle/signer/policy/impl/cades/pkcs7/impl/CAdESSignerPrepareAlgPreservationTest.java`
  - **Observar no código não-corrigido:**
  - Observe: `prepareAlgAndLength()` com algoritmo "SHA512withRSA" na lista retorna `AlgAndLength` com OID correspondente ao SHA512withRSA
  - Observe: `prepareAlgAndLength()` sem algoritmo informado seleciona `listOfAlgAndLength.get(1)` e configura `pkcs1.algorithm` com o nome correspondente
  - Observe: `prepareAlgAndLength()` com algoritmo não reconhecido pelo `SignerAlgorithmEnum` lança `SignerException`
  - Observe: `prepareAlgAndLength()` com `algorithmConstraintSet` nulo retorna fallback com algoritmo configurado/DEFAULT
  - **Escrever testes property-based:**
  - Test 1: Para qualquer algoritmo informado que esteja na lista da política, o `AlgAndLength` retornado deve ter o mesmo `algID` e `minKeyLength`
  - Test 2: No branch else, `pkcs1.algorithm` deve ser configurado com o nome do algoritmo correspondente ao segundo item da lista
  - Test 3: Algoritmo não permitido pela política lança `SignerException` com mensagem "error.no.algorithm.policy"
  - Test 4: `algorithmConstraintSet` nulo retorna `AlgAndLength` com algoritmo configurado ou DEFAULT e `minKeyLength` = 0
  - Verify tests pass on UNFIXED code (comportamento de seleção/retorno não é afetado pelo bug)
  - **EXPECTED OUTCOME**: Tests PASS — confirma baseline de comportamento a preservar
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 3. Correção da sobrescrita de signPolicyHashAlg em prepareAlgAndLength()

  - [x] 3.1 Implementar a correção
    - Arquivo: `policy-impl-cades/src/main/java/org/demoiselle/signer/policy/impl/cades/pkcs7/impl/CAdESSigner.java`
    - Método: `prepareAlgAndLength()` (linha ~1001)
    - **Branch if (algoritmo informado como parâmetro)**: Remover as 5 linhas que sobrescrevem `signPolicyHashAlg` (linhas ~1042-1046):
      ```java
      // REMOVER:
      String varOIDAlgorithmHash = varSignerAlgorithmEnum.getOIDAlgorithmHash();
      ObjectIdentifier varObjectIdentifier = signaturePolicy.getSignPolicyHashAlg().getAlgorithm();
      varObjectIdentifier.setValue(varOIDAlgorithmHash);
      AlgorithmIdentifier varAlgorithmIdentifier = signaturePolicy.getSignPolicyHashAlg();
      varAlgorithmIdentifier.setAlgorithm(varObjectIdentifier);
      signaturePolicy.setSignPolicyHashAlg(varAlgorithmIdentifier);
      ```
    - **Branch else (sem algoritmo informado)**: Remover as mesmas 5 linhas duplicadas (linhas ~1055-1060)
    - Manter a validação `if (varSignerAlgorithmEnum == null)` em ambos os branches
    - Manter a declaração de `varSignerAlgorithmEnum` para a validação null-check
    - Nenhuma alteração em `IdSigningPolicy.java`
    - _Bug_Condition: isBugCondition(input) onde sigAlgHashOID != policyHashOID AND algorithmConstraintSet IS NOT NULL_
    - _Expected_Behavior: signPolicyHashAlg.algorithm.value permanece inalterado após prepareAlgAndLength()_
    - _Preservation: Seleção de AlgAndLength, configuração de pkcs1, exceções e fallback permanecem idênticos_
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.4_

  - [x] 3.2 Verificar que o teste de bug condition agora passa
    - **Property 1: Expected Behavior** - signPolicyHashAlg preservado após prepareAlgAndLength
    - **IMPORTANT**: Re-run the SAME test from task 1 - do NOT write a new test
    - O teste da task 1 codifica o comportamento esperado (signPolicyHashAlg inalterado)
    - Quando este teste passar, confirma que o comportamento esperado é satisfeito
    - Executar: `cd policy-impl-cades && mvn test -Dtest=CAdESSignerPrepareAlgBugConditionTest`
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - _Requirements: 2.1, 2.2, 2.3_

  - [x] 3.3 Verificar que os testes de preservação continuam passando
    - **Property 2: Preservation** - Seleção de algoritmo e configuração do pkcs1
    - **IMPORTANT**: Re-run the SAME tests from task 2 - do NOT write new tests
    - Executar: `cd policy-impl-cades && mvn test -Dtest=CAdESSignerPrepareAlgPreservationTest`
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirmar que todos os testes ainda passam após a correção (sem regressões)

- [x] 4. Checkpoint - Ensure all tests pass
  - Executar suite completa: `cd policy-impl-cades && mvn clean test`
  - Verificar que todos os testes unitários existentes continuam passando
  - Verificar que os novos testes (bug condition + preservation) passam
  - Ensure all tests pass, ask the user if questions arise.

---

## Extensão: Recálculo e Verificação do Hash da Política

- [x] 5. Write policy hash recomputation exploration test
  - **Property 3: Bug Condition** - Uso do hash recalculado quando bate
  - **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms a extensão ainda não existe (método `computePolicyHash()`/`getValidatedPolicyHashOctetString()` inexistente e nenhum recálculo ocorre)
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
  - **GOAL**: Confirmar a variante ETSI correta demonstrando que o hash recalculado bate com o `signPolicyHash` do .der para políticas ICP-Brasil reais
  - **Scoped PBT Approach**: escopar a propriedade a casos concretos com políticas oficiais reais (PA_AD_RB e variantes)
  - Criar classe de teste em `policy-engine/src/test/java/org/demoiselle/signer/policy/engine/asn1/etsi/SignaturePolicyHashRecomputeTest.java`
  - Carregar políticas oficiais via o mesmo caminho de `PolicyFactory.loadPolicy()` (InputStream + `signaturePolicy.parse(primitive)`)
  - **Caso 1 (PA_AD_RB real)**: assertar que `computePolicyHash()` (bytes do digest) == `getSignPolicyHash().getDerOctetString().getOctets()`
  - **Caso 2 (demais políticas AD-RB/AD-RT/AD-RV/AD-RC/AD-RA)**: mesmo recálculo bate
  - Run test on UNFIXED code - expect FAILURE (método ainda não existe / recálculo não ocorre)
  - **EXPECTED OUTCOME**: Test FAILS — confirma que o recálculo/verificação ainda não está implementado
  - Document counterexamples: ausência do método de recálculo; nenhuma verificação bate/não-bate ocorre hoje
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 4.1, 4.2, 4.3, 5.1, 5.2_

- [x] 6. Write preservation property tests para fallback (BEFORE implementing fix)
  - **Property 4: Preservation** - Fallback seguro com warning em erro/divergência
  - **IMPORTANT**: Follow observation-first methodology
  - Criar classe de teste em `policy-engine/src/test/java/org/demoiselle/signer/policy/engine/asn1/etsi/SignaturePolicyHashFallbackTest.java`
  - **Observar no código não-corrigido**: hoje o valor do hash usado é sempre `getSignPolicyHash().getDerOctetString()`; esse é o baseline a preservar no caminho de fallback
  - **Escrever testes property-based / de comportamento** (validados após a implementação, mas que expressam o baseline a preservar):
  - Test 1: para `signPolicyHashAlg` com OID desconhecido/indisponível, o valor entregue é igual a `getSignPolicyHash().getDerOctetString()` e nenhuma exceção é lançada
  - Test 2: para política cujo `signPolicyHash` foi adulterado (divergência), o valor entregue é igual ao `Der_Hash` e um warning é logado
  - Test 3: em qualquer erro durante o recálculo, o método nunca lança exceção que quebre a assinatura
  - Test 4: `sigPolicyId`, `hashAlgorithm` e `sigPolicyQualifiers` do atributo permanecem inalterados; apenas o octet string do hash passa pela lógica
  - **EXPECTED OUTCOME**: baseline documentado (o valor do .der é o resultado no fallback); os testes passam após a implementação preservar esse comportamento no caminho de fallback
  - Mark task complete when tests are written and the preserved baseline is documented
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

- [x] 7. Recálculo e verificação do hash da política

  - [x] 7.1 Guardar bytes DER e adicionar métodos de cálculo em SignaturePolicy
    - Arquivo: `policy-engine/src/main/java/org/demoiselle/signer/policy/engine/asn1/etsi/SignaturePolicy.java`
    - Em `parse(ASN1Primitive derObject)`: guardar os primitivos DER de `signPolicyHashAlg` (`derSequence.getObjectAt(0)`) e `signPolicyInfo` (`derSequence.getObjectAt(1)`) em campos privados (ou guardar o `ASN1Sequence` original), suficientes para reconstruir a SEQUENCE sem `signPolicyHash`
    - Adicionar método privado `oidToDigestName(String oid)` mapeando SHA-256/384/512/SHA-1; retorna null para OID desconhecido
    - Adicionar método público `computePolicyHash()`: reconstrói `DERSequence([signPolicyHashAlg, signPolicyInfo])`, aplica o digest do algoritmo de `signPolicyHashAlg` conforme a regra ETSI (sem os campos externos de type/length), retorna os bytes do digest recalculado
    - Documentar explicitamente a variante ETSI adotada (confirmada pelo teste da task 5 contra políticas reais)
    - _Bug_Condition: isBugCondition = recálculo ausente; hash pego direto do .der (Requirements 4.1-4.3)_
    - _Expected_Behavior: hash recalculado pela regra ETSI sobre { signPolicyHashAlg, signPolicyInfo } com o algoritmo de signPolicyHashAlg_
    - _Requirements: 5.1, 5.3, 5.4_

  - [x] 7.2 Implementar getValidatedPolicyHashOctetString() com compara/fallback/warning
    - Arquivo: `policy-engine/.../asn1/etsi/SignaturePolicy.java`
    - Adicionar método público `getValidatedPolicyHashOctetString()`:
      - Se `oidToDigestName(...)` == null: logar WARNING e retornar `signPolicyHash.getDerOctetString()` (fallback)
      - Recalcular via `computePolicyHash()` e comparar com `signPolicyHash.getDerOctetString().getOctets()`
      - Se BATER: retornar `new DEROctetString(recomputed)` (valor recalculado)
      - Se NÃO BATER: logar WARNING e retornar `signPolicyHash.getDerOctetString()` (fallback)
      - Envolver em try/catch: qualquer exceção -> WARNING + fallback; NUNCA propagar exceção nem produzir hash inválido
    - Usar logger padrão do projeto (SLF4J) para os warnings
    - _Bug_Condition: isBugCondition = recálculo ausente/sem verificação (Requirements 4.1-4.3)_
    - _Expected_Behavior: usa recalculado quando bate; fallback + warning quando diverge/erro/algoritmo desconhecido_
    - _Preservation: no fallback, retorna exatamente o valor original do .der; nunca lança exceção_
    - _Requirements: 5.2, 6.1, 6.2, 6.3_

  - [x] 7.3 Consumir o método validado em IdSigningPolicy
    - Arquivo: `policy-impl-cades/src/main/java/org/demoiselle/signer/policy/impl/cades/pkcs7/attribute/impl/IdSigningPolicy.java`
    - Em `getValue()`, substituir `signaturePolicy.getSignPolicyHash().getDerOctetString()` por `signaturePolicy.getValidatedPolicyHashOctetString()` na montagem do `OtherHashAlgAndValue`
    - Manter inalterados `sigPolicyId`, `hashAlgorithm` (a partir de `signPolicyHashAlg`) e `sigPolicyQualifiers`
    - _Expected_Behavior: atributo passa a usar o octet string validado/recalculado_
    - _Preservation: demais campos do atributo inalterados_
    - _Requirements: 5.1, 5.2, 6.4_

  - [x] 7.4 Verificar que o teste de recálculo (exploração) agora passa
    - **Property 3: Expected Behavior** - Uso do hash recalculado quando bate
    - **IMPORTANT**: Re-run the SAME test from task 5 - do NOT write a new test
    - Executar: `cd policy-engine && mvn test -Dtest=SignaturePolicyHashRecomputeTest`
    - **EXPECTED OUTCOME**: Test PASSES (recálculo bate com o .der para políticas reais)
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

  - [x] 7.5 Verificar que os testes de fallback/preservação passam
    - **Property 4: Preservation** - Fallback seguro com warning em erro/divergência
    - **IMPORTANT**: Re-run the SAME tests from task 6 - do NOT write new tests
    - Executar: `cd policy-engine && mvn test -Dtest=SignaturePolicyHashFallbackTest`
    - **EXPECTED OUTCOME**: Tests PASS (fallback para o .der + warning, sem exceção; demais campos inalterados)
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

- [x] 8. Checkpoint - Build e testes da extensão
  - Executar build/testes dos módulos afetados: `cd policy-engine && mvn clean test` e `cd policy-impl-cades && mvn clean test`
  - Verificar que os testes existentes (tasks 1-4) continuam passando (a extensão é aditiva e independente)
  - Verificar que os novos testes (tasks 5, 6) passam após a implementação
  - Ensure all tests pass, ask the user if questions arise.

---

## Teste de Integração Fim-a-Fim

- [x] 9. Escrever e executar teste de integração fim-a-fim do atributo SignaturePolicyIdentifier
  - **Objetivo**: Provar de ponta a ponta que o atributo `SignaturePolicyIdentifier` (id-aa-ets-sigPolicyId) montado no fluxo de assinatura CAdES carrega o `hashAlgorithm` correto (SHA-256, não SHA-512) mesmo com algoritmo de assinatura SHA512withRSA, e um `hashValue` igual ao hash recalculado pela política — integrando a correção de `signPolicyHashAlg` (seções 1-3) com a extensão de recálculo/verificação do hash (seções 4-6)
  - Criada classe de teste em `policy-impl-cades/src/test/java/org/demoiselle/signer/policy/impl/cades/pkcs7/impl/CAdESPolicyHashIntegrationTest.java`
  - **Caminho de integração utilizado**: `IdSigningPolicy.getValue()` (montagem do atributo) alimentado pela `SignaturePolicy` real carregada por `CAdESSigner("SHA512withRSA", Policies.AD_RB_CADES_2_3)` (via `PolicyFactory.loadPolicy()` no construtor), após executar `CAdESSigner.prepareAlgAndLength()` para exercitar o cenário do bug. Este nível foi escolhido porque `doAttachedSign`/`prepareSignedAttributes` disparam `checkCertificateChain()` (validação ICP-Brasil), que falha com certificado self-signed; o caminho adotado é o teste de integração real da montagem do atributo com recálculo, sem depender da infraestrutura de validação de cadeia ICP. Certificado/chave RSA 2048 self-signed gerados via BouncyCastle (mesmo padrão dos testes existentes)
  - **Asserções realizadas** (3 métodos de teste, todos passando):
    - O atributo existe, tem exatamente 1 valor e o Attribute OID é `id-aa-ets-sigPolicyId` (PKCSObjectIdentifiers.id_aa_ets_sigPolicyId)
    - Pré-condição: `signPolicyHashAlg` da política AD-RB é SHA-256; após `prepareAlgAndLength()` com SHA512withRSA permanece SHA-256 (não regride para SHA-512) — valida a correção original
    - `sigPolicyHash.hashAlgorithm` == SHA-256 (OID 2.16.840.1.101.3.4.2.1), NÃO SHA-512 (2.16.840.1.101.3.4.2.3), mesmo com assinatura SHA512withRSA
    - `sigPolicyHash.hashValue` (octets) == `signaturePolicy.computePolicyHash()` == `signaturePolicy.getValidatedPolicyHashOctetString().getOctets()` == `getSignPolicyHash().getDerOctetString().getOctets()` (o recálculo bate com o .der para AD-RB)
    - `sigPolicyId` == OID da política e `sigPolicyQualifiers` contém o qualifierId id-spq-ets-uri — demais campos do atributo preservados
  - **Execução**: `mvn -pl policy-impl-cades -am test -Dtest=CAdESPolicyHashIntegrationTest -Dsurefire.failIfNoSpecifiedTests=false`
  - **RESULTADO**: Tests run: 3, Failures: 0, Errors: 0, Skipped: 0 — BUILD SUCCESS. O fluxo produz o atributo com `hashAlgorithm` = SHA-256 e `hashValue` recalculado idêntico ao valor oficial do .der. Nenhum problema real detectado no fluxo
  - _Requirements: 2.2, 2.4, 5.1, 5.2, 6.4_
