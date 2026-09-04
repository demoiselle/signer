# Bugfix Requirements Document

## Introduction

O método `prepareAlgAndLength()` em `CAdESSigner.java` sobrescreve incorretamente o campo `signPolicyHashAlg` do objeto `SignaturePolicy` com o OID do algoritmo de hash derivado do algoritmo de assinatura do certificado (ex: SHA-512 para SHA512withRSA). Esse campo representa o algoritmo usado para calcular o hash do **arquivo .der da política de assinatura**, e não o algoritmo de hash usado na assinatura do documento.

Como consequência, o atributo `SignaturePolicyIdentifier` (id-aa-ets-sigPolicyId) na assinatura CAdES é montado com o `hashAlgorithm` incorreto (SHA-512 em vez de SHA-256), causando rejeição pelo serviço VALIDAR do ITI conforme Nota Técnica Nº 4/2026/CGOPE/DITEC. O impacto atinge todas as assinaturas ICP-Brasil geradas pelo demoiselle-signer quando o algoritmo de assinatura difere do algoritmo de hash da política (ex: SHA512withRSA com política que usa SHA-256 para seu hash).

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN o certificado do assinante usa SHA512withRSA e a política de assinatura define SHA-256 como algoritmo de hash do arquivo .der da política THEN o sistema sobrescreve o campo `signPolicyHashAlg` da `SignaturePolicy` com o OID do SHA-512 (2.16.840.1.101.3.4.2.3) no método `prepareAlgAndLength()`

1.2 WHEN o atributo SignaturePolicyIdentifier é montado pelo `IdSigningPolicy.getValue()` após a execução de `prepareAlgAndLength()` THEN o sistema gera o campo `hashAlgorithm` do `sigPolicyHash` com OID SHA-512 em vez de SHA-256

1.3 WHEN o algoritmo de assinatura não é informado como parâmetro e o sistema seleciona um da lista da política (branch else do prepareAlgAndLength) THEN o sistema também sobrescreve o `signPolicyHashAlg` com o OID do hash do algoritmo selecionado

1.4 WHEN a assinatura CAdES gerada com hashAlgorithm incorreto é submetida ao serviço VALIDAR do ITI THEN a assinatura é reprovada por não conformidade com a política

### Expected Behavior (Correct)

2.1 WHEN o certificado do assinante usa qualquer algoritmo de assinatura (SHA512withRSA, SHA256withRSA, etc.) e a política de assinatura define um algoritmo de hash para o arquivo .der da política THEN o sistema SHALL preservar intacto o campo `signPolicyHashAlg` original carregado do arquivo .der da política, sem sobrescrevê-lo

2.2 WHEN o atributo SignaturePolicyIdentifier é montado pelo `IdSigningPolicy.getValue()` THEN o sistema SHALL usar o `signPolicyHashAlg` original da política (conforme definido no arquivo .der) para o campo `hashAlgorithm` do `sigPolicyHash`

2.3 WHEN o algoritmo de assinatura não é informado como parâmetro e o sistema seleciona um da lista da política THEN o sistema SHALL selecionar o algoritmo sem modificar o `signPolicyHashAlg` da política

2.4 WHEN a assinatura CAdES é gerada com o hashAlgorithm correto (igual ao definido na política) THEN o sistema SHALL produzir assinaturas válidas conforme a Nota Técnica Nº 4/2026/CGOPE/DITEC do ITI

### Unchanged Behavior (Regression Prevention)

3.1 WHEN o método `prepareAlgAndLength()` é executado com um algoritmo informado como parâmetro que consta na lista de algoritmos permitidos pela política THEN o sistema SHALL CONTINUE TO selecionar corretamente o `AlgAndLength` correspondente e configurar o algoritmo de assinatura no `pkcs1`

3.2 WHEN o método `prepareAlgAndLength()` é executado sem algoritmo informado como parâmetro THEN o sistema SHALL CONTINUE TO selecionar o segundo algoritmo da lista da política (índice 1) e configurar o `pkcs1` com esse algoritmo

3.3 WHEN o método `prepareAlgAndLength()` é executado com um algoritmo que não consta na lista de algoritmos permitidos pela política THEN o sistema SHALL CONTINUE TO lançar `SignerException` com mensagem "error.no.algorithm.policy"

3.4 WHEN o `algorithmConstraintSet` da política é nulo ou não define `signerAlgorithmConstraints` THEN o sistema SHALL CONTINUE TO usar o algoritmo configurado ou o DEFAULT como fallback

3.5 WHEN o atributo SignaturePolicyIdentifier é montado THEN o sistema SHALL CONTINUE TO incluir corretamente o `sigPolicyId` (OID da política), o `sigPolicyHash` (valor do hash) e o `sigPolicyQualifiers` (URI da política)

---

## Extensão: Recálculo e Verificação do Hash da Política

Nova abordagem aditiva, decidida com o usuário, independente da correção de `signPolicyHashAlg` descrita nas seções 1-3. Hoje o valor do `signPolicyHash` usado no atributo `SignaturePolicyIdentifier` vem diretamente do arquivo .der (`signaturePolicy.getSignPolicyHash().getDerOctetString()`), sem qualquer recálculo ou verificação. Conforme a regra ETSI (comentário de cabeçalho da classe `SignaturePolicy`), o hash da política DEVE ser recalculado e checado sempre que a política transita entre emissor e assinante/verificador, calculado sobre a estrutura `SignaturePolicy` excluindo o campo `signPolicyHash` e sem os campos externos de type/length. Esta extensão implementa esse recálculo/verificação com fallback seguro.

### Current Behavior (Defect)

4.1 WHEN o atributo `SignaturePolicyIdentifier` é montado por `IdSigningPolicy.getValue()` THEN o sistema pega o valor do `signPolicyHash` diretamente do arquivo .der (`signaturePolicy.getSignPolicyHash().getDerOctetString()`), sem recalcular

4.2 WHEN a política é carregada e parseada por `SignaturePolicy.parse(ASN1Primitive derObject)` THEN o sistema NÃO guarda os bytes/estrutura DER originais, impossibilitando qualquer recálculo posterior do hash da política

4.3 WHEN o valor do `signPolicyHash` presente no .der estiver divergente do hash real da estrutura da política THEN o sistema NÃO detecta a divergência e usa o valor do .der sem verificação

### Expected Behavior (Correct)

5.1 WHEN o atributo `SignaturePolicyIdentifier` é montado THEN o sistema SHALL recalcular o hash da política sobre a estrutura `SignaturePolicy` reconstruída contendo apenas `signPolicyHashAlg` + `signPolicyInfo` (excluindo `signPolicyHash`), sem os campos externos de type/length, usando o algoritmo de digest indicado por `signPolicyHashAlg`

5.2 WHEN o valor recalculado for igual ao `signPolicyHash` presente no .der THEN o sistema SHALL usar o valor RECALCULADO no atributo `SignaturePolicyIdentifier`

5.3 WHEN `SignaturePolicy.parse()` é executado THEN o sistema SHALL guardar os bytes/estrutura DER originais necessários para o recálculo posterior do hash da política

5.4 WHEN o recálculo é solicitado THEN o sistema SHALL expor um método público na classe `SignaturePolicy` (ex: `computePolicyHash()` que retorna o octet string recalculado e/ou `getValidatedPolicyHashOctetString()` que aplica a lógica compara/fallback/warning) para ser consumido por `IdSigningPolicy`

### Unchanged Behavior (Regression Prevention)

6.1 WHEN o valor recalculado NÃO bater com o `signPolicyHash` do .der THEN o sistema SHALL CONTINUE TO usar como fallback o valor original do .der (`signaturePolicy.getSignPolicyHash().getDerOctetString()`) e SHALL emitir um WARNING via logger

6.2 WHEN o algoritmo indicado por `signPolicyHashAlg` for desconhecido/indisponível para `MessageDigest`, ou quando ocorrer qualquer erro durante o recálculo THEN o sistema SHALL CONTINUE TO usar como fallback o valor original do .der e SHALL emitir um WARNING via logger, sem lançar exceção que quebre a assinatura

6.3 WHEN o recálculo/verificação é executado THEN o sistema SHALL NUNCA produzir hash inválido nem lançar exceção que interrompa a geração da assinatura por causa do recálculo

6.4 WHEN o atributo `SignaturePolicyIdentifier` é montado THEN o sistema SHALL CONTINUE TO montar corretamente o `sigPolicyId` (OID da política), o `hashAlgorithm` do `sigPolicyHash` (a partir de `signPolicyHashAlg`) e os `sigPolicyQualifiers` (URI da política), sem alteração — apenas o valor do octet string do hash passa pela lógica de recálculo/verificação

6.5 WHEN a correção descrita nas seções 1-3 (preservação de `signPolicyHashAlg` em `prepareAlgAndLength`) está aplicada THEN o sistema SHALL CONTINUE TO preservar esse comportamento — esta extensão é aditiva e independente
