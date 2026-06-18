# Suporte a Selo Eletrônico (Resolução 211 ICP-Brasil)

## 1. Contexto
A Resolução 211 da ICP-Brasil introduziu o certificado de **Selo Eletrônico**, destinado a pessoas jurídicas para identificação de algoritmos e equipamentos (assinatura automatizada), sem a necessidade de um representante humano (CPF do responsável) no certificado.

## 2. Requisitos de Implementação no Core

### 2.1 Identificação de Tipos de Certificado
O Demoiselle Signer deve reconhecer formalmente o tipo de certificado Selo Eletrônico (SE) através das Políticas de Certificação (OIDs):
* **SE-S (Software):** `2.16.76.1.2.201`
* **SE-H (Hardware):** `2.16.76.1.2.202`

### 2.2 Extração de Atributos
Diferente dos certificados PJ tradicionais, o Selo Eletrônico:
* **CNPJ:** Deve ser extraído prioritariamente do campo `serialNumber` (OID `2.5.4.5`) do *Subject DN*.
* **Responsável:** Não possui nome ou CPF de responsável. Consultas a esses campos devem retornar `null` de forma segura.

### 2.3 Compatibilidade com Java 25+
Devido a mudanças na implementação de `getSubjectAlternativeNames()` em versões recentes do JRE, o parsing de `OtherName` (utilizado pela ICP-Brasil para CPF/CNPJ) deve ser feito via BouncyCastle diretamente sobre os bytes da extensão, evitando dependência de classes internas `sun.security.*` que foram restringidas ou alteradas.

## 3. Estrutura de Classes
* `org.demoiselle.signer.core.extension.ICPBrasilExtensionType`: Adicionar tipo `SE`.
* `org.demoiselle.signer.core.extension.ICPBRCertificateSE`: Nova classe para representar os atributos do Selo.
* `org.demoiselle.signer.core.extension.BasicCertificate`: Adicionar métodos `isCertificateSE()` e `getICPBRCertificateSE()`.
* `org.demoiselle.signer.core.extension.CertificateExtra`: Atualizar para reconhecer OIDs de Selo e suportar parsing Java 25+.
