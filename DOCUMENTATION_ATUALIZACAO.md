# Guia de Atualização de Artefatos (ICP-Brasil)

Este guia descreve como manter as cadeias de certificados e as políticas de assinatura atualizadas para os ambientes de Produção e Homologação.

## Nova Ferramenta Unificada: `automacao-importador`

Todos os scripts antigos foram removidos e consolidados em uma única ferramenta modular escrita em Go, localizada na pasta `automacao-importador`.

### Por que a ferramenta foi atualizada?
1. **Unificação**: Produção e Homologação agora compartilham o mesmo código, reduzindo duplicação.
2. **Correção do Java/Keytool**: Certificados específicos da ICP-Brasil (como a Raiz v13 ECC) antes falhavam na importação com o erro `A entrada não é um certificado X.509`. A nova ferramenta resolve isso passando todos os certificados baixados por um processo de "limpeza/normalização" usando o OpenSSL antes de entregar ao `keytool`.
3. **Bloqueios de Rede**: A ferramenta injeta headers de navegador (`User-Agent`) para não ser bloqueada pelos firewalls do ITI.

---

## Requisitos Prévios

1.  **Go (Golang)** instalado (versão 1.21+ recomendada).
2.  **Java & Keytool** no PATH.
3.  **OpenSSL** instalado no sistema (usado para normalizar certificados).
4.  O arquivo `bcprov-lts8on-2.73.11.jar` deve estar presente nas pastas adequadas (`chain-icp-brasil/src/scripts_keytool` e `chain-icp-brasil-homolog`).

---

## Como Atualizar os Artefatos

Abra o terminal na **raiz do projeto** (`signer-evandrojr`) e execute a ferramenta informando o ambiente desejado.

### 1. Atualizar PRODUÇÃO
Baixa as políticas, baixa as cadeias do ITI (`ACcompactadox.zip`), limpa os arquivos corrompidos e gera o `cadeiasicpbrasil.bks`.

```bash
cd automacao-importador
go run main.go -env=pro
```

### 2. Atualizar HOMOLOGAÇÃO
Baixa apenas as cadeias do repositório do Serpro (lendo o HTML e convertendo os arquivos `.p7b`), limpa e gera o `cadeiasicpbrasil-HOMOLOGACAO.bks`.

```bash
cd automacao-importador
go run main.go -env=hom
```

### O que o script faz por debaixo dos panos?
- **Pro**: Salva as políticas em `policy-engine/.../artifacts` e o BKS em `chain-icp-brasil/src/main/resources/`.
- **Hom**: Salva o BKS em `chain-icp-brasil-homolog/src/main/resources/`.

Após a atualização, execute `mvn clean install -DskipTests` e rode os testes de integração (`mvn verify -Pit`).

---

## Dúvidas Frequentes

### Como as LPAs (Listas de Políticas de Assinatura) funcionam e por que ocorrem "erros" de importação?
O Demoiselle Signer hoje não lê o arquivo global da LPA automaticamente. A infraestrutura do ITI publica uma lista mestra em `http://politicas.icpbrasil.gov.br/LPA.xml`. Dentro deste XML ficam as referências (`PolicyURI`) para cada nova política (ex: `PA_AD_RB_v2_4.xml`).

Quando ocorre um erro na importação das políticas pela nossa ferramenta, normalmente significa que:
1. O repositório da ICP-Brasil pode estar instável.
2. O arquivo na ICP-Brasil está sem a versão do hash (`-sha256.txt`). A nova ferramenta foi programada para ignorar amigavelmente hashes ausentes e focar em baixar a política.

### Como saber se surgiram novas LPAs não cadastradas no DS?
A forma correta de detectar novas políticas não suportadas pelo componente é:
1. Acessar manualmente ou via script a URL: `http://politicas.icpbrasil.gov.br/LPA.xml`.
2. Procurar pela tag `<PolicyURI>`.
3. Comparar as URLs listadas neste arquivo com as que estão cadastradas no seu arquivo `policy-engine/automacao-atualizacao/politicas.txt`.
4. Se o ITI publicar uma `PA_AD_RB_v3_0.xml` na `LPA.xml`, você deverá adicioná-la ao `politicas.txt` e rodar a nossa ferramenta novamente com `-env=pro`.
