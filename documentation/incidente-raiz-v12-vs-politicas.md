# Relatório de Incidente: Incompatibilidade Raiz v12 vs Políticas ICP-Brasil

## 1. O Problema Reportado
Identificamos que assinaturas digitais geradas por produtos do Serpro (como o SerproID e Neosigner) estavam sendo **rejeitadas pelo Validador do ITI**. 

Isso ocorreu especificamente em documentos assinados por usuários que possuíam certificados recentes, emitidos sob a **Autoridade Certificadora Raiz Brasileira v12**.

### Causa Raiz
As Políticas de Assinatura (PAs) da ICP-Brasil possuem, em seu interior, uma lista estática das raízes de confiança vigentes no momento em que a política foi escrita. 
- As políticas da família **v2.3** e inferiores foram homologadas *antes* da existência da Raiz v12 e, portanto, só reconhecem as raízes v2 e v5.
- As políticas da família **v2.4** (e superiores) foram lançadas justamente para incluir suporte à nova Raiz v12.

Ao tentar assinar um documento usando um certificado da Raiz v12 em um sistema chumbado para usar a política v2.3, a assinatura matemática ocorre com sucesso, mas é legalmente inválida, resultando na rejeição no Validador Oficial.

---

## 2. Esclarecimento: O Atualizador de Políticas "Falhou"?

**Não. O `automacao-importador` (atualizador de políticas) funcionou perfeitamente.**

A confusão ocorreu porque existem duas camadas distintas no framework:
1. **Camada de Infraestrutura (O Importador Go):** A automação conectou-se ao ITI, leu a `LPA.xml`, descobriu as políticas `v2.4` e `v2.5`, baixou os arquivos físicos (`.der` e `.xml`) e os salvou corretamente na pasta `artifacts` do projeto.
2. **Camada de Lógica de Negócio (O Código Java):** O Demoiselle Signer possui um design arquitetural estático. Ele **não lê arquivos dinamicamente** do disco. Para que uma política fique disponível para uso pelas aplicações clientes (Assinador Serpro, etc.), um desenvolvedor precisa escrever o caminho do arquivo no enum `PolicyFactory.Policies.java`.

**Conclusão:** O atualizador trouxe os ingredientes, mas ninguém havia "ensinado" o cozinheiro (Java) a usar os ingredientes novos.

---

## 3. Soluções Implementadas no Demoiselle Signer (Motor)

Para erradicar o problema em todos os assinadores de forma centralizada, as seguintes medidas foram adotadas na versão atual (snapshot):

### A. Mapeamento das Novas Políticas (Hotfix Imediato)
As políticas v2.4 e v2.5 (para CAdES e XAdES) e as políticas v1.2/v1.3 (para PAdES) foram declaradas no `PolicyFactory.java`. Agora, os produtos clientes podem selecionar essas políticas modernas via código.

### B. Atualização dos Construtores Padrão (Defaults)
Se uma aplicação cliente inicializar o assinador sem especificar uma política (`new CAdESSigner()`), o motor agora utiliza por padrão a versão mais segura:
- CAdES: `AD_RB_CADES_2_4` (Era 2.3)
- XAdES: `AD_RB_XADES_2_4`
- PAdES: `AD_RB_PADES_1_2` (Era 1.1)

### C. Trava de Segurança Preditiva (RootCompatValidator)
Para impedir falhas silenciosas, implementamos um validador pré-assinatura.
- **Como funciona:** Antes de aplicar a assinatura matemática, o motor extrai o `IssuerDN` do certificado do signatário.
- **A Regra:** Se for identificada a `Raiz Brasileira v12`, mas a aplicação cliente tiver solicitado uma política antiga (ex: `< v2.4`), a operação é **bloqueada imediatamente**.
- **Comportamento:** O sistema lança a exceção `IncompatiblePolicyException: O certificado pertence a uma hierarquia da Raiz v12... Utilize obrigatoriamente a versao 2.4 ou superior`.

---

## 4. Próximos Passos (Para as Aplicações Clientes)

As equipes responsáveis pelo *Neosigner, SerproID, PDF-Sign-Handler e Assinador Serpro* devem:

1.  **Atualizar Dependência:** Fazer o bump da versão do `demoiselle-signer` em seus arquivos `pom.xml`.
2.  **Atualizar Códigos Legados:** Procurar ocorrências de `Policies.AD_RB_CADES_2_3` nos códigos-fonte e migrar para a versão `2_4`.
3.  **Tratamento de Exceções (UX):** Capturar a nova `IncompatiblePolicyException` nas interfaces gráficas para exibir uma mensagem amigável de erro ao usuário (ex: *"Por favor, atualize as configurações do assinador para suportar seu novo certificado."*), evitando telas de erro genéricas.
4.  **Estudo sobre PAdES sem Política:** (Sugestão futura) Avaliar a transição para assinaturas "padrão ETSI" puras (PAdES-B, PAdES-T), que dependem exclusivamente das cadeias de confiança dos validadores, eliminando o engessamento das políticas brasileiras engessadas.
