# Requirements Document

## Introduction

A ferramenta `automacao-importador` será (re)implementada em Java, integrada ao build Maven do projeto, manipulando o keystore BKS nativamente via API do BouncyCastle (`java.security.KeyStore` com provider BC e `java.security.cert.X509Certificate`), eliminando a dependência de subprocessos externos `keytool` e `openssl`. Ela baixa e importa cadeias de certificados e políticas ICP-Brasil para os keystores BKS de produção e homologação. O processo atual apresenta falhas confirmadas: erros de download não abortam a execução, cadeias incompletas são publicadas silenciosamente, e o keystore final contém certificados duplicados e conflitos de case (por exemplo "Hom" vs "HOM") que quebram o CAManager.

Esta feature reestrutura a ferramenta em dois processos distintos e independentes, expostos como subcomandos do mesmo binário:

- **Processo `baixar`**: baixa todas as cadeias para uma área de staging e emite um relatório de inconsistências, sem tocar no keystore final.
- **Processo `persistir`**: aplica os certificados já baixados no keystore BKS, com deduplicação configurável.

O objetivo é garantir que o keystore reflita exatamente o que a ICP-Brasil publica (sem filtro por validade), que falhas de download sejam explícitas em vez de silenciosas, e que duplicatas e conflitos de case sejam tratados de forma controlada pelo operador.

## Glossary

- **Importador**: A ferramenta de automação de importação de artefatos ICP-Brasil, implementada em Java e integrada ao build Maven do projeto.
- **Processo_Baixar**: O subcomando `baixar` do Importador, responsável por baixar cadeias para a staging e emitir relatório, sem persistir no keystore final.
- **Processo_Persistir**: O subcomando `persistir` do Importador, responsável por aplicar os certificados da staging no keystore BKS.
- **Staging**: Área de trabalho em disco onde os certificados baixados pelo Processo_Baixar são armazenados antes de qualquer persistência no keystore final.
- **Keystore_Final**: O arquivo BKS de destino (produção `cadeiasicpbrasil.bks` ou homologação `cadeiasicpbrasil-HOMOLOGACAO.bks`) manipulado nativamente via API KeyStore do BouncyCastle e consumido pelas aplicações de assinatura.
- **Relatorio_Inconsistencias**: O relatório emitido pelo Processo_Baixar contendo downloads que falharam, cadeias duplicadas, conflitos de case e demais problemas detectados.
- **Relatorio_Persistencia**: O relatório emitido pelo Processo_Persistir ao final da gravação, comparando o Keystore_Final antes e depois da operação, listando cadeias adicionadas, cadeias removidas e ajustes aplicados (deduplicações, resoluções de Conflito_De_Case e renomeações de alias).
- **Conflito_De_Case**: Situação em que dois certificados possuem o mesmo CN quando comparado de forma case-insensitive mas com grafia diferente (por exemplo "Hom" vs "HOM"), resultando em serials distintos.
- **Duplicata_Exata**: Dois ou mais certificados com o mesmo serial e o mesmo subject.
- **Metodo_Dedup**: O método de deduplicação selecionado pela flag `--remover-duplicadas`, com valores 1 (conservador) ou 2 (agressivo).
- **Metodo_Conservador**: Metodo_Dedup valor 1, que remove apenas Duplicatas_Exatas.
- **Metodo_Agressivo**: Metodo_Dedup valor 2, que agrupa certificados por CN case-insensitive e mantém apenas um por grupo.
- **Not_Before**: A data de início de validade de um certificado (campo notBefore do X.509, acessível via X509Certificate.getNotBefore()).
- **CAManager**: Componente Java consumidor do Keystore_Final que resolve autoridades certificadoras por CN de forma case-insensitive e é sensível a Conflitos_De_Case.

## Requirements

### Requirement 1: Dois subcomandos distintos (baixar e persistir)

**User Story:** Como operador do Importador, quero executar o download e a persistência das cadeias em dois processos distintos, para que eu possa revisar as inconsistências antes de alterar o keystore.

#### Acceptance Criteria

1. THE Importador SHALL expor o Processo_Baixar e o Processo_Persistir como subcomandos distintos do mesmo binário, invocáveis de forma independente.
2. WHEN o operador invoca o Processo_Baixar, THE Processo_Baixar SHALL gravar os certificados baixados na Staging sem realizar qualquer escrita, remoção ou alteração no Keystore_Final.
3. WHEN o Processo_Baixar conclui o download, THE Processo_Baixar SHALL reportar ao operador a quantidade de certificados gravados na Staging e encerrar com indicação de sucesso.
4. IF o Processo_Baixar não consegue baixar um ou mais certificados devido a indisponibilidade da origem ou erro de rede, THEN THE Processo_Baixar SHALL preservar os certificados já gravados na Staging, não modificar o Keystore_Final e reportar ao operador uma indicação de erro identificando os certificados não baixados.
5. WHEN o operador invoca o Processo_Persistir e a Staging contém ao menos um certificado baixado, THE Processo_Persistir SHALL aplicar no Keystore_Final todos os certificados presentes na Staging.
6. IF o operador invoca o Processo_Persistir e a Staging não contém nenhum certificado baixado, THEN THE Processo_Persistir SHALL abortar a execução sem modificar o Keystore_Final e reportar uma indicação de erro informando que o Processo_Baixar precisa ser executado primeiro.
7. IF o Processo_Persistir falha ao aplicar um ou mais certificados no Keystore_Final, THEN THE Processo_Persistir SHALL reverter o Keystore_Final ao estado anterior ao início da execução e reportar ao operador uma indicação de erro identificando os certificados não aplicados.

### Requirement 2: Download completo de produção e homologação

**User Story:** Como operador do Importador, quero que o Processo_Baixar baixe todas as cadeias de produção e homologação para a staging, para que eu tenha o conjunto completo disponível para inspeção.

#### Acceptance Criteria

1. WHEN o operador invoca o Processo_Baixar, THE Processo_Baixar SHALL baixar os certificados da cadeia de produção a partir do arquivo compactado (ACcompactadox.zip) e do arquivo p7b da TSA, e os certificados das cadeias de homologação a partir de todos os arquivos .p7b listados na página HTML de homologação, armazenando todos na Staging.
2. THE Processo_Baixar SHALL armazenar cada certificado baixado na Staging sem gravar nenhum certificado no Keystore_Final.
3. IF o download de qualquer fonte (ACcompactadox.zip, p7b da TSA, página HTML de homologação ou qualquer .p7b de homologação) não for concluído em até 30 segundos por tentativa, THEN THE Processo_Baixar SHALL repetir a tentativa até no máximo 3 vezes antes de sinalizar falha.
4. IF, após 3 tentativas, uma fonte permanecer inacessível ou o conteúdo baixado não puder ser interpretado como certificado válido, THEN THE Processo_Baixar SHALL encerrar com indicação de erro identificando a fonte que falhou e SHALL não gravar nenhum certificado no Keystore_Final.
5. WHILE ocorre uma falha de download ou de interpretação de qualquer fonte, THE Processo_Baixar SHALL preservar na Staging apenas os certificados já baixados e íntegros, sem removê-los.

### Requirement 3: Relatório de inconsistências

**User Story:** Como operador do Importador, quero um relatório de inconsistências ao final do download, para que eu saiba o que falhou e quais problemas existem antes de persistir.

#### Acceptance Criteria

1. WHEN o Processo_Baixar conclui a etapa de download de todas as cadeias, THE Processo_Baixar SHALL emitir o Relatorio_Inconsistencias antes de qualquer operação de persistência.
2. THE Relatorio_Inconsistencias SHALL listar cada download que falhou, identificando cada entrada pela cadeia de origem e pelo motivo da falha.
3. THE Relatorio_Inconsistencias SHALL listar cada cadeia duplicada detectada na Staging, identificando cada entrada pela cadeia envolvida e pelo tipo de duplicação (Duplicata_Exata).
4. THE Relatorio_Inconsistencias SHALL listar cada Conflito_De_Case detectado na Staging, identificando cada entrada pelas cadeias em conflito.
5. IF um ou mais downloads de cadeias de homologação falharem, THEN THE Relatorio_Inconsistencias SHALL identificar cada cadeia de homologação que faltou pelo seu identificador de origem.
6. IF nenhuma falha de download, cadeia duplicada ou Conflito_De_Case for detectado, THEN THE Relatorio_Inconsistencias SHALL indicar explicitamente a ausência de inconsistências.

### Requirement 4: Métodos de deduplicação configuráveis

**User Story:** Como operador do Importador, quero escolher o método de deduplicação ao persistir, para que eu controle como duplicatas e conflitos de case são resolvidos.

#### Acceptance Criteria

1. THE Processo_Persistir SHALL aceitar a flag `--remover-duplicadas` com os valores 1 (Metodo_Conservador) e 2 (Metodo_Agressivo).
2. IF a flag `--remover-duplicadas` é omitida, THEN THE Processo_Persistir SHALL aplicar o Metodo_Conservador como comportamento padrão.
3. IF a flag `--remover-duplicadas` recebe um valor diferente de 1 e 2, THEN THE Processo_Persistir SHALL rejeitar a operação sem gravar no Keystore_Final, preservar o Keystore_Final inalterado e apresentar uma mensagem de erro indicando que o valor da flag é inválido.
4. WHERE o Metodo_Conservador é selecionado, THE Processo_Persistir SHALL remover apenas as Duplicatas_Exatas antes de gravar no Keystore_Final.
5. WHERE o Metodo_Conservador é selecionado, THE Processo_Persistir SHALL preservar certificados que constituam um Conflito_De_Case.
6. WHERE o Metodo_Agressivo é selecionado, THE Processo_Persistir SHALL agrupar os certificados por CN comparado de forma case-insensitive e manter exatamente um certificado por grupo, conforme o critério de seleção definido no criterio 7.
7. WHERE o Metodo_Agressivo é selecionado E um grupo de CN case-insensitive contém mais de um certificado, THE Processo_Persistir SHALL manter o certificado com o Not_Before mais recente e descartar os demais do grupo.
8. WHERE o Metodo_Agressivo é selecionado E dois ou mais certificados de um mesmo grupo de CN case-insensitive possuem o Not_Before idêntico e mais recente do grupo, THE Processo_Persistir SHALL manter apenas o primeiro certificado encontrado nessa condição e descartar os demais do grupo.

### Requirement 5: Ajuda explicando os métodos de deduplicação

**User Story:** Como operador do Importador, quero que a ajuda explique cada método de deduplicação e suas implicações, para que eu escolha o método com pleno conhecimento das consequências.

#### Acceptance Criteria

1. WHEN o operador invoca o Processo_Persistir com `-h` ou `--help`, THE Processo_Persistir SHALL exibir a descrição do Metodo_Conservador, indicando que remove apenas Duplicatas_Exatas e que Conflitos_De_Case permanecem.
2. WHEN o operador invoca o Processo_Persistir com `-h` ou `--help`, THE Processo_Persistir SHALL exibir a descrição do Metodo_Agressivo, indicando que agrupa por CN case-insensitive, mantém o certificado de Not_Before mais recente e que certificados distintos de mesmo CN podem ser descartados.
3. IF o operador invoca o Processo_Persistir com `-h` ou `--help`, THEN THE Processo_Persistir SHALL exibir a ajuda sem baixar certificados, sem aplicar deduplicação e sem modificar o Keystore_Final.

### Requirement 6: Preservação de certificados expirados

**User Story:** Como operador do Importador, quero que certificados expirados sejam mantidos, para que o keystore reflita exatamente o que a ICP-Brasil publica.

#### Acceptance Criteria

1. IF o período de validade de um certificado já expirou em relação ao instante corrente do processamento, THEN THE Processo_Baixar SHALL manter esse certificado na Staging sem removê-lo nem marcá-lo como inválido.
2. IF o período de validade de um certificado já expirou em relação ao instante corrente do processamento, THEN THE Processo_Persistir SHALL gravar esse certificado no Keystore_Final sem descartá-lo por motivo de validade.
3. THE Processo_Persistir SHALL gravar no Keystore_Final todos os certificados presentes na Staging sem aplicar qualquer filtro baseado no período de validade.
4. WHILE o Metodo_Agressivo estiver em execução e houver mais de um certificado candidato com a mesma identidade de titular, THE Processo_Persistir SHALL usar o Not_Before exclusivamente como critério de desempate, selecionando o certificado com Not_Before mais recente, sem excluir os demais candidatos por motivo de validade.

### Requirement 7: Falhas de download não publicam silenciosamente

**User Story:** Como operador do Importador, quero que falhas de download impeçam a publicação silenciosa de cadeias incompletas, para que eu não gere um keystore inconsistente sem perceber.

#### Acceptance Criteria

1. IF um ou mais downloads falharem durante o Processo_Baixar, THEN THE Processo_Baixar SHALL registrar, no Relatorio_Inconsistencias, uma entrada por falha contendo o identificador do recurso que falhou e o motivo da falha.
2. IF o Processo_Persistir e a etapa de download forem combinados em um fluxo único e ocorrer ao menos uma falha de download, THEN THE Importador SHALL solicitar confirmação do operador antes de gravar no Keystore_Final e SHALL indicar a quantidade de falhas registradas no Relatorio_Inconsistencias.
3. WHERE o Importador solicita confirmação para continuar após falhas de download, THE Importador SHALL adotar "não" como resposta padrão.
4. IF o operador não confirmar explicitamente a continuação com a resposta "sim" após falhas de download, THEN THE Importador SHALL abortar a gravação no Keystore_Final e SHALL preservar inalterado o conteúdo existente do Keystore_Final.
5. WHERE a execução do Importador ocorre sem TTY interativo e ocorreu ao menos uma falha de download, THE Importador SHALL aplicar a resposta padrão "não" e abortar a gravação no Keystore_Final sem aguardar entrada do operador.
6. IF um download não for concluído em até 30 segundos, THEN THE Processo_Baixar SHALL tratá-lo como falha, registrá-lo no Relatorio_Inconsistencias e limitar a no máximo 3 tentativas por recurso antes de declarar a falha definitiva.

### Requirement 8: Aliases sem colisão e sem conflito de case

**User Story:** Como operador do Importador, quero que o keystore gerado não contenha aliases conflitantes por serial ou subject, para que o CAManager resolva as autoridades certificadoras corretamente.

#### Acceptance Criteria

1. WHEN o Processo_Persistir grava um certificado no Keystore_Final, THE Processo_Persistir SHALL atribuir a esse certificado um alias único que não seja igual, ignorando diferenças de maiúsculas e minúsculas, a nenhum alias já existente no Keystore_Final.
2. IF o alias derivado para um certificado colide com um alias já existente no Keystore_Final, THEN THE Processo_Persistir SHALL gerar um alias alternativo determinístico que torne o alias único antes de gravar o certificado.
3. WHEN o Processo_Persistir aplica o Metodo_Agressivo, THE Processo_Persistir SHALL garantir que o Keystore_Final não contenha dois aliases que difiram apenas por maiúsculas e minúsculas (Conflito_De_Case).
4. IF o Processo_Persistir detecta um Conflito_De_Case durante o Metodo_Agressivo, THEN THE Processo_Persistir SHALL manter apenas uma das entradas conflitantes no Keystore_Final e descartar as demais, preservando as entradas sem conflito.
5. WHEN o Processo_Persistir conclui a gravação do Keystore_Final, THE Processo_Persistir SHALL assegurar que cada certificado seja recuperável por um alias único, de modo que o CAManager resolva cada autoridade certificadora sem ambiguidade.

### Requirement 9: Encerramento reflete o resultado real

**User Story:** Como operador do Importador, quero que o encerramento da execução reflita o resultado real, para que uma mensagem de sucesso não apareça quando houve falhas.

#### Acceptance Criteria

1. IF ocorreram falhas durante o Processo_Baixar ou o Processo_Persistir, THEN THE Importador SHALL encerrar com código de saída diferente de zero e reportar que a execução teve falhas, identificando qual processo falhou e a quantidade de falhas.
2. WHEN nenhuma falha ocorre durante a execução, THE Importador SHALL encerrar com código de saída zero e reportar conclusão bem-sucedida.

### Requirement 10: Relatório de diferenças pós-persistência

**User Story:** Como operador do Importador, quero um relatório ao final da persistência informando quais cadeias entraram, quais saíram e quais ajustes foram feitos, para que eu tenha rastreabilidade completa de cada publicação do keystore.

#### Acceptance Criteria

1. WHEN o Processo_Persistir conclui com sucesso a gravação do Keystore_Final, THE Processo_Persistir SHALL emitir o Relatorio_Persistencia.
2. THE Relatorio_Persistencia SHALL listar cada cadeia presente no Keystore_Final após a operação que não estava presente antes dela, identificando-a por subject e serial, considerando que, WHERE o Keystore_Final não existia antes da operação, todas as cadeias gravadas contam como adicionadas.
3. THE Relatorio_Persistencia SHALL listar cada cadeia presente no Keystore_Final antes da operação que não está mais presente após ela, identificando-a por subject e serial.
4. WHERE o Metodo_Conservador ou o Metodo_Agressivo removeu uma ou mais Duplicatas_Exatas, THE Relatorio_Persistencia SHALL listar cada certificado descartado por deduplicação, identificando-o por subject e serial.
5. WHERE o Metodo_Agressivo resolveu um ou mais Conflitos_De_Case, THE Relatorio_Persistencia SHALL listar cada Conflito_De_Case resolvido, indicando o certificado mantido e os certificados descartados por subject e serial.
6. IF um alias precisou ser renomeado para evitar colisão durante a gravação, THEN THE Relatorio_Persistencia SHALL listar o alias original e o alias final atribuído.
7. IF nenhuma cadeia foi adicionada, nenhuma cadeia foi removida e nenhum ajuste foi aplicado, THEN THE Relatorio_Persistencia SHALL indicar explicitamente que o Keystore_Final permaneceu inalterado.
8. IF a gravação do Keystore_Final falhou e sofreu rollback, THEN THE Processo_Persistir SHALL abster-se de emitir o Relatorio_Persistencia e preservar o Keystore_Final no estado anterior à operação.
