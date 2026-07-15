# Atualização de Artefatos ICP-Brasil

<description>
Esta skill automatiza e guia o processo de atualização das Listas de Políticas de Assinatura (LPAs) e das Cadeias de Certificados da ICP-Brasil para os ambientes de Produção e Homologação do Demoiselle Signer.
</description>

<instructions>
Esta skill utiliza o projeto em Go `automacao-importador` presente na raiz do repositório para baixar arquivos do ITI e do Serpro, processá-los (removendo sujeiras de PEM via OpenSSL) e injetá-los no projeto Java.

## Fluxo de Trabalho (Workflow)

Quando o usuário pedir para atualizar as políticas ou cadeias, siga ESTRITAMENTE esta ordem:

### Passo 1: Autodescoberta de Políticas (Update LPA)
O ITI frequentemente lança novas políticas (ex: v2.4, v2.5). Antes de baixar arquivos velhos, devemos atualizar nosso índice.
1. Execute: `cd automacao-importador && go run main.go -update-lpa`
2. **Lição Crítica (Atenção às Versões Diferentes):** As versões que suportam as mesmas raízes podem ser diferentes dependendo do formato de assinatura. Exemplo (Suporte Raiz v12):
   - **CAdES:** O padrão (RB, RT, RV, RC) é `v2.4`, mas o `RA` é `v2.5`.
   - **XAdES:** Tudo usa `v2.5`.
   - **PAdES:** RB/RT usam `v1.3`. RC/RA usam `v1.4`.
3. Se o log indicar que "novas URLs foram encontradas", você DEVE:
   - Adicionar as constantes `.der` e `.xml` manualmente na classe `PolicyFactory.java`.
   - Se houver XAdES novo, atualizar o enum `XMLPoliciesOID.java` com os novos OIDs.
   - Atualizar os construtores "vazios" (Default) nas classes `CAdESSigner`, `PAdESSigner` e `XMLSigner` para essas versões descobertas.

### Passo 2: Atualização de Produção
Responsável por baixar do repositório raiz do ITI.
1. Execute: `cd automacao-importador && go run main.go -env=pro`
2. Valide se a saída contém "ATUALIZAÇÃO CONCLUÍDA!".

### Passo 3: Atualização de Homologação
Responsável por baixar do repositório do Serpro (conversão de p7b para crt).
1. Execute: `cd automacao-importador && go run main.go -env=hom`
2. Valide se a saída contém "ATUALIZAÇÃO CONCLUÍDA!".

### Passo 4: Verificação de Compilação
Após atualizar os binários (.der, .xml, .bks), é crucial garantir que o projeto ainda compila e que os testes de integração (que validam cadeias reais) não quebraram.
1. Volte para a raiz do repositório.
2. Execute: `mvn clean install -DskipTests`
3. Execute os testes de integração do core: `mvn verify -pl core -Pit`

### Passo 5: Commit e Aviso Final
Se tudo passou, prepare o commit (não force push, apenas deixe pronto ou pergunte se o usuário quer que faça o push).
- Diga ao usuário que a manutenção de rotina está concluída.
- Lembre-o de verificar as Aplicações Clientes (Neosigner, Assinador Serpro), pois o `demoiselle-signer` pode ter recebido novas `IncompatiblePolicyException` dependendo dos certificados usados nos testes das pontas.

## Dicas para Troubleshooting

* Se o comando Go falhar por timeout, tente rodar novamente. O servidor do ITI oscila.
* Se a importação do BKS falhar dizendo que "não é X.509", garanta que o comando `openssl` está instalado na máquina, pois o Go o utiliza em background para normalizar os arquivos `.crt` problemáticos.
</instructions>
