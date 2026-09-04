package org.demoiselle.signer.importador.dominio;

import java.util.List;

/** Diferenca calculada entre o keystore antes e depois. */
public record DiffKeystore(
        List<Certificado> adicionadas,
        List<Certificado> removidas,
        List<Certificado> descartadasDedup,
        List<ConflitoResolvido> conflitosResolvidos,
        List<AtribuicaoAlias> aliasesRenomeados,
        boolean inalterado
) {}
