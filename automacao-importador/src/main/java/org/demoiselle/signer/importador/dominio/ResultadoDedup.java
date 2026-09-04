package org.demoiselle.signer.importador.dominio;

import java.util.List;

/** Resultado da deduplicacao (entrada para o relatorio de persistencia). */
public record ResultadoDedup(
        List<Certificado> mantidos,
        List<Certificado> descartadosDuplicata,   // duplicatas exatas removidas
        List<ConflitoResolvido> conflitosCase      // preenchido apenas no metodo agressivo
) {}
