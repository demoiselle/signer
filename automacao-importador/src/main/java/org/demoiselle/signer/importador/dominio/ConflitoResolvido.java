package org.demoiselle.signer.importador.dominio;

import java.util.List;

public record ConflitoResolvido(
        String cnNorm,
        Certificado mantido,
        List<Certificado> descartados
) {}
