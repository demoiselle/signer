package org.demoiselle.signer.importador.dominio;

public record FalhaDownload(
        String fonteId,   // recurso que falhou (URL/arquivo)
        Origem origem,
        String motivo     // timeout, status HTTP, conteudo invalido, etc.
) {}
