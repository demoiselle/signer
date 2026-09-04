package org.demoiselle.signer.importador.io;

import java.util.Objects;

import org.demoiselle.signer.importador.dominio.Manifest;

/**
 * Resultado da orquestração de download por {@link ServicoDownload}.
 *
 * <p>Expõe o {@link Manifest} escrito na staging (com os certificados gravados, as
 * falhas registradas e as fontes HOM esperadas) e um atalho para a contagem de
 * certificados gravados, de modo que o chamador (o {@code ComandoBaixar}) saiba
 * quantos certificados foram gravados e quais fontes falharam sem reprocessar o
 * manifest.</p>
 */
public record ResultadoDownloadStaging(Manifest manifest) {

    public ResultadoDownloadStaging {
        Objects.requireNonNull(manifest, "manifest");
    }

    /** Quantidade de certificados gravados na staging. */
    public int certificadosGravados() {
        return manifest.certificados() == null ? 0 : manifest.certificados().size();
    }

    /** Quantidade de fontes que falharam de forma definitiva. */
    public int numeroFalhas() {
        return manifest.falhas() == null ? 0 : manifest.falhas().size();
    }
}
