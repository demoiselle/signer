package org.demoiselle.signer.importador.dominio;

import java.time.Instant;
import java.util.List;

/** Manifest da Staging, serializado como manifest.json (Jackson). */
public record Manifest(
        Instant geradoEm,
        List<Certificado> certificados,
        List<FalhaDownload> falhas,
        List<String> homEsperadas   // fontes HOM esperadas, para calcular faltantes (Req 3.5)
) {}
