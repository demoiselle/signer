package org.demoiselle.signer.importador.dominio;

import java.math.BigInteger;
import java.time.Instant;

/** Certificado normalizado extraido de um X509Certificate. Usado por todo o nucleo puro. */
public record Certificado(
        String subject,        // cert.getSubjectX500Principal().getName()
        BigInteger serial,     // cert.getSerialNumber()
        String cn,             // CN extraido do subject (grafia original)
        String cnNorm,         // cn.trim().toUpperCase(Locale.ROOT) - chave case-insensitive
        Instant notBefore,     // cert.getNotBefore() (criterio de desempate; nunca filtro)
        Instant notAfter,      // cert.getNotAfter() (apenas relatorio; nunca filtro)
        boolean selfSigned,
        Origem origem,
        String fonteId,        // identificador da fonte de download (ex.: nome do .p7b)
        String arquivo         // caminho do DER na staging
) {
    /** Identidade para duplicata exata e diff. */
    public String identidade() { return serial + "|" + subject; }
}
