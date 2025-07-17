package org.demoiselle.signer.chain.icp.brasil.provider.hom;

import java.security.cert.X509Certificate;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.jupiter.api.Test;

class HomologacaoProviderCATest {
    @Test
    void testLoadBksCertificates() {
        HomologacaoProviderCA provider = new HomologacaoProviderCA();
        Collection<X509Certificate> cas = provider.getCAs();
        assertNotNull(cas, "Coleção de CAs não pode ser nula");
        assertFalse(cas.isEmpty(), "Deve carregar pelo menos um certificado do BKS");
        for (X509Certificate cert : cas) {
            assertNotNull(cert, "Certificado não pode ser nulo");
        }
    }
}
