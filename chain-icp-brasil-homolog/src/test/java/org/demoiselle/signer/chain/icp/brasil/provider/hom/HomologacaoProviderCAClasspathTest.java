package org.demoiselle.signer.chain.icp.brasil.provider.hom;

import org.junit.Test;
import java.security.KeyStore;
import java.io.InputStream;

import static org.junit.Assert.*;

public class HomologacaoProviderCAClasspathTest {
    @Test
    public void testBksResourceLoading() throws Exception {
        InputStream is = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("cadeiasicpbrasil-HOMOLOGACAO.bks");
        assertNotNull("O arquivo cadeiasicpbrasil-HOMOLOGACAO.bks não foi encontrado no classpath", is);
        if (is != null) {
            try {
                java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                KeyStore ks = KeyStore.getInstance("BKS", "BC");
                ks.load(is, "serprosigner".toCharArray());
                assertTrue("O KeyStore deve conter pelo menos um alias", ks.aliases().hasMoreElements());
            } finally {
                is.close();
            }
        }
    }
}
