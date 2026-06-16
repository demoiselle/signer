package org.demoiselle.signer.core.keystore.loader;

import org.demoiselle.signer.core.extension.BasicCertificate;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class PfxIntegrationTest {

    @Test
    public void testReadNewProfileSESPfx() throws Exception {
        // Caminho relativo a partir da pasta 'core' para o arquivo PFX de teste
        File pfxFile = new File("../../assinador-serpro/serpro-signer/certificados/hom/ativo/7139_Y1-Selo-eletronico-pin-123456.pfx");
        
        if (!pfxFile.exists()) {
            System.out.println("Aviso: Arquivo PFX de teste não encontrado. Ignorando teste.");
            System.out.println("Caminho procurado: " + pfxFile.getAbsolutePath());
            return;
        }

        System.out.println("Lendo certificado PFX: " + pfxFile.getAbsolutePath());

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(pfxFile)) {
            ks.load(fis, "123456".toCharArray());
        }

        Enumeration<String> aliases = ks.aliases();
        Assert.assertTrue("KeyStore vazia", aliases.hasMoreElements());

        String alias = aliases.nextElement();
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        
        BasicCertificate bc = new BasicCertificate(cert);
        
        System.out.println("Subject DN: " + cert.getSubjectDN().getName());
        System.out.println("Certificate Level: " + bc.getCertificateLevel());
        System.out.println("Certificate Type: " + bc.getCertificateType());
        
        // Validações da Resolução 211
        Assert.assertTrue("Deve ser identificado como Selo Eletrônico (SE)", bc.hasCertificateSE());
        Assert.assertFalse("Selo Eletrônico não deve ser confundido com PF antigo", bc.hasCertificatePF());
        
        Assert.assertEquals("Nível deve ser SE-S", "SE-S", bc.getCertificateLevel());
        Assert.assertEquals("Tipo deve ser SE", "SE", bc.getCertificateType());
        
        // Verifica se o CNPJ foi extraído corretamente (provavelmente via serialNumber do DN)
        String cnpjEsperado = "Y1V5MYJT000195"; // Valor visto no output do openssl
        String cnpjExtraido = bc.getICPBRCertificateSE().getCNPJ();
        
        System.out.println("CNPJ Extraído: " + cnpjExtraido);
        Assert.assertEquals("CNPJ extraído incorretamente", cnpjEsperado, cnpjExtraido);
        
        System.out.println("Teste com PFX do novo perfil concluído com sucesso!");
    }
}
