package org.demoiselle.signer.core.extension;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.demoiselle.signer.core.CertificateManager;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.extension.CertificateExtra;
import org.demoiselle.signer.core.extension.ICPBrasilExtension;
import org.demoiselle.signer.core.extension.ICPBrasilExtensionType;
import org.junit.Assert;
import org.junit.Test;

public class Resolution211CertificateDataTest {

    public static final String CERT_FICTICIO =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIID8DCCAtigAwIBAgIESZYC0jANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJC\n" +
        "UjETMBEGA1UECgwKSUNQLUJyYXNpbDEUMBIGA1UEBRMLMTIzNDU2Nzg5MDkxIjAg\n" +
        "BgNVBAMMGUpPU0UgREEgU0lMVkE6MTIzNDU2Nzg5MDkwHhcNMjYwODA2MTUwMDMx\n" +
        "WhcNMjcwODA3MTUwMDMxWjBcMQswCQYDVQQGEwJCUjETMBEGA1UECgwKSUNQLUJy\n" +
        "YXNpbDEUMBIGA1UEBRMLMTIzNDU2Nzg5MDkxIjAgBgNVBAMMGUpPU0UgREEgU0lM\n" +
        "VkE6MTIzNDU2Nzg5MDkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCX\n" +
        "WPGNqqKW2xydFP7IAMorhz0SpbyiBqV/7XbNrtJr29gQkKHE88gFUO4SNMf2w6FH\n" +
        "mHcDruVpxAhVH9alknNd0/0p8qTWzzUF/uW9hW09xouJa5gBq8YnNLU1VnMM/mJ7\n" +
        "UhdCRAt+HN55q3S2D81NnhQBu/KP34DKcT1XVYdU9+PWBuaBrpf3m1po9Gbro8iu\n" +
        "bCRDOCvoKxMvPzPyE8iC1CoyHWIaFPrz6LAbsKkZYkj5qqBZGnd4H3WRsf6V4iBx\n" +
        "MPtznyyjtHj/hagu7y2nFNsh58IvNek31JU+PkYFRVcwMEwccX9Gu3gQfooRE6Dq\n" +
        "bvHUg42ZUDypfKeCycshAgMBAAGjgbkwgbYwDAYDVR0TAQH/BAIwADASBgNVHSAE\n" +
        "CzAJMAcGBWBMAQIDMEkGA1UdEQRCMECgPgYFYEwBAwGgNQQzMDEwMjE5ODAxMjM0\n" +
        "NTY3ODkwOTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwU1NQMFNQMEcGA1UdHwRA\n" +
        "MD4wPKA6oDiGNmh0dHA6Ly9yZXBvc2l0b3Jpby5zZXJwcm8uZ292LmJyL2xjci9h\n" +
        "Y3NlcnByb2FjZnY2LmNybDANBgkqhkiG9w0BAQsFAAOCAQEAPrtIFKL/bjVOBOkD\n" +
        "W0zQnctSDnZ8sFcn/WiTwF1YhvZePJDqBWJm8F0PYj6U6CSzHT96rtcmZqJ8C0OF\n" +
        "f8NiuGhIxTfQ2USB0WWDdINxbUwNQ7AO43RdEqzCJOuQF7XLlnRFGXhmedEQrZsP\n" +
        "9SYbMQew7VjHKd6nBlDlfCc4VVKxIrcC4oyrEDRyB2hOZIR0vvQXHgNLbJdT00t1\n" +
        "LdaOTE7ufrMrXjHBLOgZGkleVsLkZRvl83tuGhKR1+86vNEo+mY19LmuJR5sr+kK\n" +
        "bzD6aT2H6q2X4CpNLE6ze+cxZlpvTfePZQopcFkhYL5PNY0NKbh3R/8jI4f8GGSM\n" +
        "l3z5Yw==\n" +
        "-----END CERTIFICATE-----\n";

    @Test
    public void testCertificateData() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509Certificate x509Certificate = fromPem(CERT_FICTICIO);

        Assert.assertNotNull("Certificado não deve ser nulo", x509Certificate);
        
        System.out.println("Certificado carregado.\nSubject do X509: " + x509Certificate.getSubjectX500Principal().getName() + "\n");

        exemploUsoAnotacoes(x509Certificate);
        exemploUsoBasicExtra(x509Certificate);
        exemploUsoCertificateExtra(x509Certificate);
    }

    private void exemploUsoCertificateExtra(X509Certificate x509Certificate) {
        System.out.println("\n----- Início de Exemplo de uso do CertificateExtra -----");
        CertificateExtra certificateExtra = new CertificateExtra(x509Certificate);
        Assert.assertNotNull(certificateExtra.getOID_2_16_76_1_3_1().getCPF());
        
        System.out.println("CPF: " + certificateExtra.getOID_2_16_76_1_3_1().getCPF());
        System.out.println("CNPJ: " + (certificateExtra.getOID_2_16_76_1_3_3() != null ? certificateExtra.getOID_2_16_76_1_3_3().getCNPJ() : "null"));
        System.out.println("Nome: Certificate Extra não posssui acesso." );
        System.out.println("SE: Certificate Extra não posssui acesso.");
        System.out.println("Certificate Level: Certificate Extra não posssui acesso.");
        System.out.println("Certificate Type: Certificate Extra não posssui acesso.");
        System.out.println("Is certificate PF: " + certificateExtra.isCertificatePF());
        System.out.println("Is certificate PJ: " + certificateExtra.isCertificatePJ());
        System.out.println("Is certificate EQP: " + certificateExtra.isCertificateEquipment());
        System.out.println("Is certificate SE: " + certificateExtra.isCertificateSE());
        System.out.println("----- Fim de Exemplo de uso do CertificateExtra -----");
    }

    private void exemploUsoBasicExtra(X509Certificate x509Certificate) {
        System.out.println("\n----- Início de Exemplo de uso do BasicCertificate -----");
        BasicCertificate basicCertificate = new BasicCertificate(x509Certificate);
        Assert.assertNotNull(basicCertificate.getICPBRCertificatePF().getCPF());
        
        System.out.println("CPF: " + basicCertificate.getICPBRCertificatePF().getCPF());
        System.out.println("CNPJ: " + (basicCertificate.getICPBRCertificatePJ() != null ? basicCertificate.getICPBRCertificatePJ().getCNPJ() : "null"));
        System.out.println("Nome: " + basicCertificate.getName());
        System.out.println("SE: " + basicCertificate.getICPBRCertificateSE());
        System.out.println("Certificate Level: " + basicCertificate.getCertificateLevel());
        System.out.println("Certificate Type: " + basicCertificate.getCertificateType());
        System.out.println("Is Aplicacao Específica: " + basicCertificate.isAplicacaoEspecifica());
        System.out.println("Is Ca Certificate: " + basicCertificate.isCACertificate());
        System.out.println("Is Selo Eletronico: " + basicCertificate.isSeloEletronico());
        System.out.println("----- Fim de Exemplo de uso do BasicCertificate -----");
    }

    private void exemploUsoAnotacoes(X509Certificate x509Certificate) {
        System.out.println("\n----- Início de Exemplo de uso de Anotações -----");
        CertificateManager certManager = new CertificateManager(x509Certificate);
        CertificadoVO certificadoVO = certManager.load(CertificadoVO.class);
        Assert.assertNotNull(certificadoVO.getCpf());
        
        System.out.println("CPF: " + certificadoVO.getCpf());
        System.out.println("CNPJ: " + certificadoVO.getCnpj());
        System.out.println("Nome: " + certificadoVO.getNome());
        System.out.println("SE: " + certificadoVO.getSe());
        System.out.println("Level: " + certificadoVO.getLevel());
        System.out.println("Type: " + certificadoVO.getType());
        System.out.println("----- Fim de Exemplo de uso de Anotações -----");
    }

    private X509Certificate fromPem(String pemCertificate) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            byte[] certificateBytes = pemCertificate.getBytes(StandardCharsets.US_ASCII);
            ByteArrayInputStream inputStream = new ByteArrayInputStream(certificateBytes);
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        } catch (CertificateException ex) {
            throw new IllegalArgumentException("Nao foi possivel converter o PEM em X509Certificate", ex);
        }
    }

    public static class CertificadoVO {
        @ICPBrasilExtension(type=ICPBrasilExtensionType.CPF)
        private String cpf;
        @ICPBrasilExtension(type=ICPBrasilExtensionType.CNPJ)
        private String cnpj;
        @ICPBrasilExtension(type=ICPBrasilExtensionType.NAME)
        private String nome;
        @ICPBrasilExtension(type=ICPBrasilExtensionType.SE)
        private String se;
        @ICPBrasilExtension(type=ICPBrasilExtensionType.CERTIFICATE_LEVEL)
        private String level;
        @ICPBrasilExtension(type=ICPBrasilExtensionType.CERTIFICATE_TYPE)
        private String type;

        public String getCpf() {
            return cpf;
        }

        public String getCnpj() {
            return cnpj;
        }

        public String getNome() {
            return nome;
        }

        public String getSe() {
            return se;
        }

        public String getLevel() {
            return level;
        }

        public String getType() {
            return type;
        }
    }
}
