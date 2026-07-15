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

    public static final String CERT_V6 = 
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIGpTCCBI2gAwIBAgIMHymo/VF2vgDXXhxYMA0GCSqGSIb3DQEBCwUAMIGVMQsw\n" +
        "CQYDVQQGEwJCUjETMBEGA1UECgwKSUNQLUJyYXNpbDE7MDkGA1UECwwyU2Vydmlj\n" +
        "byBGZWRlcmFsIGRlIFByb2Nlc3NhbWVudG8gZGUgRGFkb3MgLSBTRVJQUk8xNDAy\n" +
        "BgNVBAMMK0F1dG9yaWRhZGUgQ2VydGlmaWNhZG9yYSBkbyBTRVJQUk8gRmluYWwg\n" +
        "djYwHhcNMjYwNjE2MTc0NjQ3WhcNMjkwNjE1MTc0NjQ3WjBvMQswCQYDVQQGEwJC\n" +
        "UjETMBEGA1UECgwKSUNQLUJyYXNpbDEUMBIGA1UEBRMLNzA0NjM2NDYxMzQxNTAz\n" +
        "BgNVBAMMLENBUkxPUyBBVUdVU1RPIEJFUk5BUkRFUyBBWkVWRURPOjcwNDYzNjQ2\n" +
        "MTM0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxCgOceR4VC9P9P9Q\n" +
        "dsPlmwpzgF2uQJFl7KgSRbNzD1TlB9VuacFD7lWEgV8rF8MO4r0P7N6Q12lSby+J\n" +
        "/n2b1VL56l7yzLjplA2g8+qTwaYLUgvX0wrcpym23L9h22E1GJzcgnhwCkhmSM9j\n" +
        "r92CS8Ow2GxolrFCrBUc5xb14T/qR95Bh9XC5UgYwufT46ogyh9pCZ2F6JtCuL+m\n" +
        "aa2CKXvygKPX+kFUIcXGKJPBu6UtaiZEM0mtug+LjC7C+gy6ENQgTotwL+YpimQa\n" +
        "N2MFXRMeslk8cdGTdsCBxlPSoLifV37KvSzK1IDAC0UWtRoS7CPE402A3rf8cTtN\n" +
        "ScQypQIDAQABo4ICGDCCAhQwHwYDVR0jBBgwFoAU6OO83K8EOdIf+CNSOmXKpldo\n" +
        "OsUwHQYDVR0OBBYEFMTjTtxKPo8ja4BE524l1NN6fpPdMA4GA1UdDwEB/wQEAwIF\n" +
        "4DBZBgNVHSAEUjBQME4GBmBMAQIDDTBEMEIGCCsGAQUFBwIBFjZodHRwOi8vcmVw\n" +
        "b3NpdG9yaW8uc2VycHJvLmdvdi5ici9kb2NzL2RwY3NlcnByb2FjZi5wZGYwVwYD\n" +
        "VR0RBFAwTqA4BgVgTAEDAaAvBC0wMTAyMTk4MDcwNDYzNjQ2MTM0MDAwMDAwMDAw\n" +
        "MDAwMDAwMDAwMDAwMDAwMDCBEmNhemV2ZWRvQG1wZi5tcC5icjAMBgNVHRMBAf8E\n" +
        "AjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDCBiAYDVR0fBIGAMH4w\n" +
        "PKA6oDiGNmh0dHA6Ly9yZXBvc2l0b3Jpby5zZXJwcm8uZ292LmJyL2xjci9hY3Nl\n" +
        "cnByb2FjZnY2LmNybDA+oDygOoY4aHR0cDovL2NlcnRpZmljYWRvczIuc2VycHJv\n" +
        "Lmdvdi5ici9sY3IvYWNzZXJwcm9hY2Z2Ni5jcmwwVgYIKwYBBQUHAQEESjBIMEYG\n" +
        "CCsGAQUFBzAChjpodHRwOi8vcmVwb3NpdG9yaW8uc2VycHJvLmdvdi5ici9jYWRl\n" +
        "aWFzL2Fjc2VycHJvYWNmdjYucDdiMA0GCSqGSIb3DQEBCwUAA4ICAQCUsZ/MjmzB\n" +
        "NSx6cKPq16mHTVSkwzjJvo5hrcDwtM82Qdr3RF2mq04hJMVf4kqgLvW/eWDYpqKh\n" +
        "rdI4jyYaQueVCXd20QUIb9z9Vzo679WS3l8J9Lm1s+cOcYwAB3F+bqqbDJ27G7Sd\n" +
        "yucnBHH5gspeSN+7HTZ56FxiAO9vIpyKxay8p0h6eMUcAGMgC2FCCbUviekZVl50\n" +
        "VoQbw4Nf77q+y8cK+S81MrytwzzE7WF5ia1PTSBJm/4PkyfoQ6cAP+OaKh5KvQwS\n" +
        "NJ7TPfwZIh2o41M14VFhaYFdhbroKcVrREd+Hqe232xFey/aTlPukrQqa5mTTxY1\n" +
        "pkaVBPxbS0enTn9SmXBYJs5B6alM13thRKLZYFiFJ1aQGD6s9MoU1ndvRLXU7Jgk\n" +
        "w3YR80xGUsvBPTZsdyNEGsW83v8+vzcQDc9cPppG9OSf4Sxzg8viRZgyQV6l+4x0\n" +
        "u/xv57yGXrGnZX3hrjBr0eeKpbJcpWxJVQahwpcwe6pt/vnKVlyYTFLTQVKyCvCf\n" +
        "BgJoE/FhMeT38QCpH9kKgDZ9rR3kUg5WIsLMqNvfcruZn9FMYSU2uQer6DIF55iW\n" +
        "resYRq2Lzoo2jh9NjG4OUo2oZqqJ0rVQXzZbA9gBp3VWUHMK4rJ67HLj+vgmJ7iB\n" +
        "Ncnn2UcdUuhYJirLeZCb9eJ/ocoppfufug==\n" +
        "-----END CERTIFICATE-----\n";

    @Test
    public void testCertificateData() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509Certificate x509Certificate = fromPem(CERT_V6);

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
