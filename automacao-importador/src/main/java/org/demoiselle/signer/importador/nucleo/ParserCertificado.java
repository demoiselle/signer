package org.demoiselle.signer.importador.nucleo;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Locale;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.demoiselle.signer.importador.dominio.Certificado;
import org.demoiselle.signer.importador.dominio.Origem;

/**
 * Parsing puro de X.509: converte um {@link X509Certificate} ja carregado no
 * record de dominio {@link Certificado}.
 *
 * <p>A funcao e pura sobre o certificado ja carregado: nao le arquivos nem
 * acessa a rede. A extracao dos bytes fica na camada de IO. Nenhum filtro por
 * validade e aplicado (apenas extrai as datas notBefore/notAfter).</p>
 */
public final class ParserCertificado {

    private ParserCertificado() {
    }

    /**
     * Converte um {@link X509Certificate} em {@link Certificado}, associando a
     * origem, o identificador da fonte e o caminho do arquivo (conhecidos pela
     * camada de IO que chama o parser).
     *
     * @param cert    certificado X.509 ja carregado (nao nulo)
     * @param origem  origem do certificado (PRO/HOM); pode ser nulo
     * @param fonteId identificador da fonte de download; pode ser nulo
     * @param arquivo caminho do DER na staging; pode ser nulo
     * @return o {@link Certificado} normalizado
     */
    public static Certificado paraCertificado(X509Certificate cert, Origem origem, String fonteId, String arquivo) {
        String subject = cert.getSubjectX500Principal().getName();
        String issuer = cert.getIssuerX500Principal().getName();
        BigInteger serial = cert.getSerialNumber();
        String cn = extrairCn(subject);
        String cnNorm = cn.trim().toUpperCase(Locale.ROOT);
        Instant notBefore = cert.getNotBefore().toInstant();
        Instant notAfter = cert.getNotAfter().toInstant();
        boolean selfSigned = cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());

        return new Certificado(subject, serial, cn, cnNorm, notBefore, notAfter, selfSigned, origem, fonteId, arquivo);
    }

    /**
     * Sobrecarga sem origem/fonte/arquivo, util quando esses metadados nao sao
     * conhecidos (por exemplo, ao ler um keystore existente). Usa {@code null}
     * para origem, fonteId e arquivo.
     *
     * @param cert certificado X.509 ja carregado (nao nulo)
     * @return o {@link Certificado} normalizado
     */
    public static Certificado paraCertificado(X509Certificate cert) {
        return paraCertificado(cert, null, null, null);
    }

    /**
     * Extrai o CN do subject via {@link LdapName} (RFC 2253), procurando o RDN
     * de tipo "CN" (case-insensitive no tipo). Se nao houver CN ou o subject nao
     * puder ser interpretado, retorna string vazia.
     */
    private static String extrairCn(String subject) {
        if (subject == null || subject.isEmpty()) {
            return "";
        }
        try {
            LdapName ldapName = new LdapName(subject);
            for (Rdn rdn : ldapName.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    Object valor = rdn.getValue();
                    return valor == null ? "" : valor.toString();
                }
            }
            return "";
        } catch (InvalidNameException e) {
            return "";
        }
    }
}
