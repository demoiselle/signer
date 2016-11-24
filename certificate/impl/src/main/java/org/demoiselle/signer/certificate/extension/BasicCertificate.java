/*
 * Demoiselle Framework
 * Copyright (C) 2016 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 *
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 *
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 *
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 *
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */
package org.demoiselle.signer.certificate.extension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BasicCertificate {

    private static final Logger logger = LoggerFactory.getLogger(BasicCertificate.class);

    public static final String OID_A1_CERTIFICATE = "2.16.76.1.2.1";
    public static final String OID_A2_CERTIFICATE = "2.16.76.1.2.2";
    public static final String OID_A3_CERTIFICATE = "2.16.76.1.2.3";
    public static final String OID_A4_CERTIFICATE = "2.16.76.1.2.4";
    public static final String OID_S1_CERTIFICATE = "2.16.76.1.2.101";
    public static final String OID_S2_CERTIFICATE = "2.16.76.1.2.102";
    public static final String OID_S3_CERTIFICATE = "2.16.76.1.2.103";
    public static final String OID_S4_CERTIFICATE = "2.16.76.1.2.104";

    private X509Certificate certificate = null;
    private ICPBRSubjectAlternativeNames subjectAlternativeNames = null;
    private ICPBRKeyUsage keyUsage = null;
    private ICPBR_DN certificateFrom = null;
    private ICPBR_DN certificateFor = null;

    /**
     *
     * @param certificate type X509Certificate
     * @see java.security.cert.X509Certificate
     */
    public BasicCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     *
     * @param data Os bytes do certificado a ser utilizado
     * @throws Exception Retorna a exceção Exception
     */
    public BasicCertificate(byte[] data) throws Exception {
        this.certificate = getCertificate(data);
    }

    /**
     *
     * @param is O stream do certificado a ser utilizado
     * @throws IOException Retorna a exceção IOException
     * @throws Exception Retorna a exceção Exception
     */
    public BasicCertificate(InputStream is) throws IOException, Exception {
        this.certificate = getCertificate(is);
    }

    /**
     *
     * @param is -> InputStream
     * @return X509Certificate
     * @throws CertificateException
     * @throws IOException
     * @throws Exception
     */
    private X509Certificate getCertificate(InputStream is) throws CertificateException, IOException, Exception {
        X509Certificate cert = null;

        CertificateFactory cf = CertificateFactory.getInstance("X509");
        cert = (X509Certificate) cf.generateCertificate(is);

        return cert;
    }

    /**
     *
     * @param data byte array
     * @return String
     */
    private String toString(byte[] data) {
        if (data == null) {
            return null;
        }
        return toString(new BigInteger(1, data));
    }

    /**
     *
     * @param bi Big Integer
     * @return String
     */
    private String toString(BigInteger bi) {
        if (bi == null) {
            return null;
        }

        String ret = bi.toString(16);

        if (ret.length() % 2 == 1) {
            ret = "0" + ret;
        }

        return ret.toUpperCase();
    }

    /**
     *
     * @param data -> Byte Array
     * @return X509Certificate
     * @throws Exception
     */
    private X509Certificate getCertificate(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        X509Certificate cert = getCertificate(bis);
        bis.close();
        bis = null;
        return cert;
    }

    /**
     * Return the certificate on original format X509Certificate<br>
     *
     * @return X509Certificate
     */
    public X509Certificate getX509Certificate() {
        return certificate;
    }

    /**
     * Obtem o IssuerDN de um certificado
     *
     * @return O IssuerDN do certificado
     *
     * @throws IOException Retorna a exceção IOException
     */
    public ICPBR_DN getCertificateIssuerDN() throws IOException {
        if (certificateFrom == null) {
            certificateFrom = new ICPBR_DN(certificate.getIssuerDN().getName());
        }
        return certificateFrom;
    }

    /**
     * Returns the SerialNumber of certificate on String format<br>
     *
     * @return String
     */
    public String getSerialNumber() {
        return toString(certificate.getSerialNumber());
    }

    /**
     * Retorna o SubjectDN de um Certificado
     *
     * @return O SubjectDN
     * @throws IOException Retorna a exceção IOException
     */
    public ICPBR_DN getCertificateSubjectDN() throws IOException {
        if (certificateFor == null) {
            certificateFor = new ICPBR_DN(certificate.getSubjectDN().getName());
        }
        return certificateFor;
    }

    /**
     * Returns the name that was defined on CN for CertificateSubjectDN.<br>
     * Its similar to CertificateSubjectDN.getProperty("CN"), but ignoring<br>
     * the information after ":".<br>
     *
     * @return String
     */
    public String getNome() {
        try {
            String nome = this.getCertificateSubjectDN().getProperty("CN");
            int pos;

            pos = nome.indexOf(':');
            if (pos > 0) {
                return nome.substring(0, pos);
            }
            return nome;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Retorna a data inicial de validade do certificado
     *
     * @return Date A a data inicial
     */
    public Date getBeforeDate() {
        return certificate.getNotBefore();
    }

    /**
     * Retorna a data final de validade do certificado
     *
     * @return Date A data final
     */
    public Date getAfterDate() {
        return certificate.getNotAfter();
    }

    /**
     * Returns the ICPBRKeyUsage Object with the informations about uses of the
     * certificate<br>
     *
     * @return ICPBRKeyUsage
     * @see ICPBRKeyUsage
     */
    public ICPBRKeyUsage getICPBRKeyUsage() {
        if (keyUsage == null) {
            keyUsage = new ICPBRKeyUsage(certificate);
        }
        return keyUsage;
    }

    /**
     * Returns the SubjectAlternativeNames of certificate in<br>
     * ICPBRSubjectAlternativeNames format.<br>
     * If not exists, returns <b>null</b>.<br>
     *
     * @return ICPBRSubjectAlternativeNames
     * @see ICPBRSubjectAlternativeNames
     */
    public ICPBRSubjectAlternativeNames getICPBRSubjectAlternativeNames() {
        if (this.subjectAlternativeNames == null) {
            this.subjectAlternativeNames = new ICPBRSubjectAlternativeNames(this.certificate);
        }
        return this.subjectAlternativeNames;
    }

    /**
     * Returns the email address that was defined on
     * SubjectAlternativeNames.<br>
     * Similar getICPBRSubjectAlternativeNames().getEmail()<br>
     * If not exists, returns <b>null</b>.<br>
     *
     * @return String
     */
    public String getEmail() {
        if (getICPBRSubjectAlternativeNames() == null) {
            return null;
        }
        return getICPBRSubjectAlternativeNames().getEmail();
    }

    /**
     * Check if the certificate has a "ICP-BRASIL Pessoa Fisica Certificate".
     * DOC-ICP-04<br>
     *
     * @return boolean
     */
    public boolean hasCertificatePF() {
        if (getICPBRSubjectAlternativeNames() == null) {
            return false;
        }
        return getICPBRSubjectAlternativeNames().isCertificatePF();
    }

    /**
     * Returns data of "Pessoa Fisica" on certificate in ICPBRCertificatePF
     * format<br>
     * If its not a "Pessoa Fisica" certificate <br>
     * Returns o valor <b>null</b>
     *
     * @return ICPBRCertificatePF
     * @see ICPBRCertificatePF
     */
    public ICPBRCertificatePF getICPBRCertificatePF() {
        if (getICPBRSubjectAlternativeNames() == null) {
            return null;
        }
        return getICPBRSubjectAlternativeNames().getICPBRCertificatePF();
    }

    /**
     * * Check if the certificate has a "ICP-BRASIL Pessoa Juridica
     * Certificate". DOC-ICP-04<br>
     *
     * @return boolean
     */
    public boolean hasCertificatePJ() {
        if (getICPBRSubjectAlternativeNames() == null) {
            return false;
        }
        return getICPBRSubjectAlternativeNames().isCertificatePJ();
    }

    /**
     * Returns data of "Pessoa Juridica" on certificate in ICPBRCertificatePJ
     * format<br>
     * If its not a "Pessoa Juridica" certificate <br>
     * Returns o valor <b>null</b>
     *
     *
     * @return ICPBRCertificatePJ
     * @see ICPBRCertificatePJ
     */
    public ICPBRCertificatePJ getICPBRCertificatePJ() {
        if (getICPBRSubjectAlternativeNames() == null) {
            return null;
        }
        return getICPBRSubjectAlternativeNames().getICPBRCertificatePJ();
    }

    /**
     * Check if the certificate has a "ICP-BRASIL Equipment (Equipamento ou
     * Aplicação) Certificate". DOC-ICP-04<br>
     *
     * @return boolean
     */
    public boolean hasCertificateEquipment() {
        if (getICPBRSubjectAlternativeNames() == null) {
            return false;
        }
        return getICPBRSubjectAlternativeNames().isCertificateEquipment();
    }

    /**
     * Returns data of "Equipamento/Aplicacao" on certificate in
     * ICPBRCertificateEquipment format<br>
     * If its not a "Equipamento/Aplicacao" certificate <br>
     * Returns o valor <b>null</b>
     *
     *
     * @return ICPBRCertificateEquipment
     * @see ICPBRCertificateEquipment
     */
    public ICPBRCertificateEquipment getICPBRCertificateEquipment() {
        if (getICPBRSubjectAlternativeNames() == null) {
            return null;
        }
        return getICPBRSubjectAlternativeNames().getICPBRCertificateEquipment();
    }

    /**
     * Returns the PathLength value of Certificate BasicConstraint.<br>
     * * <b>0</b> - if CA.<br>
     * * <b>1</b> - for End User Certificate.<br>
     *
     * @return int
     */
    public int getPathLength() {
        return certificate.getBasicConstraints();
    }

    /**
     * Check if is a Certificate Authority Certificate (ICP-BRASIL = AC).<br>
     * * <b>true</b> - If CA.<br>
     * * <b>false</b> -for End User Certificate.<br>
     *
     * @return boolean
     */
    public boolean isCertificadoAc() {
        return certificate.getBasicConstraints() >= 0;
    }

    /**
     * returns the ICP-BRASIL Level Certificate(A1, A2, A3, A4, S1, S2, S3,
     * S4).<br>
     * DOC-ICP-04 Returns the <b>null</b> value if the CertificatePolicies is
     * NOT present.
     *
     * @return String
     */
    public String getNivelCertificado() {
        try {
            DLSequence sequence = (DLSequence) getExtensionValue(Extension.certificatePolicies.getId());
            if (sequence != null) {
                for (int pos = 0; pos < sequence.size(); pos++) {
                    DLSequence sequence2 = (DLSequence) sequence.getObjectAt(pos);
                    ASN1ObjectIdentifier policyIdentifier = (ASN1ObjectIdentifier) sequence2.getObjectAt(0);
                    PolicyInformation policyInformation = new PolicyInformation(policyIdentifier);
                    String id = policyInformation.getPolicyIdentifier().getId();
                    if (id == null) {
                        continue;
                    }

                    if (id.startsWith(OID_A1_CERTIFICATE)) {
                        return "A1";
                    }
                    if (id.startsWith(OID_A2_CERTIFICATE)) {
                        return "A2";
                    }
                    if (id.startsWith(OID_A3_CERTIFICATE)) {
                        return "A3";
                    }
                    if (id.startsWith(OID_A4_CERTIFICATE)) {
                        return "A4";
                    }
                    if (id.startsWith(OID_S1_CERTIFICATE)) {
                        return "S1";
                    }
                    if (id.startsWith(OID_S2_CERTIFICATE)) {
                        return "S2";
                    }
                    if (id.startsWith(OID_S3_CERTIFICATE)) {
                        return "S3";
                    }
                    if (id.startsWith(OID_S4_CERTIFICATE)) {
                        return "S4";
                    }
                }
            }
            return null;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Obtém o Identificador de chave de autoridade de um certificado
     *
     * @return O Identificador de chave de autoridade
     * @throws IOException Retorna a exceção IOException
     */
    public String getAuthorityKeyIdentifier() throws IOException {
        // TODO - Precisa validar este metodo com a RFC
        DLSequence sequence = (DLSequence) getExtensionValue(Extension.authorityKeyIdentifier.getId());
        if (sequence == null || sequence.size() == 0) {
            return null;
        }
        DERTaggedObject taggedObject = (DERTaggedObject) sequence.getObjectAt(0);
        DEROctetString oct = (DEROctetString) taggedObject.getObject();
        return toString(oct.getOctets());
    }

    /**
     * Retorna o Identificador de chave de assunto de um certificado
     *
     * @return O Identificador de chave de assunto
     * @throws IOException Retorna a exceção
     */
    public String getSubjectKeyIdentifier() throws IOException {
        // TODO - Precisa validar este metodo com a RFC
        DEROctetString oct = (DEROctetString) getExtensionValue(Extension.subjectKeyIdentifier.getId());
        if (oct == null) {
            return null;
        }

        return toString(oct.getOctets());
    }

    /**
     * Retorna uma lista de ulrs que informam a localização das listas de
     * certificados revogados
     *
     * @return Lista de urls das CRLs
     * @throws IOException Retorna a exceção IOException
     */
    public List<String> getCRLDistributionPoint() throws IOException {

        List<String> crlUrls = new ArrayList<>();
        ASN1Primitive primitive = getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (primitive == null) {
            return null;
        }
        CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(primitive);
        DistributionPoint[] distributionPoints = crlDistPoint.getDistributionPoints();

        logger.info("Analizando os pontos de distribuição");
        for (DistributionPoint distributionPoint : distributionPoints) {
            DistributionPointName dpn = distributionPoint.getDistributionPoint();
            // Look for URIs in fullName
            if (dpn != null) {
                if (dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                    for (GeneralName genName : genNames) {
                        if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String url = DERIA5String.getInstance(genName.getName()).getString();
                            crlUrls.add(url);
                            logger.info("Adicionando a url {}", url);
                        }
                    }
                }
            }
        }
        return crlUrls;
    }

    /**
     * Obtém o conteúdo de um determinado OID
     *
     * @param oid A identificação do campo
     *
     * @return O conteúdo relacionado ao OID informado
     */
    public ASN1Primitive getExtensionValue(String oid) {
        byte[] extensionValue = certificate.getExtensionValue(oid);
        if (extensionValue == null) {
            return null;
        }
        try {
            DEROctetString oct = (DEROctetString) (new ASN1InputStream(extensionValue).readObject());
            return (new ASN1InputStream(oct.getOctets()).readObject());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(0);
        try {
            SimpleDateFormat dtValidade = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

            sb.append("*********************************\n");
            sb.append("Certificado DE  : ").append(this.getCertificateIssuerDN()).append("\n");
            sb.append("Serial Number . : ").append(this.getSerialNumber()).append("\n");
            sb.append("Certificado PARA: ").append(this.getCertificateSubjectDN()).append("\n");
            sb.append("Nome do Certif  : ").append(this.getNome()).append("\n");
            sb.append("Validade  . . . : de ").append(dtValidade.format(this.getBeforeDate())).append(" ate ").append(dtValidade.format(this.getAfterDate())).append("\n");
            sb.append("*********************************\n");
            sb.append("Email . . . . . : ").append(this.getEmail()).append("\n");
            sb.append("*********************************\n");
            sb.append("Tem dados PF  . : ").append(this.hasCertificatePF()).append("\n");
            if (this.hasCertificatePF()) {
                ICPBRCertificatePF tdPF = this.getICPBRCertificatePF();
                sb.append("CPF . . . . . . . : ").append(tdPF.getCPF()).append("\n");
                sb.append("Data Nascimento . : ").append(tdPF.getDataNascimento()).append("\n");
                sb.append("PIS . . . . . . . : ").append(tdPF.getNis()).append("\n");
                sb.append("Rg  . . . . . . . : ").append(tdPF.getRg()).append("\n");
                sb.append("Orgão Rg  . . . . : ").append(tdPF.getOrgaoExpedidorRg()).append("\n");
                sb.append("UF Rg  . . . . .  : ").append(tdPF.getUfExpedidorRg()).append("\n");
                sb.append("CEI  . . . . . .  : ").append(tdPF.getCEI()).append("\n");
                sb.append("Titulo  . . . . . : ").append(tdPF.getTituloEleitor()).append("\n");
                sb.append("Seção . . . . . . : ").append(tdPF.getSecaoTituloEleitor()).append("\n");
                sb.append("Zona  . . . . . . : ").append(tdPF.getZonaTituloEleitor()).append("\n");
                sb.append("Municipio Titulo. : ").append(tdPF.getMunicipioTituloEleitor()).append("\n");
                sb.append("UF Titulo . . . . : ").append(tdPF.getUfTituloEleitor()).append("\n");
            }

            sb.append("*********************************\n");
            sb.append("Tem dados PJ  . : ").append(this.hasCertificatePJ()).append("\n");
            if (this.hasCertificatePJ()) {
                ICPBRCertificatePJ tdPJ = this.getICPBRCertificatePJ();
                sb.append("CNPJ. . . . . . : ").append(tdPJ.getCNPJ()).append("\n");
                sb.append("CEI. . . . . . : ").append(tdPJ.getCEI()).append("\n");
                sb.append("NIS . . . . . . : ").append(tdPJ.getNis()).append("\n");
                sb.append("Responsável . . : ").append(tdPJ.getNomeResponsavel()).append("\n");
            }

            sb.append("*********************************\n");
            sb.append("Tem dados Equip : ").append(this.hasCertificateEquipment()).append("\n");
            if (this.hasCertificateEquipment()) {
                ICPBRCertificateEquipment tdEq = this.getICPBRCertificateEquipment();
                sb.append("CNPJ. . . . . . : ").append(tdEq.getCNPJ()).append("\n");
                sb.append("NIS . . . . . . : ").append(tdEq.getNis()).append("\n");
                sb.append("Nome Empresa. . : ").append(tdEq.getNomeEmpresarial()).append("\n");
                sb.append("Responsável . . : ").append(tdEq.getNomeResponsavel()).append("\n");
            }

            sb.append("*********************************\n");
            sb.append("Eh CertificadoAC: ").append(this.isCertificadoAc()).append("\n");
            sb.append("PathLength  . . : ").append(this.getPathLength()).append("\n");
            sb.append("Tipo Certificado: ").append(this.getNivelCertificado()).append("\n");
            sb.append("Tipo de Uso . . : ").append(this.getICPBRKeyUsage()).append("\n");

            sb.append("*********************************\n");
            sb.append("Authority KeyID : ").append(this.getAuthorityKeyIdentifier()).append("\n");
            sb.append("Subject KeyID . : ").append(this.getSubjectKeyIdentifier()).append("\n");
            sb.append("CRL DistPoint . : ").append(this.getCRLDistributionPoint()).append("\n");
        } catch (IOException e) {
            e.printStackTrace();
        }

        return sb.toString();
    }

}
