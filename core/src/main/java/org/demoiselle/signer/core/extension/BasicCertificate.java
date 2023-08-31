/*
 * Demoiselle Framework
 * Copyright (C) 2021 SERPRO
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

package org.demoiselle.signer.core.extension;

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
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Basic Certificate information based on ICP-BRASIL (PKI) definitions.
 *
 * @see CertificateExtra
 */
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

	private static final MessagesBundle coreMessagesBundle = new MessagesBundle();

	private X509Certificate certificate = null;
	private ICPBRSubjectAlternativeNames subjectAlternativeNames = null;
	private ICPBRKeyUsage keyUsage = null;
	private ICPBR_DN certificateFrom = null;
	private ICPBR_DN certificateFor = null;

	private ASN1InputStream varASN1InputStream;

	/**
	 * @param certificate type X509Certificate
	 * @see java.security.cert.X509Certificate
	 */
	public BasicCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}

	/**
	 * @param data The bytes of the certificate to be used
	 * @throws Exception exception
	 */
	public BasicCertificate(byte[] data) throws Exception {
		this.certificate = getCertificate(data);
	}

	/**
	 * @param is The input stream of the certificate to be used
	 * @throws IOException exception
	 * @throws Exception   exception
	 */
	public BasicCertificate(InputStream is) throws IOException, Exception {
		this.certificate = getCertificate(is);
	}

	/**
	 * @param is The input stream of the certificate to be used
	 * @return X509Certificate X509 certificate
	 * @throws CertificateException exception
	 * @throws Exception            exception
	 */
	private X509Certificate getCertificate(InputStream is) throws CertificateException, Exception {
		CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
		
		return (X509Certificate) cf.generateCertificate(is);
	}

	/**
	 * @param data byte array
	 * @return String string representation
	 */
	private String toString(byte[] data) {
		if (data == null) {
			return null;
		}
		return toString(new BigInteger(1, data));
	}

	/**
	 * @param bi Big Integer
	 * @return String string representation
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
	 * @param data -> Byte Array
	 * @return X509Certificate X509 certificate
	 * @throws Exception exception
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
	 * @return X509Certificate X509 certificate
	 */
	public X509Certificate getX509Certificate() {
		return certificate;
	}

	/**
	 * Gets the IssuerDN (Issuer Distinguished Name) of a certificate
	 *
	 * @return {@link ICPBR_DN} IssuerDN of a certificate
	 * @throws IOException exception
	 */
	public ICPBR_DN getCertificateIssuerDN() throws IOException {
		if (certificateFrom == null) {
			certificateFrom = new ICPBR_DN(certificate.getIssuerDN().getName());
		}
		return certificateFrom;
	}

	/**
	 * Returns the SerialNumber of certificate on String formatr
	 *
	 * @return String serial number
	 */
	public String getSerialNumber() {
		return toString(certificate.getSerialNumber());
	}

	/**
	 * Returns the SubjectDN (Subject Distinguished Name) of a Certificate
	 *
	 * @return {@link ICPBR_DN} SubjectDN of a certificate
	 * @throws IOException exception
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
	 * @return String name
	 * @deprecated spelling mistake, use getName
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
			logger.error(e.getMessage());
		}
		return null;
	}

	/**
	 * Returns the name that was defined on CN for CertificateSubjectDN.<br>
	 * Its similar to CertificateSubjectDN.getProperty("CN"), but ignoring<br>
	 * the information after ":".<br>
	 *
	 * @return String name
	 */
	public String getName() {
		try {
			String name = this.getCertificateSubjectDN().getProperty("CN");
			int pos;

			pos = name.indexOf(':');
			if (pos > 0) {
				return name.substring(0, pos);
			}
			return name;
		} catch (Exception e) {
			logger.info(e.getMessage());
			return null;
		}

	}

	/**
	 * @return Date the certificate's initial date of validity
	 */
	public Date getBeforeDate() {
		return certificate.getNotBefore();
	}

	/**
	 * @return Date The expiration date of the certificate
	 */
	public Date getAfterDate() {
		return certificate.getNotAfter();
	}

	/**
	 * Returns the ICPBRKeyUsage Object with the informations about uses of the
	 * certificate<br>
	 *
	 * @return ICPBRKeyUsage Key Usage
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
	 * @return ICPBRSubjectAlternativeNames subject alternative names
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
	 * @return String email
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
	 * @return boolean true if certificate has a "ICP-BRASIL Pessoa Física"
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
	 * Returns <b>null</b>
	 *
	 * @return ICPBRCertificatePF Certificate Pessoa Física
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
	 * @return boolean true if certificate has a "ICP-BRASIL Pessoa Jurídica"
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
	 * Returns null
	 *
	 * @return ICPBRCertificatePJ Certificate Pessoa Jurídica
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
	 * @return boolean true if certificate has equipment
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
	 * Returns <b>null</b>
	 *
	 * @return ICPBRCertificateEquipment equipment
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
	 * @return int path length
	 */
	public int getPathLength() {
		return certificate.getBasicConstraints();
	}

	/**
	 * Check if is a Certificate Authority Certificate (ICP-BRASIL = AC).<br>
	 * * <b>true</b> - If CA.<br>
	 * * <b>false</b> -for End User Certificate.<br>
	 *
	 * @return boolean true if CA certificate
	 */
	public boolean isCACertificate() {
		return certificate.getBasicConstraints() >= 0;
	}

	/**
	 * returns the ICP-BRASIL Certificate Level(A1, A2, A3, A4, S1, S2, S3,
	 * S4).<br>
	 * DOC-ICP-04 Returns the <b>null</b> value if the CertificatePolicies is
	 * NOT present.
	 *
	 * @return String Certificate level
	 */
	public String getCertificateLevel() {
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
			logger.error(e.getMessage());
			return null;
		}
	}


	/**
	 * Returns the AuthorityInfoAccess extension value on list format.<br>
	 * Otherwise, returns <b>list empty</b>.<br>
	 *
	 * @return List Authority info access list
	 */
	public List<String> getAuthorityInfoAccess() {
		List<String> address = new ArrayList<String>();
		try {
			byte[] authorityInfoAccess = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
			if (authorityInfoAccess != null && authorityInfoAccess.length > 0) {
				AuthorityInformationAccess infoAccess = AuthorityInformationAccess.getInstance(
					JcaX509ExtensionUtils.parseExtensionValue(authorityInfoAccess));
				for (AccessDescription desc : infoAccess.getAccessDescriptions())
					if (desc.getAccessLocation().getTagNo() == GeneralName.uniformResourceIdentifier)
						address.add(((DERIA5String) desc.getAccessLocation().getName()).getString());
			}
			return address;
		} catch (Exception error) {
			logger.error(error.getMessage());
			return address;
		}
	}


	/**
	 * *
	 *
	 * @return the authority key identifier of a certificate
	 */
	public String getAuthorityKeyIdentifier() {
		// TODO - Precisa validar este metodo com a RFC
		try {
			DLSequence sequence = (DLSequence) getExtensionValue(Extension.authorityKeyIdentifier.getId());
			if (sequence == null || sequence.size() == 0) {
				return null;
			}
			DERTaggedObject taggedObject = (DERTaggedObject) sequence.getObjectAt(0);
			DEROctetString oct = (DEROctetString) taggedObject.getObject();
			return toString(oct.getOctets());
		} catch (Exception error) {
			logger.error(error.getMessage());
			return null;
		}

	}

	/**
	 * @return The subject key identifier of a certificate
	 * @throws IOException exception
	 */
	public String getSubjectKeyIdentifier() throws IOException {
		// TODO - Precisa validar este metodo com a RFC
		try {
			DEROctetString oct = (DEROctetString) getExtensionValue(Extension.subjectKeyIdentifier.getId());
			if (oct == null) {
				return null;
			}

			return toString(oct.getOctets());
		} catch (Exception error) {
			logger.error(error.getMessage());
			return null;
		}

	}

	/**
	 * @return A list of ulrs that inform the location of the certificate revocation lists
	 * @throws IOException exception
	 */
	public List<String> getCRLDistributionPoint() throws IOException {

		List<String> crlUrls = new ArrayList<>();
		ASN1Primitive primitive = getExtensionValue(Extension.cRLDistributionPoints.getId());
		if (primitive == null) {
			return null;
		}
		CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(primitive);
		DistributionPoint[] distributionPoints = crlDistPoint.getDistributionPoints();

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
							logger.debug("Adicionando a url {}", url);
						}
					}
				}
			}
		}
		return crlUrls;
	}

	/**
	 * Gets the contents of a given OID
	 *
	 * @param oid Object Identifier (OID)
	 * @return org.bouncycastle.asn1.ASN1Primitive Content related to the reported OID
	 */
	public ASN1Primitive getExtensionValue(String oid) {
		try {
			byte[] extensionValue = certificate.getExtensionValue(oid);
			if (extensionValue == null) {
				return null;
			}
			varASN1InputStream = new ASN1InputStream(extensionValue);
			DEROctetString oct = (DEROctetString) varASN1InputStream.readObject();
			varASN1InputStream = new ASN1InputStream(oct.getOctets());
			return varASN1InputStream.readObject();
		} catch (Exception e) {
			logger.error(e.getMessage());
			return null;
		}
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(0);
		try {
			SimpleDateFormat dtValidade = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

			sb.append("*********************************\n");
			sb.append(coreMessagesBundle.getString("text.certicate.IssuerDN")).append(this.getCertificateIssuerDN()).append("\n");

			sb.append(coreMessagesBundle.getString("text.certicate.serialNumber")).append(this.getSerialNumber()).append("\n");
			sb.append(coreMessagesBundle.getString("text.certicate.subjectDN")).append(this.getCertificateSubjectDN()).append("\n");
			sb.append(coreMessagesBundle.getString("text.certicate.name")).append(this.getName()).append("\n");
			sb.append(coreMessagesBundle.getString("text.certicate.valid.from")).append(dtValidade.format(this.getBeforeDate())).append("ate").append(dtValidade.format(this.getAfterDate())).append("\n");
			sb.append("*********************************\n");
			//       sb.append("*********************************\n");
			if (this.hasCertificatePF()) {
				ICPBRCertificatePF tdPF = this.getICPBRCertificatePF();
				sb.append(coreMessagesBundle.getString("text.certicate.email")).append(this.getEmail()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.cpf")).append(tdPF.getCPF()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.birth.date")).append(tdPF.getBirthDate()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.pis")).append(tdPF.getNis()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.rg")).append(tdPF.getRg()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.rg.issuing.agency")).append(tdPF.getIssuingAgencyRg()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.rg.uf")).append(tdPF.getUfIssuingAgencyRg()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.cei")).append(tdPF.getCEI()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.voter.document")).append(tdPF.getElectoralDocument()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.section")).append(tdPF.getSectionElectoralDocument()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.zone")).append(tdPF.getZoneElectoralDocument()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.voter.city")).append(tdPF.getCityElectoralDocument()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.voter.uf")).append(tdPF.getUFElectoralDocument()).append("\n");
			}

			sb.append("*********************************\n");
			sb.append(coreMessagesBundle.getString("text.certicate.is.pj")).append(this.hasCertificatePJ()).append("\n");
			if (this.hasCertificatePJ()) {
				ICPBRCertificatePJ tdPJ = this.getICPBRCertificatePJ();
				sb.append(coreMessagesBundle.getString("text.certicate.cnpj")).append(tdPJ.getCNPJ()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.cei")).append(tdPJ.getCEI()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.nis")).append(tdPJ.getNis()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.responsible")).append(tdPJ.getResponsibleName()).append("\n");
			}

			sb.append("*********************************\n");
			sb.append(coreMessagesBundle.getString("text.certicate.is.equipment")).append(this.hasCertificateEquipment()).append("\n");
			if (this.hasCertificateEquipment()) {
				ICPBRCertificateEquipment tdEq = this.getICPBRCertificateEquipment();
				sb.append(coreMessagesBundle.getString("text.certicate.cnpj")).append(tdEq.getCNPJ()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.nis")).append(tdEq.getNis()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.bussiness.name")).append(tdEq.getCorporateName()).append("\n");
				sb.append(coreMessagesBundle.getString("text.certicate.responsible")).append(tdEq.getResponsibleName()).append("\n");
			}

			sb.append("*********************************\n");
			sb.append(coreMessagesBundle.getString("text.certicate.is.ca")).append(this.isCACertificate()).append("\n");
			sb.append(coreMessagesBundle.getString("text.certicate.pahtLenth")).append(this.getPathLength()).append("\n");
			sb.append(coreMessagesBundle.getString("text.certicate.type")).append(this.getCertificateLevel()).append("\n");
			sb.append(coreMessagesBundle.getString("text.certicate.type.use")).append(this.getICPBRKeyUsage()).append("\n");

			sb.append("*********************************\n");
			sb.append(coreMessagesBundle.getString("text.certicate.authority.key")).append(this.getAuthorityKeyIdentifier()).append("\n");
			sb.append(coreMessagesBundle.getString("text.certicate.Authority.info.acess")).append(this.getAuthorityInfoAccess()).append("\n");
			sb.append(coreMessagesBundle.getString("text.certicate.subject.key")).append(this.getSubjectKeyIdentifier()).append("\n");
			sb.append(coreMessagesBundle.getString("text.certicate.crl.url")).append(this.getCRLDistributionPoint()).append("\n");
		} catch (IOException e) {
			logger.error(e.getMessage());
		}
		return sb.toString();
	}
}
