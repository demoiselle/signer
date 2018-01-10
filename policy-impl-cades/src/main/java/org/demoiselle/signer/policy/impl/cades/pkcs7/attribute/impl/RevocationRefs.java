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
package org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.esf.CrlIdentifier;
import org.bouncycastle.asn1.esf.CrlListID;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.OcspIdentifier;
import org.bouncycastle.asn1.esf.OcspListID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.extension.ICPBR_CRL;
import org.demoiselle.signer.core.repository.CRLRepository;
import org.demoiselle.signer.core.repository.CRLRepositoryFactory;
import org.demoiselle.signer.cryptography.Digest;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.cryptography.factory.DigestFactory;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.UnsignedAttribute;
import com.itextpdf.signatures.OcspClientBouncyCastle;

/**
 * 
 * Complete Revocation Refs Attribute Definition
 * 
 * The Complete Revocation Refs attribute is an unsigned attribute. Only a
 * single instance of this attribute must occur with an electronic signature. It
 * references the full set of the CRL or OCSP responses that have been used in
 * the validation of the signer and CA certificates used in ES with Complete
 * validation data.
 * 
 * The following object identifier identifies the CompleteRevocationRefs
 * attribute:
 * 
 * id-aa-ets-revocationRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 22}
 * 
 * The complete revocation refs attribute value has the ASN.1 syntax
 * CompleteRevocationRefs.
 * 
 * CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef
 * 
 * The complete-revocation-references attribute value has the ASN.1 syntax
 * CompleteRevocationRefs:
 *
 * CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef
 *
 * CrlOcspRef ::= SEQUENCE { crlids [0] CRLListID OPTIONAL, ocspids [1]
 * OcspListID OPTIONAL, otherRev [2] OtherRevRefs OPTIONAL }
 *
 * CompleteRevocationRefs shall contain one CrlOcspRef for the
 * signing-certificate, followed by one for each OtherCertID in the
 * CompleteCertificateRefs attribute. The second and subsequent CrlOcspRef
 * fields shall be in the same order as the OtherCertID to which they relate. At
 * least one of CRLListID or OcspListID or OtherRevRefs should be present for
 * all but the "trusted" CA of the certificate path.
 *
 * CRLListID ::= SEQUENCE { crls SEQUENCE OF CrlValidatedID }
 *
 * CrlValidatedID ::= SEQUENCE { crlHash OtherHash, crlIdentifier CrlIdentifier
 * OPTIONAL }
 *
 * CrlIdentifier ::= SEQUENCE { crlissuer Name, crlIssuedTime UTCTime, crlNumber
 * INTEGER OPTIONAL }
 *
 * OcspListID ::= SEQUENCE { ocspResponses SEQUENCE OF OcspResponsesID }
 *
 * OcspResponsesID ::= SEQUENCE { ocspIdentifier OcspIdentifier, ocspRepHash
 * OtherHash OPTIONAL }
 *
 * OcspIdentifier ::= SEQUENCE { ocspResponderID ResponderID, -- As in OCSP
 * response data producedAt GeneralizedTime -- As in OCSP response data }
 * 
 *
 */
public class RevocationRefs implements UnsignedAttribute {

	private final String identifier = "1.2.840.113549.1.9.16.2.22";
	private Certificate[] certificates = null;
	private final CRLRepository crlRepository = CRLRepositoryFactory
			.factoryCRLRepository();;

	@Override
	public void initialize(PrivateKey privateKey, Certificate[] certificates,
			byte[] content, SignaturePolicy signaturePolicy, byte[] hash) {
		this.certificates = certificates;
	}

	@Override
	public String getOID() {
		return identifier;
	}

	@Override
	public Attribute getValue() throws SignerException {

		try {
			
			// TODO toda cadeia.
			int chainSize = certificates.length - 1;
			X509Certificate cert = (X509Certificate) certificates[0];
			Collection<ICPBR_CRL> icpCrls = crlRepository.getX509CRL(cert);
			BasicCertificate basicCert = new BasicCertificate(cert);
			List<String> ListaURLCRL = basicCert.getCRLDistributionPoint();

			OcspResponsesID[] ocspResponsesIDArray = new
			OcspResponsesID[chainSize];
			CrlValidatedID[] crls = new CrlValidatedID[icpCrls.size()];

			for (ICPBR_CRL icpCrl : icpCrls) {
				int i = 0;
				crls[i] = makeCrlValidatedID(icpCrl.getCRL());
				i++;
			}

			/*
			for (int i = 0; i < chainSize; i++ ){			  
				OcspClientBouncyCastle client = new OcspClientBouncyCastle(null);
			  	X509Certificate checkCert = (X509Certificate) certificates[i];
			  	X509Certificate rootCert = (X509Certificate)  certificates[chainSize]; 
			  	String crlUrl = ListaURLCRL.get(i);
			  	//BasicOCSPResp ocspResp =  client.getBasicOCSPResp(checkCert,rootCert,crlUrl);			  
			  	BasicOCSPResp ocspResp =  client.getBasicOCSPResp(checkCert,rootCert, null);
			  	ocspResponsesIDArray[i] = makeOcspResponsesID(ocspResp);			  
			} 
			  
			OcspListID ocspids = new OcspListID(ocspResponsesIDArray);
			*/
			CrlListID crlids = new CrlListID(crls);
			//CrlOcspRef crlOcspRef = new CrlOcspRef(crlids, ocspids, null);
			CrlOcspRef crlOcspRef = new CrlOcspRef(crlids, null, null);
			return new Attribute(
					new ASN1ObjectIdentifier(identifier),
					new DERSet(
							new ASN1Encodable[] { new DERSequence(crlOcspRef) }));
			// CrlOcspRef[] crlOcspRefArray = new
			// CrlOcspRef[completeRevocationRefs.size()];

		} catch (NoSuchAlgorithmException | CRLException e) {
			throw new SignerException(e.getMessage());
		} catch (IOException e) {
			throw new SignerException(e.getMessage());
		}
		
	}

	/**
	 * 
	 * 
	 * @param extract
	 *            CrlValidatedID from X509CRL
	 * @return a CrlValidatedID
	 * @throws NoSuchAlgorithmException
	 * @throws CRLException
	 */

	private CrlValidatedID makeCrlValidatedID(X509CRL crl)
			throws NoSuchAlgorithmException, CRLException {

		Digest digest = DigestFactory.getInstance().factoryDefault();
		digest.setAlgorithm(DigestAlgorithmEnum.SHA_256);

		OtherHash hash = new OtherHash(digest.digest(crl.getEncoded()));

		BigInteger crlnumber;
		CrlIdentifier crlid;
		if (crl.getExtensionValue("2.5.29.20") != null) {
			// crlnumber = new
			// DERInteger(crl.getExtensionValue("2.5.29.20")).getPositiveValue();
			crlnumber = new ASN1Integer(crl.getExtensionValue("2.5.29.20"))
					.getPositiveValue();

			crlid = new CrlIdentifier(new X500Name(crl.getIssuerX500Principal()
					.getName()), new DERUTCTime(crl.getThisUpdate()), crlnumber);
		} else {
			crlid = new CrlIdentifier(new X500Name(crl.getIssuerX500Principal()
					.getName()), new DERUTCTime(crl.getThisUpdate()));
		}

		CrlValidatedID crlvid = new CrlValidatedID(hash, crlid);

		return crlvid;
	}

	/**
	 * make OcspResponsesID from BasicOCSPResp
	 * 
	 * @param ocspResp
	 * @return OcspResponsesID
	 * @throws NoSuchAlgorithmException
	 * @throws OCSPException
	 * @throws IOException
	 */
	private OcspResponsesID makeOcspResponsesID(BasicOCSPResp ocspResp)
			throws NoSuchAlgorithmException, OCSPException, IOException {

		Digest digest = DigestFactory.getInstance().factoryDefault();
		digest.setAlgorithm(DigestAlgorithmEnum.SHA_256);

		byte[] digestValue = digest.digest(ocspResp.getEncoded());
		OtherHash hash = new OtherHash(digestValue);

		OcspResponsesID ocsprespid = new OcspResponsesID(new OcspIdentifier(
				ocspResp.getResponderId().toASN1Object(),
				new DERGeneralizedTime(ocspResp.getProducedAt())), hash);

		return ocsprespid;
	}

}
