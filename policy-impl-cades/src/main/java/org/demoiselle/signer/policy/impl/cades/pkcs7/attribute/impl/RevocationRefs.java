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

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.esf.CrlIdentifier;
import org.bouncycastle.asn1.esf.CrlListID;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.OcspIdentifier;
import org.bouncycastle.asn1.esf.OcspListID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.OtherRevRefs;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.cryptography.Digest;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.cryptography.factory.DigestFactory;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.UnsignedAttribute;
import org.demoiselle.signer.policy.impl.cades.util.AlgorithmNames;

/**
 * 
 * Complete Revocation Refs Attribute Definition
 * 
 * The Complete Revocation Refs attribute is an unsigned attribute.
 * Only a single instance of this attribute must occur with an electronic signature. 
 * It references the full set of the CRL or OCSP
 * responses that have been used in the validation of the signer and CA
 * certificates used in ES with Complete validation data.
 * 
 * The following object identifier identifies the CompleteRevocationRefs  attribute:
 * 
 *  id-aa-ets-revocationRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *      		us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 22}
 *      
 *  The complete revocation refs attribute value has the ASN.1 syntax CompleteRevocationRefs.
 *  
 *  CompleteRevocationRefs ::=  SEQUENCE OF CrlOcspRef
 * 
 *  The complete-revocation-references attribute value has the ASN.1
 *  syntax CompleteRevocationRefs:
 *
 *  CompleteRevocationRefs ::=  SEQUENCE OF CrlOcspRef
 *
 *  CrlOcspRef ::= SEQUENCE {
 *     crlids      [0]   CRLListID    OPTIONAL,
 *     ocspids     [1]   OcspListID   OPTIONAL,
 *     otherRev    [2]   OtherRevRefs OPTIONAL
 *  }
 *
 *  CompleteRevocationRefs shall contain one CrlOcspRef for the
 *  signing-certificate, followed by one for each OtherCertID in the
 *  CompleteCertificateRefs attribute.  The second and subsequent
 *  CrlOcspRef fields shall be in the same order as the OtherCertID to
 *  which they relate.  At least one of CRLListID or OcspListID or
 *  OtherRevRefs should be present for all but the "trusted" CA of the
 *  certificate path.
 *
 *	CRLListID ::=  SEQUENCE {
 *   	crls        SEQUENCE OF CrlValidatedID }
 *
 *	CrlValidatedID ::=  SEQUENCE {
 *    	crlHash                   OtherHash,
 *    	crlIdentifier             CrlIdentifier OPTIONAL }
 *
 *	CrlIdentifier ::= SEQUENCE {
 *   	crlissuer                 Name,
 *   	crlIssuedTime             UTCTime,
 *   	crlNumber                 INTEGER OPTIONAL }
 *
 *	OcspListID ::=  SEQUENCE {
 *   	ocspResponses        SEQUENCE OF OcspResponsesID }
 *
 *	OcspResponsesID ::=  SEQUENCE {
 *   	ocspIdentifier              OcspIdentifier,
 *   	ocspRepHash                 OtherHash    OPTIONAL
 *	}
 *
 *	OcspIdentifier ::= SEQUENCE {
 *  		ocspResponderID    ResponderID,
 *     	-- As in OCSP response data
 *  		producedAt         GeneralizedTime
 *  	-- As in OCSP response data
 *	}
 * 
 *
 */
public class RevocationRefs implements UnsignedAttribute {

    private final String identifier = PKCSObjectIdentifiers.id_aa_ets_revocationRefs.getId();
    private static MessagesBundle cadesMessagesBundle = new MessagesBundle();
    private SignaturePolicy signaturePolicy = null;
    private Certificate[] certificates = null;

    @Override
    public void initialize(PrivateKey privateKey, Certificate[] certificates, byte[] content, SignaturePolicy signaturePolicy, byte[] hash) {
    	this.certificates = certificates;
    	this.signaturePolicy = signaturePolicy;
    }

    @Override
    public String getOID() {
        return identifier;
    }

    @Override
    public Attribute getValue() throws SignerException {
    	
    	ArrayList<CrlOcspRef> completeRevocationRefs = new ArrayList<CrlOcspRef>();
    	CrlOcspRef[] crlOcspRefArray = new CrlOcspRef[certificates.length];
    	
    	for (int i = 0; i < certificates.length; i++ ){
		  	X509Certificate issuerCert = null;
	  	    X509Certificate cert = (X509Certificate) certificates[i];
	  	    if (i+1 < certificates.length){  
	  	    	issuerCert = (X509Certificate) certificates[i+1];
	  	    }else{ // raiz
	  	    	issuerCert = (X509Certificate) certificates[i];
	  	    }
    		Digest digest = DigestFactory.getInstance().factoryDefault();
    		digest.setAlgorithm(DigestAlgorithmEnum.SHA_256);
			byte[] certHash;
			try {
				certHash = digest.digest(cert.getEncoded());
				OtherHashAlgAndValue otherHash = new OtherHashAlgAndValue(new AlgorithmIdentifier(
		        		new ASN1ObjectIdentifier(AlgorithmNames.getOIDByAlgorithmName(DigestAlgorithmEnum.SHA_256.getAlgorithm()))),null);
				OtherHash crlHash = new OtherHash(otherHash);
				X500Name dirName = new X500Name(issuerCert.getSubjectX500Principal().getName());
				GeneralName name = new GeneralName(dirName);
				GeneralNames issuer = new GeneralNames(name);
				ASN1Integer serialNumber = new ASN1Integer(cert.getSerialNumber());
				IssuerSerial issuerSerial = new IssuerSerial(issuer, serialNumber);
				AlgorithmIdentifier algId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
				OtherCertID otherCertID = new OtherCertID(algId, certHash, issuerSerial);
				
				//CrlOcspRef crlOcspRef = new CrlOcspRef(crlids, ocspids, otherRev);
				CrlOcspRef crlOcspRef = new CrlOcspRef(null, null, null);
				crlOcspRefArray[i] = crlOcspRef;
			} catch (CertificateEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			 
 
	 }
    	//CrlOcspRef[] crlOcspRefArray = new CrlOcspRef[completeRevocationRefs.size()];
    	
    	
    	
    	    	
    	/* 
    	CrlIdentifier crlIdentifier = new CrlIdentifier(null, null, null);
    	//CrlValidatedID[] crls = new CrlValidatedID[crlListIdValues.size()];
    	
    	CrlValidatedID[] crls = new CrlValidatedID(crlHash, crlIdentifier);  
    	CrlListID crlids = new CrlListID(crls);
    	OcspIdentifier ocspIdentifier = new OcspIdentifier(null, null);
    	//OcspResponsesID[] ocspResponses = new OcspResponsesID[ocspListIDValues.size()];
    	OcspResponsesID[] ocspResponses = new OcspResponsesID(ocspIdentifier, crlHash);
    	OcspListID ocspids =  new OcspListID(ocspResponses);
    	ASN1ObjectIdentifier otherRevRefType = new ASN1ObjectIdentifier(identifier);
    	ASN1Encodable otherRevRefs = null;
        OtherRevRefs otherRev = new OtherRevRefs(otherRevRefType, otherRevRefs);
        CrlOcspRef crlOcspRef = new CrlOcspRef(crlids, ocspids, otherRev);
        
        
        //new Attribute(PKCSObjectIdentifiers.id_aa_ets_revocationRefs, new DERSet(new DERSequence(completeRevocationRefs.toArray(crlOcspRefArray)))));
     	*/
    	
    	
        return new Attribute(new ASN1ObjectIdentifier(identifier), new DERSet(new DERSequence(
				new ASN1Encodable[] { new DERSequence(crlOcspRefArray) })));
				
				
      
        
    }

}
