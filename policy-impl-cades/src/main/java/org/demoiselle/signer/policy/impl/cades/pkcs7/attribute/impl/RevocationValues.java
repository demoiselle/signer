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
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.CertificateList;
import org.demoiselle.signer.core.extension.ICPBR_CRL;
import org.demoiselle.signer.core.repository.CRLRepository;
import org.demoiselle.signer.core.repository.CRLRepositoryFactory;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.UnsignedAttribute;

/**
 *
 *  Revocation Values Attribute Definition
 *
 *  The Revocation Values attribute is an unsigned attribute.
 *   Only a single instance of this attribute must occur with an electronic signature.
 *   It holds the values of CRLs and OCSP referenced in the CompleteRevocationRefs attribute.
 *
 *   The following object identifier identifies the Revocation Values attribute:
 *
 *   id-aa-ets-revocationValues OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *   				us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 24}
 *
 *   The revocation values attribute value has the ASN.1 syntax RevocationValues.
 *
 *   RevocationValues ::=  SEQUENCE {
 *    crlVals           [0] SEQUENCE OF CertificateList     OPTIONAL,
 *    ocspVals          [1] SEQUENCE OF BasicOCSPResponse   OPTIONAL,
 *    otherRevVals      [2] OtherRevVals
 *  }
 *
 *     OtherRevVals ::= SEQUENCE {
 *     otherRevValType       OtherRevValType,
 *     otherRevVals          ANY DEFINED BY otherRevValType
 *   }
 *
 *   OtherRevValType ::= OBJECT IDENTIFIER
 *
 *  The syntax and semantics of the other revocation values is outside the scope of this document.
 *  The definition of the syntax of the other form of revocation information is as identified by OtherRevRefType.
 *
 *  CertificateList is defined in RFC 2459 [RFC2459] and in ITU-T Recommendation X.509 [X509]).
 *
 *   BasicOCSPResponse is defined in RFC 2560 [OCSP].
 *
 * @author 07721825741
 */
public class RevocationValues implements UnsignedAttribute {

    //private static final Logger logger = LoggerFactory.getLogger(RevocationValues.class);
    private final ASN1ObjectIdentifier identifier =  PKCSObjectIdentifiers.id_aa_ets_revocationValues;
    private Certificate[] certificates = null;
    private static MessagesBundle cadesMessagesBundle = new MessagesBundle();
    private final CRLRepository crlRepository = CRLRepositoryFactory.factoryCRLRepository();

    @Override
    public void initialize(PrivateKey privateKey, Certificate[] certificates, byte[] content, SignaturePolicy signaturePolicy, byte[] hash) {
    	this.certificates = certificates;
    }

    @Override
    public String getOID() {
        return identifier.getId();
    }

    @Override
    public Attribute getValue() throws SignerException {
    	List<X509CRL> crlList = new ArrayList<X509CRL>();
    	ArrayList<CertificateList> crlVals = new ArrayList<CertificateList>();
    	List<BasicOCSPResponse> ocspVals = new ArrayList<BasicOCSPResponse>();
    	try {

    		int chainSize = certificates.length -1;
    		for (int ix = 0; ix < chainSize; ix++ ){
    			X509Certificate cert = (X509Certificate) certificates[ix];
    			Collection<ICPBR_CRL> icpCrls = crlRepository.getX509CRL(cert);
    			for (ICPBR_CRL icpCrl : icpCrls) {
    				crlList.add(icpCrl.getCRL());
    			}
    		}
    		if (crlList.isEmpty()){
    			throw new SignerException(cadesMessagesBundle.getString("error.crl.list.empty"));
    		}else{
    			for(X509CRL varCrl : crlList){
    				crlVals.add(CertificateList.getInstance(varCrl.getEncoded()));
    			}
    		}
    		CertificateList[] crlValuesArray = new CertificateList[crlVals.size()];
    		BasicOCSPResponse[] ocspValuesArray = new BasicOCSPResponse[ocspVals.size()];
    		//	OtherRevVals otherRevVals = new OtherRevVals(null);
    		//return new Attribute(new ASN1ObjectIdentifier(identifier),	new DERSet(null));
    		//org.bouncycastle.asn1.esf.RevocationValues revocationVals = new org.bouncycastle.asn1.esf.RevocationValues(crlVals.toArray(crlValuesArray), ocspVals.toArray(ocspValuesArray), null);
    		//org.bouncycastle.asn1.esf.RevocationValues revocationVals = new org.bouncycastle.asn1.esf.RevocationValues(crlVals.toArray(crlValuesArray), null, null);
    		return new Attribute(identifier,new DERSet(new DERSequence(crlVals.toArray(crlValuesArray))));
    	} catch (Exception e) {
    		throw new SignerException(e.getMessage());
		}
    }

}
