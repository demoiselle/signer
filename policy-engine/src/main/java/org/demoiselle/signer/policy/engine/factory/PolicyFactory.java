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
package org.demoiselle.signer.policy.engine.factory;

import java.io.IOException;
import java.io.InputStream;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.engine.asn1.icpb.LPA;

/**
 * 
 *  Factory for the digital signature policies defined by ICP-BRASIL
 *  
 *  http://www.iti.gov.br/icp-brasil/repositorio/144-icp-brasil/repositorio/3974-artefatos-de-assinatura-digital
 *
 */
public class PolicyFactory {


    public static final PolicyFactory instance = new PolicyFactory();
    
    private final static Logger LOGGER = Logger.getLogger(PolicyFactory.class.getName());

    public static PolicyFactory getInstance() {
        return PolicyFactory.instance;
    }


    // TODO - Carregar politica em formato XML
    public SignaturePolicy loadPolicy(Policies policy) {
        SignaturePolicy signaturePolicy = new SignaturePolicy();
        InputStream is = this.getClass().getResourceAsStream(policy.getFile());
        ASN1Primitive primitive = this.readANS1FromStream(is);
        signaturePolicy.parse(primitive);
        signaturePolicy.setSignPolicyURI(policy.getUrl());
        return signaturePolicy;
    }

    
    /**
     * @deprecated  Politics DISCONTINUED
     */

    @Deprecated
    public LPA loadLPA() {
        org.demoiselle.signer.policy.engine.asn1.icpb.LPA listaPoliticaAssinatura = new org.demoiselle.signer.policy.engine.asn1.icpb.LPA();
        InputStream is = this.getClass().getResourceAsStream(ListOfSubscriptionPolicies.LPAV1.getFile());
        ASN1Primitive primitive = this.readANS1FromStream(is);
        listaPoliticaAssinatura.parse(primitive);
        return listaPoliticaAssinatura;
    }

    
    /**
     * @deprecated   Politics DISCONTINUED 28/11/2016
     */

    @Deprecated    
    public org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA loadLPAv2() {
        org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA listaPoliticaAssinatura = new org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA();
        InputStream is = this.getClass().getResourceAsStream(ListOfSubscriptionPolicies.LPAV2.getFile());
        ASN1Primitive primitive = this.readANS1FromStream(is);
        listaPoliticaAssinatura.parse(primitive);
        return listaPoliticaAssinatura;    
    }
    
    /**
     * Load signature policy for CAdES standard (PKCS)
     * @return org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA
     */
    
    public org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA loadLPACAdES() {
        org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA listaPoliticaAssinatura = new org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA();
        InputStream is = this.getClass().getResourceAsStream(ListOfSubscriptionPolicies.CAdES.getFile());
        ASN1Primitive primitive = this.readANS1FromStream(is);
        listaPoliticaAssinatura.parse(primitive);
        return listaPoliticaAssinatura;    
    }
    
    /**
     *  Load signature policy for PAdES standard (PDF)
     * @return org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA
     */
    public org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA loadLPAPAdES() {
        org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA listaPoliticaAssinatura = new org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA();
        InputStream is = this.getClass().getResourceAsStream(ListOfSubscriptionPolicies.PAdES.getFile());
        ASN1Primitive primitive = this.readANS1FromStream(is);
        listaPoliticaAssinatura.parse(primitive);
        return listaPoliticaAssinatura;    
    }
    
    /**
     *  Load signature policy for XAdES (XML) standard
     * @return
     */
    		
    // TODO - Implementar
    public org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA loadLPAXAdES() {
        return new org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA();    
    }
    
    
    private ASN1Primitive readANS1FromStream(InputStream is) {
        ASN1InputStream asn1is = new ASN1InputStream(is);
        ASN1Primitive primitive = null;
        try {
            primitive = asn1is.readObject();
        } catch (IOException error) {
        	LOGGER.getLevel();
			LOGGER.log(Level.ERROR, "Error reading stream.", error);
            throw new RuntimeException(error);
        } finally {
            try {
                asn1is.close();
            } catch (IOException error) {
                throw new RuntimeException(error);
            }
        }
        return primitive;
    }

    /**
     * 
     * Policies available on the ITI website. 
     * http://www.iti.gov.br/icp-brasil/certificados/190-repositorio/artefatos-de-assinatura-digital
     *
     */
    public enum Policies {

        
        AD_RB_CADES_1_0("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RB.der", 
        		"http://politicas.icpbrasil.gov.br/PA_AD_RB.der"),
        AD_RB_CADES_1_1("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RB_v1_1.der", 
        		"http://politicas.icpbrasil.gov.br/PA_AD_RB_v1_1.der"),
        AD_RB_CADES_2_0("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RB_v2_0.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_0.der"),
        AD_RB_CADES_2_1("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RB_v2_1.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_1.der"),
        AD_RB_CADES_2_2("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RB_v2_2.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_2.der"),
        AD_RT_CADES_1_0("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RT.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RT.der"),
        AD_RT_CADES_1_1("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RT_v1_1.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RT_v1_1.der"),
        AD_RT_CADES_2_0("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RT_v2_0.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_0.der"),
        AD_RT_CADES_2_1("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RT_v2_1.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_1.der"),
        AD_RT_CADES_2_2("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RT_v2_2.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_2.der"),      
        AD_RV_CADES_1_0("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RV.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RV.der"),
        AD_RV_CADES_1_1("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RV_v1_1.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RV_v1_1.der"),
        AD_RV_CADES_2_0("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RV_v2_0.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RV_v2_0.der"),
        AD_RV_CADES_2_1("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RV_v2_1.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RV_v2_1.der"),
        AD_RV_CADES_2_2("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RV_v2_2.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RV_v2_2.der"),
        AD_RC_CADES_1_0("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RC.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RC.der"),
        AD_RC_CADES_1_1("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RC_v1_1.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RC_v1_1.der"),
        AD_RC_CADES_2_0("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RC_v2_0.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RC_v2_0.der"),
        AD_RC_CADES_2_1("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RC_v2_1.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RC_v2_1.der"),
        AD_RC_CADES_2_2("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RC_v2_2.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RC_v2_2.der"),
        AD_RA_CADES_1_0("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RA.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RA.der"),
        AD_RA_CADES_1_1("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RA_v1_1.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RA_v1_1.der"),
        AD_RA_CADES_1_2("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RA_v1_2.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RA_v1_2.der"),
        AD_RA_CADES_2_0("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RA_v2_0.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RA_v2_0.der"),
        AD_RA_CADES_2_1("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RA_v2_1.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RA_v2_1.der"),
        AD_RA_CADES_2_2("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RA_v2_2.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RA_v2_2.der"),
        AD_RA_CADES_2_3("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RA_v2_3.der",
        		"http://politicas.icpbrasil.gov.br/PA_AD_RA_v2_3.der"),
        		

// TODO - Carregar politica em formato XML, necessário???   		
        AD_RB_XADES_2_2("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RB_v2_3.xml",
                		"http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_3.xml"),        		
        AD_RT_XADES_2_3("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RT_v2_3.xml",
                		"http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_3.xml"),
   		AD_RV_XADES_2_3("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RV_v2_3.xml",
                   		"http://politicas.icpbrasil.gov.br/PA_AD_RV_v2_3.xml"),
        AD_RC_XADES_2_3("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RC_v2_3.xml",
                        "http://politicas.icpbrasil.gov.br/PA_AD_RC_v2_3.xml"),   		
        AD_RA_XADES_2_3("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RA_v2_3.xml",
                   		"http://politicas.icpbrasil.gov.br/PA_AD_RA_v2_3.xml"),           		
                        		
                        		
        		
        AD_RB_PADES_1_0("/org/demoiselle/signer/policy/engine/artifacts/PA_PAdES_AD_RB_v1_0.der",
                		"http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_0.der"),        		
        AD_RT_PADES_1_0("/org/demoiselle/signer/policy/engine/artifacts/PA_PAdES_AD_RT_v1_0.der",
                		"http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RT_v1_0.der"),
   		AD_RC_PADES_2_3("/org/demoiselle/signer/policy/engine/artifacts/PA_PAdES_AD_RC_v1_1.der",
                        "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RC_v1_1.der"),
        AD_RA_PADES_1_1("/org/demoiselle/signer/policy/engine/artifacts/PA_PAdES_AD_RA_v1_1.der",
                		"http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RA_v1_1.der");
        
                
        private Policies(String file, String url) {
        	this.file = file;
            this.url = url;
        }

        private String file;
        
        public String getFile() {
            return file;
        }
        
        private String url;
        
        public String getUrl() {
        	return url;
        }
    }
    

    /**
     * 
     * List of policies:
     *  http://www.iti.gov.br/icp-brasil/certificados/190-repositorio/artefatos-de-assinatura-digital
     *
     */
    public enum ListOfSubscriptionPolicies {

        LPAV1("/org/demoiselle/signer/policy/engine/artifacts/LPA.der"),
        LPAV2("/org/demoiselle/signer/policy/engine/artifacts/LPAv2.der"),
        CAdES("/org/demoiselle/signer/policy/engine/artifacts/LPA_CAdES.der"),
        XADES("/org/demoiselle/signer/policy/engine/artifacts/LPA_XAdES.xml"),
        PAdES("/org/demoiselle/signer/policy/engine/artifacts/LPA_PAdES.der");

        // TODO  verificar se eh possivel utilizar FILE e URL
        
        //http://politicas.icpbrasil.gov.br/LPA.der
        //http://politicas.icpbrasil.gov.br/LPAv2.der
        //http://politicas.icpbrasil.gov.br/LPA_CAdES.der
        //http://politicas.icpbrasil.gov.br/LPA_XAdES.xml
        //http://politicas.icpbrasil.gov.br/LPA_PAdES.der
        
        //private String url;
        private String file;

        
        private ListOfSubscriptionPolicies(String file) {
            this.file = file;
        }
        
//        private ListOfSubscriptionPolicies(String file, String url) {
//        	this.file = file;
//            this.url = url;
//        }

//        public String getUrl() {
//            return url;
//        }

        public String getFile() {
            return file;
        }        
    }
}
