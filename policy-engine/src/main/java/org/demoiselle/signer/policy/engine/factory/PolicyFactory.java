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
package org.demoiselle.signer.policy.engine.factory;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.demoiselle.signer.core.repository.Configuration;
import org.demoiselle.signer.core.util.Downloads;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.engine.asn1.icpb.LPA;
import org.demoiselle.signer.policy.engine.repository.LPARepository;
import org.demoiselle.signer.policy.engine.repository.PolicyEngineConfig;
import org.demoiselle.signer.policy.engine.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * 
 *  Factory for the digital signature policies defined by ICP-BRASIL
 *  
 *  http://iti.gov.br/repositorio/84-repositorio/133-artefatos-de-assinatura-digital
 *
 */
public class PolicyFactory {

    public static final PolicyFactory instance = new PolicyFactory();
  
    private static final Logger LOGGER = LoggerFactory.getLogger(PolicyFactory.class);
    private static MessagesBundle policyMessagesBundle = new MessagesBundle("messages_policy");

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
    
    public Document loadXMLPolicy(Policies policy) throws ParserConfigurationException, SAXException, IOException {
    	
        InputStream is = this.getClass().getResourceAsStream(policy.getFile());
        
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder dBuilder;
		
		dBuilder = dbFactory.newDocumentBuilder();
		Document doc = dBuilder.parse(is);
        
        
        return doc;
    }

    
    /**
	 * @return LPA ICP Brasil signature policy v1
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
	 * @return LPA ICP Brasil signature policy v2
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
     * @return org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA ICP Brasil signature policy v2
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
     * @return org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA ICP Brasil signature policy v2
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
     * @return ICP Brasil signature policy v2
     */
    		
    // TODO - Implementar
    public org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA loadLPAXAdES() {
        return new org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA();    
    }
    
    
    /**
     * Load signature policy for CAdES standard (PKCS) from local repository
     * @return org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA
     */
    
    public org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA loadLPACAdESLocal() {
        org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA listaPoliticaAssinatura = new org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA();
        InputStream is;
		try {
			Configuration config = Configuration.getInstance();
			Path pathLPA = Paths.get(config.getLpaPath(), "LPA_CAdES.der");
			LOGGER.debug(policyMessagesBundle.getString("info.lpa.load.local", pathLPA));
			is = new FileInputStream(pathLPA.toString());
			ASN1Primitive primitive = this.readANS1FromStream(is);
	        listaPoliticaAssinatura.parse(primitive);
	        return listaPoliticaAssinatura;
		} catch (FileNotFoundException e) {
			LOGGER.warn(policyMessagesBundle.getString("error.lpa.not.found", "LPA_CAdES.der"));
			listaPoliticaAssinatura = loadLPACAdESUrl();			
		}
		if (listaPoliticaAssinatura != null){
			return listaPoliticaAssinatura;
		}else{
			LOGGER.error(policyMessagesBundle.getString("error.lpa.not.found", "LPA_CAdES.der"));
			throw new RuntimeException(policyMessagesBundle.getString("error.lpa.not.found", "LPA_CAdES.der"));
			
		}
    }
    
    /**
     *  Load signature policy for PAdES standard (PDF) from local repository
     * @return org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA
     */
    public org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA loadLPAPAdESLocal() {
        org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA listaPoliticaAssinatura = new org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA();
        InputStream is;
        try {
        	Configuration config = Configuration.getInstance();
        	Path pathLPA = Paths.get(config.getLpaPath(), "LPA_PAdES.der");
        	is = new FileInputStream(pathLPA.toString());
			ASN1Primitive primitive = this.readANS1FromStream(is);
	        listaPoliticaAssinatura.parse(primitive);
	        return listaPoliticaAssinatura;
		} catch (FileNotFoundException e) {
			LOGGER.warn(policyMessagesBundle.getString("error.lpa.not.found", "LPA_PAdES.der"));
			listaPoliticaAssinatura = loadLPAPAdESUrl();
		}
        if (listaPoliticaAssinatura != null){
			return listaPoliticaAssinatura;
		}else{
			LOGGER.error(policyMessagesBundle.getString("error.lpa.not.found", "LPA_PAdES.der"));
			throw new RuntimeException(policyMessagesBundle.getString("error.lpa.not.found", "LPA_PAdES.der"));
		}
        
        
    }
    
    /**
     *  Load signature policy for XAdES (XML) standard from local repository
     * @return
     */
    		
    // TODO - Implementar
    public org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA loadLPAXAdESLocal() {
        return new org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA();    
    }
    
      
    /**
     * Load signature policy for CAdES standard (PKCS) from url
     * @return org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA
     */
    
    public org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA loadLPACAdESUrl() {
        org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA listaPoliticaAssinatura = new org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA();
        String conURL = ListOfSubscriptionPolicies.CAdES_ITI_URL.getUrl();
        try{        	
        	InputStream is = Downloads.getInputStreamFromURL(conURL);
        	ASN1Primitive primitive = this.readANS1FromStream(is);
            listaPoliticaAssinatura.parse(primitive);      
            is.close();
            if (!LPARepository.saveLocalLPA(conURL, "LPA_CAdES.der")){
            	LOGGER.warn(policyMessagesBundle.getString("error.lpa.not.saved", "LPA_CAdES.der"));
            	throw new RuntimeException(policyMessagesBundle.getString("error.lpa.not.saved", conURL));
            }            
        }catch(RuntimeException ex){
        	LOGGER.error(ex.getMessage());
        	LOGGER.error(policyMessagesBundle.getString("error.lpa.not.saved", conURL));
        	listaPoliticaAssinatura = loadLocalLPACAdESUrl();
        	return listaPoliticaAssinatura;
        	
		} catch (IOException e) {
			LOGGER.error(e.getMessage());
			LOGGER.error(policyMessagesBundle.getString("error.lpa.not.saved", conURL));
			listaPoliticaAssinatura = loadLocalLPACAdESUrl();
			return listaPoliticaAssinatura;
		}
        
        return listaPoliticaAssinatura;
            
    }
    /**
     * 
     * Load signature policy for CAdES standard (PKCS) from local url
     * @return org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA
     */
    private org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA loadLocalLPACAdESUrl(){
    	org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA listaPoliticaAssinatura = new org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA();
    	String conURL = ListOfSubscriptionPolicies.CAdES_LOCAL_URL.getUrl();
        try{        	
        	InputStream is = Downloads.getInputStreamFromURL(conURL);
        	ASN1Primitive primitive = this.readANS1FromStream(is);
            listaPoliticaAssinatura.parse(primitive);      
            is.close();
            if (!LPARepository.saveLocalLPA(conURL, "LPA_CAdES.der")){
            	LOGGER.warn(policyMessagesBundle.getString("error.lpa.not.saved", "LPA_CAdES.der"));
            	throw new RuntimeException(policyMessagesBundle.getString("error.lpa.not.saved", conURL));
            }            
        }catch(RuntimeException ex1){
        	LOGGER.error(ex1.getMessage());
        	throw new RuntimeException(policyMessagesBundle.getString("error.lpa.not.saved", conURL));
		} catch (IOException e1) {
			LOGGER.error(e1.getMessage());
			throw new RuntimeException(policyMessagesBundle.getString("error.lpa.not.saved", conURL));
		}
    	return listaPoliticaAssinatura;
    }
    
    /**
     *  Load signature policy for PAdES standard (PDF) from url
     * @return org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA
     */
    public org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA loadLPAPAdESUrl() {
        org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA listaPoliticaAssinatura = new org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA();
        InputStream is;
        String conURL = ListOfSubscriptionPolicies.PAdES_ITI_URL.getUrl();
		try {			
			is = Downloads.getInputStreamFromURL(conURL);
			ASN1Primitive primitive = this.readANS1FromStream(is);
			is.close();
			if (!LPARepository.saveLocalLPA(conURL, "LPA_PAdES.der")){
	        	LOGGER.error(policyMessagesBundle.getString("error.lpa.not.saved", "LPA_PAdES.der"));
	        	throw new RuntimeException(policyMessagesBundle.getString("error.lpa.not.saved", conURL));
	        	}	        
	        listaPoliticaAssinatura.parse(primitive);	       
		} catch (RuntimeException e) {		
			LOGGER.error(e.getMessage());
			LOGGER.error(policyMessagesBundle.getString("error.lpa.not.saved", conURL));
			listaPoliticaAssinatura = loadLocalLPAPAdESUrl();
			return listaPoliticaAssinatura;
		} catch (IOException e) {
			LOGGER.error(e.getMessage());
			LOGGER.error(policyMessagesBundle.getString("error.lpa.not.saved", conURL));
			listaPoliticaAssinatura = loadLocalLPAPAdESUrl();
			return listaPoliticaAssinatura;
		}
		 return listaPoliticaAssinatura; 
    }
    
    /**
     *  Load signature policy for PAdES standard (PDF) from local 
     * @return org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA
     */
    private org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA loadLocalLPAPAdESUrl() {
        org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA listaPoliticaAssinatura = new org.demoiselle.signer.policy.engine.asn1.icpb.v2.LPA();
        InputStream is;
        String conURL = ListOfSubscriptionPolicies.PAdES_LOCAL_URL.getUrl();
		try {			
			is = Downloads.getInputStreamFromURL(conURL);
			ASN1Primitive primitive = this.readANS1FromStream(is);
			is.close();
			if (!LPARepository.saveLocalLPA(conURL, "LPA_PAdES.der")){
	        	LOGGER.error(policyMessagesBundle.getString("error.lpa.not.saved", "LPA_PAdES.der"));
	        	throw new RuntimeException(policyMessagesBundle.getString("error.lpa.not.saved", conURL));
	        	}	        
	        listaPoliticaAssinatura.parse(primitive);	       
		} catch (RuntimeException e) {		
			LOGGER.error(e.getMessage());
			throw new RuntimeException(policyMessagesBundle.getString("error.lpa.not.saved", conURL));
		} catch (IOException e) {
			LOGGER.error(e.getMessage());
			throw new RuntimeException(policyMessagesBundle.getString("error.lpa.not.saved", conURL));
		}
		 return listaPoliticaAssinatura; 
    }
    
   
    /**
     *  Load signature policy for XAdES (XML) standard from url
     * 
     */
    		
    // TODO - Implementar
    public void loadLPAXAdESUrl() {
        String conURL = ListOfSubscriptionPolicies.XADES_ITI_URL.getUrl();
        LOGGER.info(conURL);
            
    }
    
    /**
     *  Load signature policy for XAdES (XML) standard from local url
     */
    		
    // TODO - Implementar
    public void loadLocalLPAXAdESUrl() {
    	String conURL = ListOfSubscriptionPolicies.XADES_LOCAL_URL.getUrl();
    	LOGGER.info(conURL);
            
    }
    
    private ASN1Primitive readANS1FromStream(InputStream is) {
        ASN1InputStream asn1is = new ASN1InputStream(is);
        ASN1Primitive primitive = null;
        try {
            primitive = asn1is.readObject();
        } catch (IOException error) {
			LOGGER.error("Error reading stream.", error);
            throw new RuntimeException(error);
        } finally {
            try {
                asn1is.close();
            } catch (IOException error) {
            	LOGGER.error(error.getMessage());
                throw new RuntimeException(error);
            }
        }
        return primitive;
    }

    /**
     * 
     * Policies available on the ITI website. 
     * http://iti.gov.br/repositorio/84-repositorio/133-artefatos-de-assinatura-digital
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
        AD_RB_CADES_2_3("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RB_v2_3.der",
                		"http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_3.der"),
                		
                		
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
        AD_RT_CADES_2_3("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RT_v2_3.der",
                		"http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_3.der"),
        		
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
        AD_RV_CADES_2_3("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RV_v2_3.der",
                		"http://politicas.icpbrasil.gov.br/PA_AD_RV_v2_3.der"),
        		
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
        AD_RC_CADES_2_3("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RC_v2_3.der",
                		"http://politicas.icpbrasil.gov.br/PA_AD_RC_v2_3.der"),
        		
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
        AD_RA_CADES_2_4("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RA_v2_4.der",
                		"http://politicas.icpbrasil.gov.br/PA_AD_RA_v2_4.der"),        		
        		

// TODO - Carregar politica em formato XML, necessário??? 
       // FORMATO XAdES
        AD_RB_XADES_2_2("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RB_v2_2.xml",
                		"http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_2.xml"),
        AD_RB_XADES_2_3("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RB_v2_3.xml",
                        		"http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_3.xml"),        		
        AD_RB_XADES_2_4("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RB_v2_4.xml",
                                		"http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_4.xml"),
                                		
        AD_RT_XADES_2_3("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RT_v2_3.xml",
                		"http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_3.xml"),
        AD_RT_XADES_2_4("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RT_v2_4.xml",
                        		"http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_4.xml"),
                		
   		AD_RV_XADES_2_3("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RV_v2_3.xml",
                   		"http://politicas.icpbrasil.gov.br/PA_AD_RV_v2_3.xml"),                   		
        AD_RV_XADES_2_4("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RV_v2_4.xml",
                           		"http://politicas.icpbrasil.gov.br/PA_AD_RV_v2_4.xml"),
                   		
        AD_RC_XADES_2_3("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RC_v2_3.xml",
                        "http://politicas.icpbrasil.gov.br/PA_AD_RC_v2_3.xml"),
        AD_RC_XADES_2_4("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RC_v2_4.xml",
                                "http://politicas.icpbrasil.gov.br/PA_AD_RC_v2_4.xml"),
                        
        AD_RA_XADES_2_3("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RA_v2_3.xml",
                   		"http://politicas.icpbrasil.gov.br/PA_AD_RA_v2_3.xml"),           		
                   		
        AD_RA_XADES_2_4("/org/demoiselle/signer/policy/engine/artifacts/PA_AD_RA_v2_4.xml",
                           		"http://politicas.icpbrasil.gov.br/PA_AD_RA_v2_4.xml"),
                        		
        // FORMATO PAdES 		
        		
        AD_RB_PADES_1_0("/org/demoiselle/signer/policy/engine/artifacts/PA_PAdES_AD_RB_v1_0.der",
                		"http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_0.der"),        		
        AD_RB_PADES_1_1("/org/demoiselle/signer/policy/engine/artifacts/PA_PAdES_AD_RB_v1_1.der",
                        		"http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_1.der"),
                        		
        AD_RT_PADES_1_0("/org/demoiselle/signer/policy/engine/artifacts/PA_PAdES_AD_RT_v1_0.der",
                		"http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RT_v1_0.der"),
        AD_RT_PADES_1_1("/org/demoiselle/signer/policy/engine/artifacts/PA_PAdES_AD_RT_v1_1.der",
                        		"http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RT_v1_1.der"),
                		
   		AD_RC_PADES_1_0("/org/demoiselle/signer/policy/engine/artifacts/PA_PAdES_AD_RC_v1_0.der",
                        "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RC_v1_0.der"),
        AD_RC_PADES_1_1("/org/demoiselle/signer/policy/engine/artifacts/PA_PAdES_AD_RC_v1_1.der",
                                "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RC_v1_1.der"),
        AD_RC_PADES_1_2("/org/demoiselle/signer/policy/engine/artifacts/PA_PAdES_AD_RC_v1_2.der",
                                        "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RC_v1_2.der"),
                                
        AD_RA_PADES_1_1("/org/demoiselle/signer/policy/engine/artifacts/PA_PAdES_AD_RA_v1_1.der",
                		"http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RA_v1_1.der"),
        AD_RA_PADES_1_2("/org/demoiselle/signer/policy/engine/artifacts/PA_PAdES_AD_RA_v1_2.der",
        		"http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RA_v1_2.der");
        
                
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
     *  http://iti.gov.br/repositorio/84-repositorio/133-artefatos-de-assinatura-digital
     *
     */
    public enum ListOfSubscriptionPolicies {

    	// In Signer component
        LPAV1("/org/demoiselle/signer/policy/engine/artifacts/LPA.der"),
        LPAV2("/org/demoiselle/signer/policy/engine/artifacts/LPAv2.der"),
        CAdES("/org/demoiselle/signer/policy/engine/artifacts/LPA_CAdES.der"),
        XADES("/org/demoiselle/signer/policy/engine/artifacts/LPA_XAdES.xml"),
        PAdES("/org/demoiselle/signer/policy/engine/artifacts/LPA_PAdES.der"),

        // deprecated
        LPAV1_URL("http://politicas.icpbrasil.gov.br/LPA.der"),
        LPAV2_URL("http://politicas.icpbrasil.gov.br/LPAv2.der"),
        
        
        CAdES_ITI_URL(PolicyEngineConfig.getInstance().getUrl_iti_lpa_cades()),
        CAdES_ITI_URL_SHA(PolicyEngineConfig.getInstance().getUrl_iti_lpa_cades_sha()),
        XADES_ITI_URL(PolicyEngineConfig.getInstance().getUrl_iti_lpa_xades()),
        XADES_ITI_URL_SHA(PolicyEngineConfig.getInstance().getUrl_iti_lpa_xades_sha()),
        PAdES_ITI_URL(PolicyEngineConfig.getInstance().getUrl_iti_lpa_pades()),
        PAdES_ITI_URL_SHA(PolicyEngineConfig.getInstance().getUrl_iti_lpa_pades_sha()),
        CAdES_LOCAL_URL(PolicyEngineConfig.getInstance().getUrl_local_lpa_cades()),
        CAdES_LOCAL_URL_SHA(PolicyEngineConfig.getInstance().getUrl_local_lpa_cades_sha()),
        XADES_LOCAL_URL(PolicyEngineConfig.getInstance().getUrl_local_lpa_xades()),
        XADES_LOCAL_URL_SHA(PolicyEngineConfig.getInstance().getUrl_local_lpa_xades_sha()),
        PAdES_LOCAL_URL(PolicyEngineConfig.getInstance().getUrl_local_lpa_pades()),
        PAdES_LOCAL_URL_SHA(PolicyEngineConfig.getInstance().getUrl_local_lpa_pades_sha());
        
        
        private String url;
        private String file;

        
        private ListOfSubscriptionPolicies(String file) {
            this.file = file;
            this.url = file;
        }
        
//        private ListOfSubscriptionPolicies(String file, String url) {
//        	this.file = file;
//            this.url = url;
//        }

        public String getUrl() {
            return url;
        }

        public String getFile() {
            return file;
        }        
    }
    
    
}
