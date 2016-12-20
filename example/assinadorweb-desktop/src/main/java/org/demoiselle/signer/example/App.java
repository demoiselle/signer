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

package org.demoiselle.signer.example;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.JOptionPane;

import org.demoiselle.signer.jnlp.action.AbstractFrameExecute;
import org.demoiselle.signer.jnlp.util.AuthorizationException;
import org.demoiselle.signer.jnlp.util.ConectionException;
import org.demoiselle.signer.jnlp.util.Utils;
import org.demoiselle.signer.jnlp.view.MainFrame;
import org.demoiselle.signer.signature.cades.SignerException;
import org.demoiselle.signer.signature.cades.factory.PKCS7Factory;
import org.demoiselle.signer.signature.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.signature.core.util.ZipBytes;
import org.demoiselle.signer.signature.policy.engine.factory.PolicyFactory;


public class App extends AbstractFrameExecute {
	
	private static final Logger LOGGER = Logger.getLogger(App.class.getName());

    String jnlpIdentifier = "";
    String jnlpService = "";
    byte[] zipDownload = null;
    InputStream certificateForHTTPS = null;
    
	public static Map<String, byte[]> files = Collections.synchronizedMap(new HashMap<String, byte[]>());
	public static Map<String, byte[]> signatures = Collections.synchronizedMap(new HashMap<String, byte[]>());

    /**
     * Carrega as variaveis do arquivo jnlp
     *  
     */
    public App() {
    	
    	//Propriedades do JNLP
    	jnlpIdentifier = System.getProperty("jnlp.identifier");
        jnlpService = System.getProperty("jnlp.service");
        
        LOGGER.log(Level.INFO, "jnlp.identifier..: " + jnlpIdentifier);
        LOGGER.log(Level.INFO, "jnlp.service.....: " + jnlpService);
        
        if (jnlpIdentifier == null || jnlpIdentifier.isEmpty()) {
            JOptionPane.showMessageDialog(null, "A variavel \"jnlp.identifier\" não está configurada.", "Erro", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }

        if (jnlpService == null || jnlpService.isEmpty()) {
            JOptionPane.showMessageDialog(null, "A variavel \"jnlp.service\" não está configurada.", "Erro", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }

        
        try{

        	//Certificado para conexão HTTPS
	        //certificateForHTTPS = new ByteArrayInputStream(Utils.getSSLCertificate(jnlpService));
	        //Download do ZIP com arquivos via HTTPS
	        //zipDownload = Utils.downloadFromUrl(jnlpService.concat("/download/"), jnlpIdentifier, certificateForHTTPS);
        	
        	//Download do ZIP com arquivos via HTTP
        	zipDownload = Utils.downloadFromUrl(jnlpService.concat("/download/"), jnlpIdentifier);
	        
	        //Descompactando os arquivos
	        files = ZipBytes.decompressing(zipDownload);
        }catch(AuthorizationException e){
        	LOGGER.log(Level.SEVERE, e.getMessage());
        	JOptionPane.showMessageDialog(null, "Token Inválido: " + e.getMessage(), "Erro", JOptionPane.ERROR_MESSAGE);
        	System.exit(0);
    	}catch(ConectionException e){
    		LOGGER.log(Level.SEVERE, e.getMessage());
    		JOptionPane.showMessageDialog(null, "Erro de Conexão: " + e.getMessage(), "Erro", JOptionPane.ERROR_MESSAGE);
    		System.exit(0);
    	}
        
        //Lista os arquivos na tela
        List<String> fileNames = new ArrayList<String>(files.keySet());
        MainFrame.setListFileName(fileNames);
    }
    
    @Override
    public void execute(KeyStore ks, String alias, MainFrame principal) {
        try {
            //Parametrizando o objeto PKCS7Signer para assinatura desanexada.
            PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
            signer.setCertificates(ks.getCertificateChain(alias));
            signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));
            signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_CADES_2_2);
            signer.setAttached(false);
            
            //Varrendo todos os arquivos, gera uma assinatura para cada arquivo
            for (Map.Entry<String, byte[]> entry : files.entrySet()) {
            	LOGGER.log(Level.INFO, "Assinando arquivo: " + entry.getKey());
                byte[] signed = signer.doSign(entry.getValue());
                signatures.put(entry.getKey(), signed);
            }
            //compressão dos arquivos em um zip
            byte[] uploadZip = ZipBytes.compressing(signatures);
            
            //Upload das assinaturas via HTTPS
            //Utils.uploadToURL(uploadZip, jnlpService.concat("/upload/"), jnlpIdentifier, new ByteArrayInputStream(Utils.getSSLCertificate(jnlpService)));
            
            //Upload das assinaturas via HTTP
            Utils.uploadToURL(uploadZip, jnlpService.concat("/upload/"), jnlpIdentifier);

            
            LOGGER.log(Level.INFO, "Assinatura(s) realizada(s) com sucesso.");
            System.exit(0);
            
        }catch(AuthorizationException ex){
        	LOGGER.log(Level.SEVERE, ex.getMessage());
        	JOptionPane.showMessageDialog(principal, "Token Inválido: " + ex.getMessage(), "Erro", JOptionPane.ERROR_MESSAGE);
        	System.exit(0);
    	}catch(ConectionException ex){
    		LOGGER.log(Level.SEVERE, ex.getMessage());
    		JOptionPane.showMessageDialog(principal, "Erro de Conexão: " + ex.getMessage(), "Erro", JOptionPane.ERROR_MESSAGE);
    		System.exit(0);
    	} 
        catch (KeyStoreException ex) {
        	ex.printStackTrace();
            JOptionPane.showMessageDialog(principal, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }
        catch (NoSuchAlgorithmException ex) {
        	ex.printStackTrace();
            JOptionPane.showMessageDialog(principal, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }
        catch (UnrecoverableKeyException ex) {
        	ex.printStackTrace();
            JOptionPane.showMessageDialog(principal, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }        
        catch(SignerException ex){
        	ex.printStackTrace();
            JOptionPane.showMessageDialog(principal, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        	
        }
        
    }

    @Override
    public void cancel(KeyStore ks, String alias, MainFrame principal) {
    	sendCancelToken(principal);
        principal.setVisible(false); //you can't see me!
        principal.dispose(); //Destroy the JFrame object
    }
    
    @Override
    public void close(MainFrame principal) {
    	sendCancelToken(principal);
    }
    
    private void sendCancelToken(MainFrame principal){
        //certificateForHTTPS = new ByteArrayInputStream(Utils.getSSLCertificate(jnlpService));
        //Avisa ao serviço que a assinatura foi cancelada via HTTPS
        //Utils.cancel("Usuário cancelou a aplicação", jnlpService.concat("/cancelar/"), jnlpIdentifier, certificateForHTTPS);
        
      //Avisa ao serviço que a assinatura foi cancelada via HTTP
        Utils.cancel("Usuário cancelou a aplicação", jnlpService.concat("/cancelar/"), jnlpIdentifier);

    }
    

}
