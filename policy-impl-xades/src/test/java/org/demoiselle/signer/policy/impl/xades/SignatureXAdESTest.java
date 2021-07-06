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

package org.demoiselle.signer.policy.impl.xades;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.impl.xades.xml.XMLSigner;
import org.junit.Test;
import org.w3c.dom.Document;

public class SignatureXAdESTest {

	
	@Test
	public void testSign() {
				
		try {
			KeyStore keyStore = null;
			
			keyStore = getKeyStoreTokenBySigner();
			String fileName = "teste_assinatura.xml";

	        ClassLoader classLoader = getClass().getClassLoader();
	        URL fileUri = classLoader.getResource(fileName);
	        File newFile=new File(fileUri.toURI());
	        
//	        InputStreamReader streamReader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
//	        BufferedReader reader = new BufferedReader(streamReader); 
	        			
			String alias = getAlias(keyStore);
			XMLSigner xades = new XMLSigner();
			xades.setAlias(alias);
			xades.setKeyStore(keyStore);
			xades.setPolicyId(XMLPoliciesOID.AD_RB_XADES_2_4.getOID());
			Document doc = xades.sign(newFile.getPath());					
			String signedFile = fileName.replaceFirst(".xml$", "_signed.xml");
			OutputStream os = new FileOutputStream("src/test/resources/"+signedFile);
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer trans = tf.newTransformer();
			trans.transform(new DOMSource(doc), new StreamResult(os));
					
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (TransformerException e) {
		  e.printStackTrace();
		} catch (Throwable e) {
		  e.printStackTrace();
		}		

	}
	
	
	// Usa o Signer para leitura, funciona para windows e NeoID
	private KeyStore getKeyStoreTokenBySigner() {

		try {
			
			KeyStoreLoader keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
			KeyStore keyStore = keyStoreLoader.getKeyStore();

			return keyStore;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		} finally {
		}

	}
	
	
	/**
	 * 
	 * Faz a leitura do token em LINUX, precisa setar a lib (.SO) e a senha do token.
	 */
	@SuppressWarnings({ "restriction", "unused" })
	private KeyStore getKeyStoreToken() {

		try {
			// ATENÇÃO ALTERAR CONFIGURAÇÃO ABAIXO CONFORME O TOKEN USADO

			// Para TOKEN Branco a linha abaixo
			// String pkcs11LibraryPath =
			// "/usr/lib/watchdata/ICP/lib/libwdpkcs_icp.so";

			// Para TOKEN Azul a linha abaixo
			String pkcs11LibraryPath = "/usr/lib/libeToken.so";

			StringBuilder buf = new StringBuilder();
			buf.append("library = ").append(pkcs11LibraryPath).append("\nname = Provedor\n");
			Provider p = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(buf.toString().getBytes()));
			Security.addProvider(p);
			// ATENÇÃO ALTERAR "SENHA" ABAIXO
			Builder builder = KeyStore.Builder.newInstance("PKCS11", p,	new KeyStore.PasswordProtection("senha".toCharArray()));
			KeyStore ks;
			ks = builder.getKeyStore();

			return ks;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		} finally {
		}

	}

	@SuppressWarnings("unused")
	private KeyStore getKeyStoreFileBySigner() {

		try {
				// informar o caminho e nome do arquivo
			File filep12 = new File("/");
			
			KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader(filep12);
			// Informar a senha
			KeyStore keystore = loader.getKeyStore("senha");
			return keystore;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		} finally {
		}

	}
	
	
	private String getAlias(KeyStore ks) {
		Certificate[] certificates = null;
		String alias = "";
		Enumeration<String> e;
		try {
			e = ks.aliases();
			while (e.hasMoreElements()) {
				alias = e.nextElement();
				System.out.println("alias..............: " + alias);
				System.out.println("iskeyEntry"+ ks.isKeyEntry(alias));
				System.out.println("containsAlias"+ks.containsAlias(alias));
				//System.out.println(""+ks.getKey(alias, null));
				certificates = ks.getCertificateChain(alias);
			}

		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return alias;
	}

}
