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

package org.demoiselle.signer.signer.examples;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.demoiselle.signer.chain.icp.brasil.provider.impl.ICPBrasilUserHomeProviderCA;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;

public class Signer {

	private static final Logger LOGGER = LoggerFactory.getLogger(Signer.class.getName());

	public static void main(String[] args) throws Throwable {

		String textToSign = "Julian Cesar";
		String homeUser = ICPBrasilUserHomeProviderCA.PATH_HOME_USER;

		LOGGER.log(Level.INFO, "============= Iniciando aplicação =============");

		Path p7sFilePath = Paths.get(homeUser, "textoAssinado." + Policies.AD_RB_CADES_2_0 + ".p7s");
		sign(textToSign, p7sFilePath, Policies.AD_RB_CADES_2_0, SignerAlgorithmEnum.SHA256withRSA);

		p7sFilePath = Paths.get(homeUser, "textoAssinado." + Policies.AD_RB_CADES_2_1 + ".p7s");
		sign(textToSign, p7sFilePath, Policies.AD_RB_CADES_2_1, SignerAlgorithmEnum.SHA256withRSA);

		p7sFilePath = Paths.get(homeUser, "textoAssinado." + Policies.AD_RB_CADES_2_2 + ".p7s");
		sign(textToSign, p7sFilePath, Policies.AD_RB_CADES_2_2, SignerAlgorithmEnum.SHA512withRSA);

		LOGGER.log(Level.INFO, "============= Finalizando aplicação =============");

	}

	public static KeyStoreLoader keyStoreLoader;
	public static KeyStore keyStore;
	public static String alias;
	public static X509Certificate certificate;
	public static PrivateKey privateKey;
	public static String password;
	public static Certificate[] certificateChain;

	public static void sign(String text, Path pathP7s, Policies police, SignerAlgorithmEnum algorithm)
			throws KeyStoreException, IOException, UnrecoverableKeyException, NoSuchAlgorithmException {

		LOGGER.log(Level.INFO, "===== " + police.toString() + " =====");

		byte[] content = text.getBytes();

		PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();

		// if (pinHandler == null) {
		// pinHandler = new PinHandler("Ações");
		// }

		if (keyStoreLoader == null) {
			keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
			// keyStoreLoader.setCallbackHandler(pinHandler);
			keyStore = keyStoreLoader.getKeyStore();
			alias = keyStore.aliases().nextElement();
			certificate = (X509Certificate) keyStore.getCertificate(alias);
			privateKey = (PrivateKey) keyStore.getKey(alias, null);
			certificateChain = keyStore.getCertificateChain(alias);
		}

		signer.setCertificates(certificateChain);
		signer.setPrivateKey(privateKey);

		signer.setSignaturePolicy(police);
		signer.setAlgorithm(algorithm);

		byte[] sign = signer.doAttachedSign(content);

		System.out.println(">>>>>>>>>> Validando a assinatura");

		// FIXME comentado check does not exist?!!
		// Valida
		// signer.check(content, sign);

		ByteArrayInputStream bis = new ByteArrayInputStream(sign);

		Files.copy(bis, pathP7s, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
	}
}
