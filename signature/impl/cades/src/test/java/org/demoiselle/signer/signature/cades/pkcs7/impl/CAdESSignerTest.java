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
package org.demoiselle.signer.signature.cades.pkcs7.impl;

import org.demoiselle.signer.signature.cades.factory.PKCS7Factory;
import org.demoiselle.signer.signature.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.signature.policy.engine.factory.PolicyFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.Test;
import org.slf4j.LoggerFactory;

/**
 *
 * @author 07721825741
 */
public class CAdESSignerTest {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(CAdESSignerTest.class);

    // @Test
    
    // TODO teste depende de configuração de ambiente do usuário, devemos criar uma alternativa
    public void testSignAndVerifySignature() {
        try {
            String configName = "~/drives/drivers.config";
            String password = "";

            Provider p = new sun.security.pkcs11.SunPKCS11(configName);
            Security.addProvider(p);

            KeyStore ks = KeyStore.getInstance("PKCS11", "SunPKCS11-Provedor");
            ks.load(null, password.toCharArray());

            Certificate[] certificates = null;

            String alias = "";

            Enumeration<String> e = ks.aliases();
            while (e.hasMoreElements()) {
                alias = e.nextElement();
                logger.info("alias..............: {}", alias);
                certificates = ks.getCertificateChain(alias);
            }

            X509Certificate c = (X509Certificate) certificates[0];
            logger.info("Número de série....: {}", c.getSerialNumber().toString());

            byte[] content = "Hello World".getBytes();

            /* Parametrizando o objeto doSign */
            PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
            signer.setCertificates(ks.getCertificateChain(alias));
            signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));
            signer.setSignaturePolicy(PolicyFactory.Policies.AD_RT_CADES_2_2);
            signer.setAttached(true);

            /* Realiza a assinatura do conteudo */
            logger.info("Efetuando a  assinatura do conteudo");
            byte[] signed = signer.doSign(content);

            /* Valida o conteudo */
            logger.info("Efetuando a validacao da assinatura.");
            boolean checked = signer.check(content, signed);

            if (checked) {
                logger.info("A assinatura foi validada.");
            } else {
                logger.info("A assinatura foi invalidada!");
            }

            try (FileOutputStream fos = new FileOutputStream(new File("./helloworld.p7s"))) {
                fos.write(signed);
            }

        } catch (KeyStoreException | NoSuchProviderException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException ex) {
            Logger.getLogger(CAdESSignerTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
