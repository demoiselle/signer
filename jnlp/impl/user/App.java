/*
 * Demoiselle Framework
 * Copyright (C) 2017 SERPRO
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
package org.demoiselle.signer.jnlp.user;

import java.io.File;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import javax.swing.JOptionPane;
import org.demoiselle.signer.signature.cades.factory.PKCS7Factory;
import org.demoiselle.signer.signature.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.signature.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.jnlp.action.AbstractFrameExecute;
import org.demoiselle.signer.jnlp.util.ConectionException;
import org.demoiselle.signer.jnlp.util.Utils;
import org.demoiselle.signer.jnlp.view.MainFrame;

/**
 *
 * 
 */
public class App extends AbstractFrameExecute {

    String jnlpIdentifier = "";
    String jnlpService = "";

    /**
     * Carrega as variaveis do arquivo jnlp
     */
    public App() {

        jnlpIdentifier = System.getProperty("jnlp.identifier");
        jnlpService = System.getProperty("jnlp.service");

        System.out.println("jnlp.identifier..: " + jnlpIdentifier);
        System.out.println("jnlp.service.....: " + jnlpService);
    }

    @Override
    public void execute(KeyStore ks, String alias, MainFrame principal) {
        try {

            if (jnlpIdentifier == null || jnlpIdentifier.isEmpty()) {
                JOptionPane.showMessageDialog(principal, "A variavel \"jnlp.identifier\" não está configurada.", "Erro", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (jnlpService == null || jnlpService.isEmpty()) {
                JOptionPane.showMessageDialog(principal, "A variavel \"jnlp.service\" não está configurada.", "Erro", JOptionPane.ERROR_MESSAGE);
                return;
            }

            /* Parametrizando o objeto doSign */
            PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
            signer.setCertificates(ks.getCertificateChain(alias));
            signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));
            signer.setSignaturePolicy(PolicyFactory.Policies.AD_RT_CADES_2_2);
            signer.setAttached(true);
            /* Realiza a assinatura do conteudo */
            System.out.println("Efetuando a  assinatura do conteudo");
            Utils utils = new Utils();
            //Faz o download do conteudo a ser assinado
            String conexao = jnlpService.concat("/download/").concat(jnlpIdentifier);
            System.out.println("Conectando em....: " + conexao);
            byte[] content = utils.downloadFromUrl(conexao);
            byte[] signed = signer.signer(content);
            // Grava o conteudo assinado no disco para verificar o resultado
            utils.writeContentToDisk(signed, System.getProperty("user.home").concat(File.separator).concat("resultado.p7s"));

            //Faz o upload do conteudo assinado
//            utils.uploadToURL(signed, jnlpService.concat("/upload/").concat(jnlpIdentifier));
            utils.uploadToURL(signed, jnlpService.concat("/upload/"));
            JOptionPane.showMessageDialog(principal, "O arquivo foi assinado com sucesso.", "Mensagem", JOptionPane.INFORMATION_MESSAGE);
            System.exit(0);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | ConectionException ex) {
            JOptionPane.showMessageDialog(principal, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }
    }

    @Override
    public void cancel(KeyStore ks, String alias, MainFrame principal) {
        /* Seu codigo customizado aqui... */
        System.out.println("org.demoiselle.signer.jnlp.user.App.cancel()");
        principal.setVisible(false); //you can't see me!
        principal.dispose(); //Destroy the JFrame object
    }

}
