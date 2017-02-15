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
package org.demoiselle.signer.timestamp.signer;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author 07721825741
 */
public class RequestSigner {

    private static final Logger logger = LoggerFactory.getLogger(RequestSigner.class);

    /**
     * Realiza a assinatura de uma requisicao de carimbo de tempo
     *
     * @param privateKey
     * @param certificates
     * @param request
     * @return A requisicao assinada
     */
    public byte[] signRequest(PrivateKey privateKey, Certificate[] certificates, byte[] request, String algorithm) {
        try {
            logger.info("Efetuando a assinatura da requisicao");
            Security.addProvider(new BouncyCastleProvider());

            X509Certificate signCert = (X509Certificate) certificates[0];
            List<X509Certificate> certList = new ArrayList<>();
            certList.add(signCert);

            // setup the generator
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            String varAlgorithm = null;
            if (algorithm != null && !algorithm.isEmpty()){
            	varAlgorithm = algorithm;
            }else{
            	varAlgorithm = "SHA256withRSA";
            }
            	
            SignerInfoGenerator signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder().build(varAlgorithm, privateKey, signCert);
            generator.addSignerInfoGenerator(signerInfoGenerator);

            Store certStore = new JcaCertStore(certList);
            generator.addCertificates(certStore);

//            Store crlStore = new JcaCRLStore(crlList);
//            generator.addCRLs(crlStore);
            // Create the signed data object
            CMSTypedData data = new CMSProcessableByteArray(request);
            CMSSignedData signed = generator.generate(data, true);
            return signed.getEncoded();

        } catch (CMSException | IOException | OperatorCreationException | CertificateEncodingException ex) {
            logger.info(ex.getMessage());
        }
        return null;
    }

}
