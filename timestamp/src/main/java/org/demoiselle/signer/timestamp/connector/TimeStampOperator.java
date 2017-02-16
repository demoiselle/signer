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
package org.demoiselle.signer.timestamp.connector;

import org.demoiselle.signer.core.exception.CertificateCoreException;
import org.demoiselle.signer.cryptography.Digest;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.cryptography.factory.DigestFactory;
import org.demoiselle.signer.timestamp.Timestamp;
import org.demoiselle.signer.timestamp.enumeration.ConnectionType;
import org.demoiselle.signer.timestamp.enumeration.PKIFailureInfo;
import org.demoiselle.signer.timestamp.enumeration.PKIStatus;
import org.demoiselle.signer.timestamp.signer.RequestSigner;
import org.demoiselle.signer.timestamp.utils.TimeStampConfig;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author 07721825741
 */
public class TimeStampOperator {

    private static final Logger logger = LoggerFactory.getLogger(TimeStampOperator.class);

    private InputStream inputStream = null;
    private Timestamp timestamp;
    private TimeStampRequest timeStampRequest;
    private TimeStampResponse timeStampResponse;

    /**
     * Cria uma requisição de carimbo de tempo assinada pelo usuario
     *
     * @param privateKey
     * @param certificates
     * @param content
     * @return Uma requisicao de carimbo de tempo
     * @throws CertificateCoreException
     */
    public byte[] createRequest(PrivateKey privateKey, Certificate[] certificates, byte[] content) throws CertificateCoreException {
        try {
            logger.info("Gerando o digest do conteudo");
            Digest digest = DigestFactory.getInstance().factoryDefault();
            digest.setAlgorithm(DigestAlgorithmEnum.SHA_256);
            byte[] hashedMessage = digest.digest(content);
            
            logger.info(Base64.toBase64String(hashedMessage));

            logger.info("Montando a requisicao para o carimbador de tempo");
            TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
                        
            timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier(TimeStampConfig.getInstance().getTSPOid()));
            timeStampRequestGenerator.setCertReq(true);
            BigInteger nonce = BigInteger.valueOf(100);
            timeStampRequest = timeStampRequestGenerator.generate(new ASN1ObjectIdentifier(TSPAlgorithms.SHA256.getId()), hashedMessage, nonce);
            byte request[] = timeStampRequest.getEncoded();
            logger.info("Efetuando a  assinatura do conteudo");
            RequestSigner requestSigner = new RequestSigner();
            byte[] signedRequest = requestSigner.signRequest(privateKey, certificates, request, "SHA256withRSA");
            return signedRequest;
        } catch (IOException ex) { //catch (IOException | NoSuchAlgorithmException ex
        
            throw new CertificateCoreException(ex.getMessage());
        }
    }

    /**
     *
     * @param keystoreLocation
     * @param pin
     * @param alias
     * @param content
     * @return
     * @throws CertificateCoreException
     */
    public byte[] createRequest(String keystoreLocation, String pin, String alias, byte[] content) throws CertificateCoreException {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(keystoreLocation), pin.toCharArray());
            PrivateKey pk = (PrivateKey) ks.getKey(alias, pin.toCharArray());
            Certificate[] certs = ks.getCertificateChain(alias);
            return this.createRequest(pk, certs, content);
        } catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | UnrecoverableKeyException | IOException ex) {
            throw new CertificateCoreException(ex.getMessage());
        }
    }

    /**
     * Envia a requisicao de carimbo de tempo para um servidor de carimbo de
     * tempo
     *
     * @param request
     * @return O carimbo de tempo retornado pelo servidor
     */
    public byte[] invoke(byte[] request) throws CertificateCoreException {
        try {

            logger.info("Iniciando pedido de carimbo de tempo");
            Connector connector = ConnectorFactory.buildConnector(ConnectionType.SOCKET);
            connector.setHostname(TimeStampConfig.getInstance().getTspHostname());
            connector.setPort(TimeStampConfig.getInstance().getTSPPort());

            logger.info("Obtendo o response");
            inputStream = connector.connect(request);

            long tempo;
            // Valor do timeout da verificacao de dados disponiveis para leitura
            int timeOut = 3500;
            // Verificando se os 4 bytes iniciais estao disponiveis para leitura
            for (tempo = System.currentTimeMillis() + timeOut; inputStream.available() < 4 && System.currentTimeMillis() < tempo;) {
                try {
                    Thread.sleep(1L);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Lendo tamanho total
            byte[] tamanhoRetorno = new byte[4];
            inputStream.read(tamanhoRetorno, 0, 4);
            int tamanho = new BigInteger(tamanhoRetorno).intValue();

            // Verificando se os bytes na quantidade "tamanho" estao disponiveis
            if (System.currentTimeMillis() < tempo) {
                while (inputStream.available() < tamanho && System.currentTimeMillis() < tempo) {
                    try {
                        Thread.sleep(1L);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
                if (System.currentTimeMillis() >= tempo) {
                    logger.error("Erro timeout ao receber dados");
                }
            } else {
                logger.error("Erro timeout ao receber dados");
            }

            // Lendo flag
            byte[] retornoFlag = new byte[1];
            inputStream.read(retornoFlag, 0, 1);
            // tamanho total menos o tamanho da flag
            tamanho -= 1;

            // Lendo dados carimbo
            byte[] retornoCarimboDeTempo = new byte[tamanho];
            inputStream.read(retornoCarimboDeTempo, 0, tamanho);
            timeStampResponse = new TimeStampResponse(retornoCarimboDeTempo);

            logger.info("PKIStatus....: {}", timeStampResponse.getStatus());

            switch (timeStampResponse.getStatus()) {
                case 0: {
                    logger.info(PKIStatus.granted.getMessage());
                    break;
                }
                case 1: {
                    logger.info(PKIStatus.grantedWithMods.getMessage());
                    break;
                }
                case 2: {
                    logger.info(PKIStatus.rejection.getMessage());
                    throw new CertificateCoreException(PKIStatus.rejection.getMessage());
                }
                case 3: {
                    logger.info(PKIStatus.waiting.getMessage());
                    throw new CertificateCoreException(PKIStatus.waiting.getMessage());
                }
                case 4: {
                    logger.info(PKIStatus.revocationWarning.getMessage());
                    throw new CertificateCoreException(PKIStatus.revocationWarning.getMessage());
                }
                case 5: {
                    logger.info(PKIStatus.revocationNotification.getMessage());
                    throw new CertificateCoreException(PKIStatus.revocationNotification.getMessage());
                }
                default: {
                    logger.info(PKIStatus.unknownPKIStatus.getMessage());
                    throw new CertificateCoreException(PKIStatus.unknownPKIStatus.getMessage());
                }
            }

            int failInfo = -1;

            if (timeStampResponse.getFailInfo() != null) {
                failInfo = Integer.parseInt(new String(timeStampResponse.getFailInfo().getBytes()));
            }

            logger.info("FailInfo....: {}", failInfo);

            switch (failInfo) {
                case 0:
                    logger.info(PKIFailureInfo.badAlg.getMessage());
                    break;
                case 2:
                    logger.info(PKIFailureInfo.badRequest.getMessage());
                    break;
                case 5:
                    logger.info(PKIFailureInfo.badDataFormat.getMessage());
                    break;
                case 14:
                    logger.info(PKIFailureInfo.timeNotAvailable.getMessage());
                    break;
                case 15:
                    logger.info(PKIFailureInfo.unacceptedPolicy.getMessage());
                    break;
                case 16:
                    logger.info(PKIFailureInfo.unacceptedExtension.getMessage());
                    break;
                case 17:
                    logger.info(PKIFailureInfo.addInfoNotAvailable.getMessage());
                    break;
                case 25:
                    logger.info(PKIFailureInfo.systemFailure.getMessage());
                    break;
            }

            timeStampResponse.validate(timeStampRequest);
            TimeStampToken timeStampToken = timeStampResponse.getTimeStampToken();
            this.setTimestamp(new Timestamp(timeStampToken));

            if (timeStampToken == null) {
                throw new CertificateCoreException("O Token retornou nulo.");
            }
            connector.close();

            //Imprime os dados do carimbo de tempo
            logger.info(timestamp.toString());

            //Retorna o carimbo de tempo gerado
            return timestamp.getCodificado();

        } catch (CertificateCoreException | TSPException | IOException e) {
            throw new CertificateCoreException(e.getMessage());
        }
    }

    /**
     * Efetua a validacao de um carimbo de tempo
     *
     * @param content
     * @param response O carimbo de tempo a ser validado
     *
     */
    @SuppressWarnings("unchecked")
	public void validate(byte[] content, byte[] response) throws CertificateCoreException {
        try {
            TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(response));
            CMSSignedData s = timeStampToken.toCMSSignedData();

            int verified = 0;

            Store certStore = s.getCertificates();
            SignerInformationStore signers = s.getSignerInfos();
            Collection<SignerInformation> c = signers.getSigners();
            Iterator<SignerInformation> it = c.iterator();

            while (it.hasNext()) {
                SignerInformation signer = (SignerInformation) it.next();
                Collection<?> certCollection = certStore.getMatches(signer.getSID());
                Iterator<?> certIt = certCollection.iterator();
                X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
                    verified++;
                }
                cert.getExtension(new ASN1ObjectIdentifier("2.5.29.31")).getExtnValue();
            }

            logger.info("Assinaturas Verificadas....: {}", verified);

            //Valida o hash  incluso no carimbo de tempo com hash do arquivo carimbado
            Digest digest = DigestFactory.getInstance().factoryDefault();
            digest.setAlgorithm(DigestAlgorithmEnum.SHA_256);
            digest.digest(content);

            if (Arrays.equals(digest.digest(content), timeStampToken.getTimeStampInfo().getMessageImprintDigest())) {
                logger.info("Hash do documento conferido com sucesso.");
            } else {
                throw new CertificateCoreException("O documento fornecido nao corresponde ao do carimbo de tempo!");
            }

        } catch (TSPException | IOException | CMSException | OperatorCreationException | CertificateException ex) {
            throw new CertificateCoreException(ex.getMessage());
        }
    }

    public void setTimestamp(Timestamp timestamp) {
        this.timestamp = timestamp;
    }

    public Timestamp getTimestamp() {
        return timestamp;
    }

}
