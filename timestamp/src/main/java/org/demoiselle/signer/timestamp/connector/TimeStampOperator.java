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

package org.demoiselle.signer.timestamp.connector;

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
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Store;
import org.demoiselle.signer.core.exception.CertificateCoreException;
import org.demoiselle.signer.core.keystore.loader.configuration.Configuration;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.cryptography.Digest;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.cryptography.factory.DigestFactory;
import org.demoiselle.signer.timestamp.Timestamp;
import org.demoiselle.signer.timestamp.enumeration.ConnectionType;
import org.demoiselle.signer.timestamp.signer.RequestSigner;
import org.demoiselle.signer.timestamp.utils.TimeStampConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Performs all time stamp operations: from the connection with the time stamp authority to the stamp validation.
 *
 * @author 07721825741
 */
// TODO verificar os valores de algoritmos que estão sendo setados manualmente, provavelmente deve buscado do que foi setado ou no que estiver na política.
public class TimeStampOperator {

	private static final Logger logger = LoggerFactory.getLogger(TimeStampOperator.class);
	private static MessagesBundle timeStampMessagesBundle = new MessagesBundle();

	private InputStream inputStream = null;
	private Timestamp timestamp;
	private TimeStampRequest timeStampRequest;
	private TimeStampResponse timeStampResponse;

	/**
	 * Creates a time stamp request, signed with the users's certificate.
	 *
	 * @param privateKey   private key to sign with
	 * @param certificates certificate chain
	 * @param content      set null if signing only hash
	 * @param hash         set null if signing content
	 * @return A time stamp request
	 * @throws CertificateCoreException exception
	 */
	public byte[] createRequest(PrivateKey privateKey, Certificate[] certificates, byte[] content, byte[] hash) throws CertificateCoreException {
		try {
			logger.debug(timeStampMessagesBundle.getString("info.timestamp.digest"));
			Digest digest = DigestFactory.getInstance().factoryDefault();
			String varAlgoOid = null;
			String varAlgo = null;
			if (Configuration.getInstance().getSO().toLowerCase().indexOf("indows") > 0) {
				logger.debug(timeStampMessagesBundle.getString("info.timestamp.winhash"));
				varAlgoOid = TSPAlgorithms.SHA256.getId();
				varAlgo = "SHA256withRSA";
				digest.setAlgorithm(DigestAlgorithmEnum.SHA_256);
			} else {
				logger.debug(timeStampMessagesBundle.getString("info.timestamp.linuxhash"));
				varAlgoOid = TSPAlgorithms.SHA512.getId();
				varAlgo = "SHA512withRSA";
				digest.setAlgorithm(DigestAlgorithmEnum.SHA_512);
			}


			byte[] hashedMessage = null;
			if (content != null) {
				hashedMessage = digest.digest(content);
				//logger.info(Base64.toBase64String(hashedMessage));
			} else {
				hashedMessage = hash;
			}
			logger.debug(timeStampMessagesBundle.getString("info.timestamp.prepare.request"));
			TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
			timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier(TimeStampConfig.getInstance().getTSPOid()));
			timeStampRequestGenerator.setCertReq(true);
			BigInteger nonce = BigInteger.valueOf(100);
			timeStampRequest = timeStampRequestGenerator.generate(new ASN1ObjectIdentifier(varAlgoOid), hashedMessage, nonce);
			byte request[] = timeStampRequest.getEncoded();
			logger.debug(timeStampMessagesBundle.getString("info.timestamp.sign.request"));
			RequestSigner requestSigner = new RequestSigner();
			byte[] signedRequest = requestSigner.signRequest(privateKey, certificates, request, varAlgo);
			return signedRequest;
		} catch (IOException ex) {
			logger.error("createRequest :" + ex.getMessage());
			throw new CertificateCoreException(ex.getMessage());
		}
	}

	/**
	 * Creates a time stamp request using a certificate of type PKCS12.
	 *
	 * @param keystoreLocation key store location.
	 * @param pin              personal identification number.
	 * @param alias            alias.
	 * @param content          content of the request.
	 * @param hash             a hash.
	 * @return request as a byte[].
	 * @throws CertificateCoreException exception.
	 */
	public byte[] createRequest(String keystoreLocation, String pin, String alias, byte[] content, byte[] hash) throws CertificateCoreException {
		try {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(new FileInputStream(keystoreLocation), pin.toCharArray());
			PrivateKey pk = (PrivateKey) ks.getKey(alias, pin.toCharArray());
			Certificate[] certs = ks.getCertificateChain(alias);
			return this.createRequest(pk, certs, content, hash);
		} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | UnrecoverableKeyException | IOException ex) {
			logger.error(ex.getMessage());
			throw new CertificateCoreException(ex.getMessage());
		}
	}

	/**
	 * Sends the time stamp request {@link #createRequest(PrivateKey, Certificate[], byte[], byte[])} to a time stamp server
	 *
	 * @param request request to be sent
	 * @return The time stamp returned by the server
	 */
	public byte[] invoke(byte[] request) throws CertificateCoreException {
		try {

			logger.debug(timeStampMessagesBundle.getString("info.timestamp.init.request"));
			Connector connector = ConnectorFactory.buildConnector(ConnectionType.SOCKET);
			connector.setHostname(TimeStampConfig.getInstance().getTspHostname());
			connector.setPort(TimeStampConfig.getInstance().getTSPPort());
			logger.debug(timeStampMessagesBundle.getString("info.timestamp.response"));
			inputStream = connector.connect(request);


			long tempo;
			// Valor do timeout da verificacao de dados disponiveis para leitura
			int timeOut = org.demoiselle.signer.timestamp.configuration.TimeStampConfig.getInstance().getTimeOut();
			// Verificando se os 4 bytes iniciais estao disponiveis para leitura
			for (tempo = System.currentTimeMillis() + timeOut; inputStream.available() < 4 && System.currentTimeMillis() < tempo; ) {
				try {
					Thread.sleep(1L);
				} catch (InterruptedException e) {
					logger.debug(e.getMessage());
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
						logger.error(e.getMessage());
					}
				}
				if (System.currentTimeMillis() >= tempo) {
					logger.error(timeStampMessagesBundle.getString("info.timestamp.timeout"));
					throw new CertificateCoreException(timeStampMessagesBundle.getString("info.timestamp.timeout"));
				}
			} else {
				logger.error(timeStampMessagesBundle.getString("info.timestamp.timeout"));
				throw new CertificateCoreException(timeStampMessagesBundle.getString("info.timestamp.timeout"));
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

			logger.debug(timeStampMessagesBundle.getString("info.timestamp.status", timeStampResponse.getStatus()));

			switch (timeStampResponse.getStatus()) {
				case 0: {
					logger.debug(timeStampMessagesBundle.getString("info.pkistatus.granted"));
					break;
				}
				case 1: {
					logger.debug(timeStampMessagesBundle.getString("info.pkistatus.grantedWithMods"));
					break;
				}
				case 2: {
					logger.error(timeStampMessagesBundle.getString("error.pkistatus.rejection"));
					throw new CertificateCoreException(timeStampMessagesBundle.getString("error.pkistatus.rejection"));
				}
				case 3: {
					logger.error(timeStampMessagesBundle.getString("error.pkistatus.waiting"));
					throw new CertificateCoreException(timeStampMessagesBundle.getString("error.pkistatus.waiting"));
				}
				case 4: {
					logger.error(timeStampMessagesBundle.getString("error.pkistatus.revocation.warn"));
					throw new CertificateCoreException(timeStampMessagesBundle.getString("error.pkistatus.revocation.warn"));
				}
				case 5: {
					logger.error(timeStampMessagesBundle.getString("error.pkistatus.revocation.notification"));
					throw new CertificateCoreException(timeStampMessagesBundle.getString("error.pkistatus.revocation.notification"));
				}
				default: {
					logger.error(timeStampMessagesBundle.getString("error.pkistatus.unknown"));
					throw new CertificateCoreException(timeStampMessagesBundle.getString("error.pkistatus.unknown"));
				}
			}


			// ok
			int failInfo = -1;

			if (timeStampResponse.getFailInfo() != null) {
				failInfo = Integer.parseInt(new String(timeStampResponse.getFailInfo().getBytes()));
			}

			logger.debug(timeStampMessagesBundle.getString("info.timestamp.failinfo", failInfo));

			switch (failInfo) {
				case 0:
					logger.error(timeStampMessagesBundle.getString("error.pkifailureinfo.badAlg"));
					break;
				case 2:
					logger.error(timeStampMessagesBundle.getString("error.pkifailureinfo.badRequest"));
					break;
				case 5:
					logger.error(timeStampMessagesBundle.getString("error.pkifailureinfo.badDataFormat"));
					break;
				case 14:
					logger.error(timeStampMessagesBundle.getString("error.pkifailureinfo.timeNotAvailable"));
					break;
				case 15:
					logger.error(timeStampMessagesBundle.getString("error.pkifailureinfo.unacceptedPolicy"));
					break;
				case 16:
					logger.error(timeStampMessagesBundle.getString("error.pkifailureinfo.unacceptedExtension"));
					break;
				case 17:
					logger.error(timeStampMessagesBundle.getString("error.pkifailureinfo.addInfoNotAvailable"));
					break;
				case 25:
					logger.error(timeStampMessagesBundle.getString("error.pkifailureinfo.systemFailure"));
					break;
			}


			timeStampResponse.validate(timeStampRequest);
			TimeStampToken timeStampToken = timeStampResponse.getTimeStampToken();
			this.setTimestamp(new Timestamp(timeStampToken));

			if (timeStampToken == null) {
				logger.error(timeStampMessagesBundle.getString("error.timestamp.token.null"));
				throw new CertificateCoreException(timeStampMessagesBundle.getString("error.timestamp.token.null"));
			}
			connector.close();

			//Imprime os dados do carimbo de tempo
			logger.debug(timestamp.toString());

			//Retorna o carimbo de tempo gerado
			return timestamp.getEncoded();

		} catch (CertificateCoreException | TSPException | IOException e) {
			logger.error(e.getMessage());
			throw new CertificateCoreException(e.getMessage());
		}
	}

	/**
	 * Validate a time stamp
	 *
	 * @param content   if it is assigned, the parameter hash must to be null
	 * @param timeStamp timestamp to be validated
	 * @param hash      if it is assigned, the parameter content must to be null
	 * @throws CertificateCoreException validate exception
	 */
	@SuppressWarnings("unchecked")
	public void validate(byte[] content, byte[] timeStamp, byte[] hash) throws CertificateCoreException {
		try {
			TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(timeStamp));
			CMSSignedData s = timeStampToken.toCMSSignedData();


			int verified = 0;

			Store<?> certStore = s.getCertificates();
			SignerInformationStore signers = s.getSignerInfos();
			Collection<SignerInformation> c = signers.getSigners();
			Iterator<SignerInformation> it = c.iterator();

			while (it.hasNext()) {
				SignerInformation signer = it.next();
				Collection<?> certCollection = certStore.getMatches(signer.getSID());
				Iterator<?> certIt = certCollection.iterator();
				X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
				SignerInformationVerifier siv = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert);
				if (signer.verify(siv)) {
					verified++;
				}
				cert.getExtension(new ASN1ObjectIdentifier("2.5.29.31")).getExtnValue();
				timeStampToken.validate(siv);
			}

			logger.debug(timeStampMessagesBundle.getString("info.signature.verified", verified));

			//Valida o hash  incluso no carimbo de tempo com hash do arquivo carimbado
			byte[] calculatedHash = null;
			if (content != null) {
				Digest digest = DigestFactory.getInstance().factoryDefault();
				TimeStampTokenInfo info = timeStampToken.getTimeStampInfo();
				ASN1ObjectIdentifier algOID = info.getMessageImprintAlgOID();
				digest.setAlgorithm(algOID.toString());
				calculatedHash = digest.digest(content);
			} else {
				calculatedHash = hash;
			}


			if (Arrays.equals(calculatedHash, timeStampToken.getTimeStampInfo().getMessageImprintDigest())) {
				logger.debug(timeStampMessagesBundle.getString("info.timestamp.hash.ok"));
			} else {
				logger.error(timeStampMessagesBundle.getString("info.timestamp.hash.nok"));
				throw new CertificateCoreException(timeStampMessagesBundle.getString("info.timestamp.hash.nok"));
			}

		} catch (TSPException | IOException | CMSException | OperatorCreationException | CertificateException ex) {
			logger.error(ex.getMessage());
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
