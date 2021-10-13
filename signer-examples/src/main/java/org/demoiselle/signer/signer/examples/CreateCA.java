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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.demoiselle.signer.core.util.Base64Utils;
import sun.security.provider.X509Factory;

public class CreateCA {

	// http://stackoverflow.com/questions/18633273/correctly-creating-a-new-certificate-with-an-intermediate-certificate-using-boun
	// http://stackoverflow.com/questions/31618568/how-can-i-create-a-ca-root-certificate-with-bouncy-castle
	public static void main(String[] args) throws IOException, OperatorCreationException, NoSuchAlgorithmException {

		// ---------------------- CA Creation ----------------------
		// System.out.println("Generating Keys");
		KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
		rsa.initialize(1024);
		KeyPair kp = rsa.generateKeyPair();

		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.YEAR, 100);

		// System.out.println("Getting data");
		byte[] pk = kp.getPublic().getEncoded();
		SubjectPublicKeyInfo bcPk = SubjectPublicKeyInfo.getInstance(pk);

		// System.out.println("Creating cert");
		X509v1CertificateBuilder certGen = new X509v1CertificateBuilder(new X500Name("CN=CA Cert"), BigInteger.ONE,
				new Date(), cal.getTime(), new X500Name("CN=CA Cert"), bcPk);

		X509CertificateHolder certHolder = certGen
				.build(new JcaContentSignerBuilder("SHA1withRSA").build(kp.getPrivate()));

		StringBuffer s = new StringBuffer();

		s.append(X509Factory.BEGIN_CERT + "\n");
		s.append(Base64Utils.base64Encode(certHolder.getEncoded()) + "\n");
		s.append(X509Factory.END_CERT);

		saveFile(s.toString().getBytes());

		// ---------------------- ISSUER Creation ----------------------

	}

	public static void saveFile(byte[] data) throws IOException {
		FileOutputStream out = new FileOutputStream(new File("/tmp/ca.cer"));
		out.write(data);
		out.close();
	}

}
