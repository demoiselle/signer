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

package org.demoiselle.signer.core;

import java.io.File;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

import org.demoiselle.signer.core.exception.CertificateCoreException;
import org.demoiselle.signer.core.exception.CertificateValidatorCRLException;
import org.demoiselle.signer.core.exception.CertificateValidatorException;
import org.demoiselle.signer.core.repository.ConfigurationRepo;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.core.validator.CRLValidator;
import org.demoiselle.signer.core.validator.PeriodValidator;

/**
 * Methods to build, initialize and validate a {@link X509Certificate}.
 */
public class CertificateManager {

	private X509Certificate x509;
	private Collection<IValidator> validators;

	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	/**
	 * @param x509 java.security.cert.X509Certificate
	 * @throws CertificateValidatorException exception
	 */
	public CertificateManager(X509Certificate x509) throws CertificateValidatorException {
		this(x509, true);
	}

	/**
	 * @param x509       java.security.cert.X509Certificate
	 * @param validators Array of {@link IValidator}
	 * @throws CertificateValidatorException exception
	 */
	public CertificateManager(X509Certificate x509, IValidator... validators) throws CertificateValidatorException {
		this(x509, true, validators);
	}

	/**
	 * @param pinNumber  personal id number
	 * @param validators Array of {@link IValidator}
	 * @throws CertificateValidatorException exception
	 */
	public CertificateManager(String pinNumber, IValidator... validators) throws CertificateValidatorException {
		this(pinNumber, true, validators);
	}

	/**
	 * @param fileX509   a file that contains a java.security.cert.X509Certificate
	 * @param validators Array of {@link IValidator}
	 * @throws CertificateValidatorException exception
	 */
	public CertificateManager(File fileX509, IValidator... validators) throws CertificateValidatorException {
		this(fileX509, true, validators);
	}

	/**
	 * @param x509                  java.security.cert.X509Certificate
	 * @param loadDefaultValidators TRUE or FALSE to call this method
	 * @param validators            Array of {@link IValidator}
	 * @throws CertificateValidatorException exception
	 */
	public CertificateManager(X509Certificate x509, boolean loadDefaultValidators, IValidator... validators) throws CertificateValidatorException {
		this.init(x509, loadDefaultValidators, validators);
	}

	/**
	 * @param pinNumber             personal id number
	 * @param loadDefaultValidators TRUE or FALSE to call this method
	 * @param validators            Array of {@link IValidator}
	 * @throws CertificateValidatorException exception
	 */
	public CertificateManager(String pinNumber, boolean loadDefaultValidators, IValidator... validators) throws CertificateValidatorException {
		CertificateLoader loader = new CertificateLoaderImpl();
		X509Certificate x509 = loader.loadFromToken(pinNumber);
		this.init(x509, loadDefaultValidators, validators);
	}

	/**
	 * @param fileX509              a file that contains a java.security.cert.X509Certificate
	 * @param loadDefaultValidators TRUE or FALSE to call this method
	 * @param validators            Array of {@link IValidator}
	 * @throws CertificateValidatorException exception
	 */
	public CertificateManager(File fileX509, boolean loadDefaultValidators, IValidator... validators) throws CertificateValidatorException {
		CertificateLoader loader = new CertificateLoaderImpl();
		X509Certificate x509 = loader.load(fileX509);
		this.init(x509, loadDefaultValidators, validators);
	}

	/**
	 * @param x509                  java.security.cert.X509Certificate
	 * @param loadDefaultValidators TRUE or FALSE to call this method
	 * @param validators            Array of {@link IValidator}
	 * @throws CertificateValidatorException when not possible to validate certificate
	 */
	private void init(X509Certificate x509, boolean loadDefaultValidators, IValidator... validators) throws CertificateValidatorException, CertificateValidatorCRLException {
		this.x509 = x509;
		this.validators = new ArrayList<>();

		if (loadDefaultValidators) {
			loadDefaultValidators();
		}

		for (IValidator validator : validators) {
			this.validators.add(validator);
		}

		for (IValidator validator : this.validators) {
			validator.validate(x509);
		}
	}

	/**
	 * Load a {@link X509Certificate}.
	 *
	 * @param object destiny of load operation
	 */
	public void load(Object object) {
		Field[] fields = object.getClass().getDeclaredFields();
		for (Field field : fields) {
			for (Annotation annotation : field.getAnnotations()) {
				if (annotation.annotationType().isAnnotationPresent(OIDExtension.class)) {
					OIDExtension oid = annotation.annotationType().getAnnotation(OIDExtension.class);

					Class<? extends IOIDExtensionLoader> loaderClass = oid.loader();
					try {
						IOIDExtensionLoader loader = loaderClass.newInstance();
						loader.load(object, field, x509);
					} catch (IllegalAccessException | InstantiationException e) {
						throw new CertificateCoreException(coreMessagesBundle.getString("error.initialize.attribute", field.getName()), e);
					}
				}
			}
		}
	}

	/**
	 * New Instance for a class
	 *
	 * @param <T>   Type parameter for returned instance
	 * @param clazz class to be instantiated
	 * @return new instance of class
	 */
	public <T> T load(Class<T> clazz) {
		T object;
		try {
			object = clazz.newInstance();
		} catch (IllegalAccessException | InstantiationException e) {
			throw new CertificateCoreException(coreMessagesBundle.getString("error.new.instance", clazz.getName()), e);
		}
		load(object);
		return object;
	}

	/**
	 * Add {@link PeriodValidator} and {@link CRLValidator}
	 */
	private void loadDefaultValidators() {
		validators.add(new PeriodValidator());
		if (ConfigurationRepo.getInstance().isValidateLCR()) {
			validators.add(new CRLValidator());
		}
	}
}
