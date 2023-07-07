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

package org.demoiselle.signer.core.extension;

import org.demoiselle.signer.core.IOIDExtensionLoader;
import org.demoiselle.signer.core.exception.CertificateCoreException;
import org.demoiselle.signer.core.util.MessagesBundle;

import java.lang.reflect.Field;
import java.security.cert.X509Certificate;

/**
 * Load X.509 Extension OIDs for ICP-Brasil's extensions.
 *
 * @see ICPBrasilExtensionType
 */
public class ICPBrasilExtensionLoader implements IOIDExtensionLoader {

	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	@Override
	public void load(Object object, Field field, X509Certificate x509) {
		if (field.isAnnotationPresent(ICPBrasilExtension.class)) {
			ICPBrasilExtension annotation = field.getAnnotation(ICPBrasilExtension.class);

			Object keyValue;
			try {

				BasicCertificate cert = new BasicCertificate(x509);

				switch (annotation.type()) {
					case CPF:
						if (cert.hasCertificatePF()) {
							keyValue = cert.getICPBRCertificatePF().getCPF();
						} else {
							keyValue = "";
						}
						break;
					case CNPJ:
						if (cert.hasCertificatePJ()) {
							keyValue = cert.getICPBRCertificatePJ().getCNPJ();
						} else {
							if (cert.hasCertificateEquipment()) {
								keyValue = cert.getICPBRCertificateEquipment().getCNPJ();
							} else {
								keyValue = "";
							}
						}
						break;
					case PIS_PASEP:
						if (cert.hasCertificatePF()) {
							keyValue = cert.getICPBRCertificatePF().getNis();
						} else {
							if (cert.hasCertificatePJ()) {
								keyValue = cert.getICPBRCertificatePJ().getNis();
							} else {
								if (cert.hasCertificateEquipment()) {
									keyValue = cert.getICPBRCertificateEquipment().getNis();
								} else {
									keyValue = "";
								}
							}
						}
						break;
					case NIS:
						if (cert.hasCertificatePF()) {
							keyValue = cert.getICPBRCertificatePF().getNis();
						} else {
							if (cert.hasCertificatePJ()) {
								keyValue = cert.getICPBRCertificatePJ().getNis();
							} else {
								if (cert.hasCertificateEquipment()) {
									keyValue = cert.getICPBRCertificateEquipment().getNis();
								} else {
									keyValue = "";
								}
							}
						}
						break;
					case CEI:
						if (cert.hasCertificatePF()) {
							keyValue = cert.getICPBRCertificatePF().getCEI();
						} else {
							if (cert.hasCertificatePJ()) {
								keyValue = cert.getICPBRCertificatePJ().getCEI();
							} else {
								keyValue = "";
							}
						}
						break;
					case CEI_PESSOA_FISICA:
						if (cert.hasCertificatePF()) {
							keyValue = cert.getICPBRCertificatePF().getCEI();
						} else {
							keyValue = "";
						}
						break;
					case CEI_PESSOA_JURIDICA:
						if (cert.hasCertificatePJ()) {
							keyValue = cert.getICPBRCertificatePJ().getCEI();
						} else {
							keyValue = "";
						}
						break;
					case NAME:
						keyValue = cert.getName();
						break;
					case NAME_RESPONSIBLE_PESSOA_JURIDICA:
						if (cert.hasCertificatePJ()) {
							keyValue = cert.getICPBRCertificatePJ().getResponsibleName();
						} else {
							keyValue = "";
						}
						break;
					case CPF_RESPONSIBLE_PESSOA_JURIDICA:
						if (cert.hasCertificatePJ()) {
							keyValue = cert.getICPBRCertificatePJ().getResponsibleCPF();
						} else {
							keyValue = "";
						}
						break;
					case EMAIL:
						keyValue = cert.getEmail();
						break;
					case BIRTH_DATE:
						if (cert.hasCertificatePF()) {
							keyValue = cert.getICPBRCertificatePF().getBirthDate();
						} else {
							if (cert.hasCertificatePJ()) {
								keyValue = cert.getICPBRCertificatePJ().getBirthDate();
							} else {
								if (cert.hasCertificateEquipment()) {
									if (cert.getICPBRCertificateEquipment().getBirthDate() != null) {
										keyValue = cert.getICPBRCertificateEquipment().getBirthDate().toString();
									}else {
										keyValue = "";
									}
										
									
								} else {
									keyValue = "";
								}
							}
						}
						break;
					case ID_NUMBER:
						if (cert.hasCertificatePF()) {
							keyValue = cert.getICPBRCertificatePF().getRg();
						} else {
							if (cert.hasCertificatePJ()) {
								keyValue = cert.getICPBRCertificatePJ().getRg();
							} else {
								if (cert.hasCertificateEquipment()) {
									keyValue = cert.getICPBRCertificateEquipment().getRg();
								} else {
									keyValue = "";
								}
							}
						}
						break;
					case IDENTITY_DISPATCHER:
						if (cert.hasCertificatePF()) {
							keyValue = cert.getICPBRCertificatePF().getIssuingAgencyRg();
						} else {
							if (cert.hasCertificatePJ()) {
								keyValue = cert.getICPBRCertificatePJ().getIssuingAgencyRg();
							} else {
								if (cert.hasCertificateEquipment()) {
									keyValue = cert.getICPBRCertificateEquipment().getIssuingAgencyRg();
								} else {
									keyValue = "";
								}
							}
						}
						break;
					case UF_IDENTITY_DISPATCHER:
						if (cert.hasCertificatePF()) {
							keyValue = cert.getICPBRCertificatePF().getUfIssuingAgencyRg();
						} else {
							if (cert.hasCertificatePJ()) {
								keyValue = cert.getICPBRCertificatePJ().getUfIssuingAgencyRg();
							} else {
								if (cert.hasCertificateEquipment()) {
									keyValue = cert.getICPBRCertificateEquipment().getUfIssuingAgencyRg();
								} else {
									keyValue = "";
								}
							}
						}
						break;
					case NUMBER_ELECTORAL_DOCUMENT:
						if (cert.hasCertificatePF()) {
							keyValue = cert.getICPBRCertificatePF().getElectoralDocument();
						} else {
							keyValue = "";
						}
						break;
					case ZONE_ELECTORAL_DOCUMENT:
						if (cert.hasCertificatePF()) {
							keyValue = cert.getICPBRCertificatePF().getZoneElectoralDocument();
						} else {
							keyValue = "";
						}
						break;
					case SECTION_ELECTORAL_DOCUMENT:
						if (cert.hasCertificatePF()) {
							keyValue = cert.getICPBRCertificatePF().getSectionElectoralDocument();
						} else {
							keyValue = "";
						}
						break;
					case CITY_ELECTORAL_DOCUMENT:
						if (cert.hasCertificatePF()) {
							keyValue = cert.getICPBRCertificatePF().getCityElectoralDocument();
						} else {
							keyValue = "";
						}
						break;
					case UF_ELECTORAL_DOCUMENT:
						if (cert.hasCertificatePF()) {
							keyValue = cert.getICPBRCertificatePF().getUFElectoralDocument();
						} else {
							keyValue = "";
						}
						break;

					case BUSINESS_NAME:
						if (cert.hasCertificateEquipment()) {
							keyValue = cert.getICPBRCertificateEquipment().getCorporateName();
						} else {
							keyValue = "";
						}
						break;
					case CERTIFICATE_TYPE:
						if (cert.hasCertificatePF()) {
							keyValue = "PF";
						} else {
							if (cert.hasCertificatePJ()) {
								keyValue = "PJ";
							} else {
								if (cert.hasCertificateEquipment()) {
									keyValue = "EA";
								} else {
									keyValue = "";
								}
							}
						}
						break;
					case CERTIFICATE_LEVEL:
						keyValue = cert.getCertificateLevel();
						break;

					default:
						throw new CertificateCoreException(coreMessagesBundle.getString("error.field.not.implemented", annotation.type()));
				}

				try {
					field.setAccessible(true);
					field.set(object, keyValue);
				} catch (Exception e) {
					throw new CertificateCoreException(coreMessagesBundle.getString("error.load.value.field", field.getName()), e);
				}
			} catch (Exception e) {
				throw new CertificateCoreException(coreMessagesBundle.getString("error.get.value.field", field.getName()), e);
			}
		}
	}
}
