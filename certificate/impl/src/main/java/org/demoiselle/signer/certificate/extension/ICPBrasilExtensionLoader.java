/*
 * Demoiselle Framework
 * Copyright (C) 2010 SERPRO
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
package org.demoiselle.signer.certificate.extension;

import org.demoiselle.signer.certificate.IOIDExtensionLoader;
import org.demoiselle.signer.certificate.exception.CertificateCoreException;

import java.lang.reflect.Field;
import java.security.cert.X509Certificate;

public class ICPBrasilExtensionLoader implements IOIDExtensionLoader {

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
                    case NOME:
                        keyValue = cert.getNome();
                        break;
                    case NOME_RESPONSAVEL_PESSOA_JURIDICA:
                        if (cert.hasCertificatePJ()) {
                            keyValue = cert.getICPBRCertificatePJ().getNomeResponsavel();
                        } else {
                            keyValue = "";
                        }
                        break;
                    case EMAIL:
                        keyValue = cert.getEmail();
                        break;
                    case DATA_NASCIMENTO:
                        if (cert.hasCertificatePF()) {
                            keyValue = cert.getICPBRCertificatePF().getDataNascimento();
                        } else {
                            if (cert.hasCertificatePJ()) {
                                keyValue = cert.getICPBRCertificatePJ().getDataNascimento();
                            } else {
                                if (cert.hasCertificateEquipment()) {
                                    keyValue = cert.getICPBRCertificateEquipment().getDataNascimento().toString();
                                } else {
                                    keyValue = "";
                                }
                            }
                        }
                        break;
                    case NUMERO_IDENTIDADE:
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
                    case ORGAO_EXPEDIDOR_IDENTIDADE:
                        if (cert.hasCertificatePF()) {
                            keyValue = cert.getICPBRCertificatePF().getOrgaoExpedidorRg();
                        } else {
                            if (cert.hasCertificatePJ()) {
                                keyValue = cert.getICPBRCertificatePJ().getOrgaoExpedidorRg();
                            } else {
                                if (cert.hasCertificateEquipment()) {
                                    keyValue = cert.getICPBRCertificateEquipment().getOrgaoExpedidorRg();
                                } else {
                                    keyValue = "";
                                }
                            }
                        }
                        break;
                    case UF_ORGAO_EXPEDIDOR_IDENTIDADE:
                        if (cert.hasCertificatePF()) {
                            keyValue = cert.getICPBRCertificatePF().getUfExpedidorRg();
                        } else {
                            if (cert.hasCertificatePJ()) {
                                keyValue = cert.getICPBRCertificatePJ().getUfExpedidorRg();
                            } else {
                                if (cert.hasCertificateEquipment()) {
                                    keyValue = cert.getICPBRCertificateEquipment().getUfExpedidorRg();
                                } else {
                                    keyValue = "";
                                }
                            }
                        }
                        break;
                    case NUMERO_TITULO_ELEITOR:
                        if (cert.hasCertificatePF()) {
                            keyValue = cert.getICPBRCertificatePF().getTituloEleitor();
                        } else {
                            keyValue = "";
                        }
                        break;
                    case ZONA_TITULO_ELEITOR:
                        if (cert.hasCertificatePF()) {
                            keyValue = cert.getICPBRCertificatePF().getZonaTituloEleitor();
                        } else {
                            keyValue = "";
                        }
                        break;
                    case SECAO_TITULO_ELEITOR:
                        if (cert.hasCertificatePF()) {
                            keyValue = cert.getICPBRCertificatePF().getSecaoTituloEleitor();
                        } else {
                            keyValue = "";
                        }
                        break;
                    case MUNICIPIO_TITULO_ELEITOR:
                        if (cert.hasCertificatePF()) {
                            keyValue = cert.getICPBRCertificatePF().getMunicipioTituloEleitor();
                        } else {
                            keyValue = "";
                        }
                        break;
                    case UF_TITULO_ELEITOR:
                        if (cert.hasCertificatePF()) {
                            keyValue = cert.getICPBRCertificatePF().getUfTituloEleitor();
                        } else {
                            keyValue = "";
                        }
                        break;

                    case NOME_EMPRESARIAL:
                        if (cert.hasCertificateEquipment()) {
                            keyValue = cert.getICPBRCertificateEquipment().getNomeEmpresarial();
                        } else {
                            keyValue = "";
                        }
                        break;
                    case TIPO_CERTIFICADO:
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
                    case NIVEL_CERTIFICADO:
                        keyValue = cert.getNivelCertificado();
                        break;

                    default:
                        throw new CertificateCoreException(annotation.type() + " Not Implemented");
                }

                try {
                    field.setAccessible(true);
                    field.set(object, keyValue);
                } catch (Exception e) {
                    throw new CertificateCoreException("Error on load value in field " + field.getName(), e);
                }
            } catch (Exception e) {
                throw new CertificateCoreException("Error trying get Keyvalue " + annotation.type(), e);
            }
        }
    }
}
