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

package org.demoiselle.signer.policy.engine.asn1.icpb.v2;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;

import org.demoiselle.signer.core.repository.ConfigurationRepo;
import org.demoiselle.signer.policy.engine.asn1.GeneralizedTime;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.engine.exception.PolicyException;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PolicyValidator {

	private static MessagesBundle policyMessagesBundle = new MessagesBundle("messages_policy");
	private static final Logger LOGGER = LoggerFactory.getLogger(PolicyValidator.class);
	private final ConfigurationRepo config = ConfigurationRepo.getInstance();

	private SignaturePolicy sp;
	private String policyName;
	private LPA listOfPolicies;

	public PolicyValidator(SignaturePolicy sp, String policyName) {
		super();
		this.sp = sp;
		this.policyName = policyName;
	}

	public boolean validate() {
		try {
			boolean valid = false;

			Date dateNotBefore = this.sp.getSignPolicyInfo().getSignatureValidationPolicy().getSigningPeriod()
				.getNotBefore().getDate();
			Date dateNotAfter = this.sp.getSignPolicyInfo().getSignatureValidationPolicy().getSigningPeriod()
				.getNotAfter().getDate();

			Date actualDate = new GregorianCalendar().getTime();
			SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy - hh:mm:ss");

			if (actualDate.before(dateNotBefore) || actualDate.after(dateNotAfter)) {
				LOGGER.error(policyMessagesBundle.getString("error.policy.valid.period", sdf.format(dateNotBefore), sdf.format(dateNotAfter)));
				throw new PolicyException(policyMessagesBundle.getString("error.policy.valid.period", sdf.format(dateNotBefore), sdf.format(dateNotAfter)));
			}
			PolicyFactory factory = PolicyFactory.getInstance();

			LPA tempListOfPolicies = null;

			if (policyName.contains("CADES")) {
				tempListOfPolicies = factory.loadLPACAdES();
				listOfPolicies = tempListOfPolicies;
				Date nextUpdate = tempListOfPolicies.getNextUpdate().getDate();
				if (actualDate.after(nextUpdate)) {
					LOGGER.debug(policyMessagesBundle.getString("error.policy.not.updated", sdf.format(nextUpdate)));
					LOGGER.debug(policyMessagesBundle.getString("info.lpa.load.local", config.getLpaPath()));
					tempListOfPolicies = factory.loadLPACAdESLocal();
					if (tempListOfPolicies != null) {
						nextUpdate = tempListOfPolicies.getNextUpdate().getDate();
						if (actualDate.after(nextUpdate)) {
							LOGGER.debug(policyMessagesBundle.getString("error.policy.local.not.updated", config.getLpaPath() + "LPA_CAdES.der", sdf.format(nextUpdate)));
							tempListOfPolicies = factory.loadLPACAdESUrl();
							if (tempListOfPolicies != null) {
								nextUpdate = tempListOfPolicies.getNextUpdate().getDate();
								if (actualDate.after(nextUpdate)) {
									LOGGER.debug(policyMessagesBundle.getString("error.policy.not.updated", sdf.format(nextUpdate)));
								} else {
									listOfPolicies = tempListOfPolicies;
								}
							}
						} else {
							listOfPolicies = tempListOfPolicies;
						}
					} else {
						tempListOfPolicies = factory.loadLPACAdESUrl();
						if (tempListOfPolicies != null) {
							nextUpdate = tempListOfPolicies.getNextUpdate().getDate();
							if (actualDate.after(nextUpdate)) {
								LOGGER.debug(policyMessagesBundle.getString("error.policy.not.updated", sdf.format(nextUpdate)));
							} else {
								listOfPolicies = tempListOfPolicies;
							}
						} else {
							LOGGER.warn(policyMessagesBundle.getString("error.lpa.not.found"));
						}
					}
				}


				for (PolicyInfo policyInfo : listOfPolicies.getPolicyInfos()) {
					if (policyInfo.getPolicyOID().getValue().contentEquals(sp.getSignPolicyInfo().getSignPolicyIdentifier().getValue())) {
						valid = true;
						GeneralizedTime revocationDate = policyInfo.getRevocationDate();
						if (revocationDate != null) {
							LOGGER.error(policyMessagesBundle.getString("error.policy.revocated", sdf.format(revocationDate.getDate())));
							throw new PolicyException(policyMessagesBundle.getString("error.policy.revocated", sdf.format(revocationDate.getDate())));
						}
					}
				}
			} else {
				if (policyName.contains("PADES")) {
					tempListOfPolicies = factory.loadLPAPAdES();
					listOfPolicies = tempListOfPolicies;
					Date nextUpdate = tempListOfPolicies.getNextUpdate().getDate();
					if (actualDate.after(nextUpdate)) {
						LOGGER.debug(policyMessagesBundle.getString("error.policy.not.updated", sdf.format(nextUpdate)));
						LOGGER.debug(policyMessagesBundle.getString("info.lpa.load.local"));
						tempListOfPolicies = factory.loadLPAPAdESLocal();
						if (tempListOfPolicies != null) {
							nextUpdate = tempListOfPolicies.getNextUpdate().getDate();
							if (actualDate.after(nextUpdate)) {
								LOGGER.debug(policyMessagesBundle.getString("error.policy.local.not.updated", config.getLpaPath() + "LPA_PAdES.der", sdf.format(nextUpdate)));
								tempListOfPolicies = factory.loadLPAPAdESUrl();
								if (tempListOfPolicies != null) {
									nextUpdate = tempListOfPolicies.getNextUpdate().getDate();
									if (actualDate.after(nextUpdate)) {
										LOGGER.debug(policyMessagesBundle.getString("error.policy.not.updated", sdf.format(nextUpdate)));
									} else {
										listOfPolicies = tempListOfPolicies;
									}
								}
							} else {
								listOfPolicies = tempListOfPolicies;
							}
						} else {
							tempListOfPolicies = factory.loadLPAPAdESUrl();
							if (tempListOfPolicies != null) {
								nextUpdate = tempListOfPolicies.getNextUpdate().getDate();
								if (actualDate.after(nextUpdate)) {
									LOGGER.debug(policyMessagesBundle.getString("error.policy.not.updated", sdf.format(nextUpdate)));
								} else {
									listOfPolicies = tempListOfPolicies;
								}
							} else {
								LOGGER.warn(policyMessagesBundle.getString("error.lpa.not.found"));
							}
						}
					}
					for (PolicyInfo policyInfo : listOfPolicies.getPolicyInfos()) {
						if (policyInfo.getPolicyOID().getValue().contentEquals(sp.getSignPolicyInfo().getSignPolicyIdentifier().getValue())) {
							valid = true;
							GeneralizedTime revocationDate = policyInfo.getRevocationDate();
							if (revocationDate != null) {
								LOGGER.error(policyMessagesBundle.getString("error.policy.revocated", sdf.format(revocationDate.getDate())));
								throw new PolicyException(policyMessagesBundle.getString("error.policy.revocated", sdf.format(revocationDate.getDate())));
							}
						}
					}
				} else {
					if (policyName.contains("XADES")) {
						LOGGER.error(policyMessagesBundle.getString("error.policy.not.recognized", policyName));
						throw new PolicyException(policyMessagesBundle.getString("error.policy.not.recognized", policyName));

					} else {
						LOGGER.error(policyMessagesBundle.getString("error.policy.not.recognized", policyName));
						throw new PolicyException(policyMessagesBundle.getString("error.policy.not.recognized", policyName));
					}
				}
			}

			return valid;
		} catch (Exception ex) {
			throw new PolicyException(ex.getMessage(), ex);
		}
	}
}
