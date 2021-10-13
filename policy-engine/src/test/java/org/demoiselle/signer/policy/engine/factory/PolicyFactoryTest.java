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

package org.demoiselle.signer.policy.engine.factory;

import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PolicyFactoryTest {

	private static final Logger logger = LoggerFactory.getLogger(PolicyFactoryTest.class);

	//@Test
	public void testLoadPolicy() {
		PolicyFactory factory = PolicyFactory.getInstance();
		Policies[] policies = PolicyFactory.Policies.values();

		for (Policies policy : policies) {
			// TODO - falta implentar policy para XADES
			if (policy.toString().contains("CADES") || policy.toString().contains("PADES")) {
				logger.info(factory.loadPolicy(policy).toString());
			}
		}
	}

	/**
	 * Test of loadLPA method, of class PolicyFactory.
	 */
	@SuppressWarnings("deprecation")
	//@Test
	public void testLoadLPA() {
		PolicyFactory factory = PolicyFactory.getInstance();
		logger.info(factory.loadLPA().toString());
	}

	/**
	 * Test of loadLPAv2 method, of class PolicyFactory.
	 */
	@SuppressWarnings("deprecation")
	//@Test
	public void testLoadLPAv2() {
		PolicyFactory factory = PolicyFactory.getInstance();
		logger.info(factory.loadLPAv2().toString());
	}

	@Test
	public void testLoadCades() {
		PolicyFactory factory = PolicyFactory.getInstance();
		logger.info(factory.loadLPACAdES().toString());
	}
}
