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

package org.demoiselle.signer.core.timestamp;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.ServiceLoader;
import java.util.Set;

import org.demoiselle.signer.core.Priority;
import org.demoiselle.signer.core.exception.CertificateCoreException;
import org.demoiselle.signer.core.util.MessagesBundle;

/**
 * Recover a TimeStampGenerator service
 */
public final class TimeStampGeneratorSelector implements Serializable {

	// TODO Criar Exception
	private static final long serialVersionUID = 1L;
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	private static ServiceLoader<TimeStampGenerator> loader;

	private TimeStampGeneratorSelector() {
	}

	public static TimeStampGenerator selectReference() {
		TimeStampGenerator selected = selectClass(getOptions());
		return selected;
	}

	private static Collection<TimeStampGenerator> getOptions() {
		Set<TimeStampGenerator> result = new HashSet<TimeStampGenerator>();

		loader = ServiceLoader.load(TimeStampGenerator.class);
		for (TimeStampGenerator clazz : loader) {
			result.add(clazz);
		}
		return result;
	}

	/**
	 * @param options Collection<TimeStampGenerator>
	 * @return
	 */
	private static TimeStampGenerator selectClass(Collection<TimeStampGenerator> options) {
		TimeStampGenerator selected = null;

		for (TimeStampGenerator option : options) {
			if (selected == null || getPriority(option) < getPriority(selected)) {
				selected = option;
			}
		}

		if (selected != null) {
			performAmbiguityCheck(TimeStampGenerator.class, selected, options);
		}

		return selected;
	}

	/**
	 * verify if have a @Priotity annotation
	 *
	 * @param clazz
	 * @return
	 */
	private static int getPriority(TimeStampGenerator clazz) {
		Priority priority = clazz.getClass().getAnnotation(Priority.class);

		// FIXME Seria throw new ...?
		if (priority == null) {
			new CertificateCoreException(coreMessagesBundle.getString("error.priority.null", clazz.getClass().getName()));
		}

		return priority != null
			? priority.value()
			: Priority.MAX_PRIORITY;
	}

	/**
	 * verify if have a @Priotity ambiguity annotation
	 *
	 * @param type
	 * @param selected
	 * @param options
	 */
	private static <T> void performAmbiguityCheck(Class<T> type, TimeStampGenerator selected, Collection<TimeStampGenerator> options) {
		int selectedPriority = getPriority(selected);

		List<TimeStampGenerator> ambiguous = new ArrayList<TimeStampGenerator>();

		for (TimeStampGenerator option : options) {
			if (selected != option && selectedPriority == getPriority(option)) {
				ambiguous.add(option);
			}
		}

		if (!ambiguous.isEmpty()) {
			ambiguous.add(selected);

			throw new CertificateCoreException(coreMessagesBundle.getString("error.priority.ambiguous", selected.getClass().getCanonicalName()));
		}
	}

}
