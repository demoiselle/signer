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

package org.demoiselle.signer.timestamp.configuration;

import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TimeOut configurations.
 *
 * @author emerson.saito@serpro.gov.br
 */
public class TimeStampConfig {

	private static final Logger LOGGER = LoggerFactory.getLogger(TimeStampConfig.class);
	private static MessagesBundle timeStampMessagesBundle = new MessagesBundle();

	/**
	 * System key to set timeout for timestamp connector
	 */
	public static final String TIMESTAMP_TIMEOUT = "signer.timestamp.timeout";

	/**
	 * System environment key to set timeout for timestamp connector
	 */
	public static final String ENV_TIMESTAMP_TIMEOUT = "SIGNER_TIMESTAMP_TIMEOUT";

	/**
	 * System key to set how many times replay timestamp connector
	 */
	public static final String TIMESTAMP_CONNECT_REPLAY = "signer.timestamp.connect_replay";

	/**
	 * System environment key to set how many times replay timestamp connector
	 */
	public static final String ENV_TIMESTAMP_CONNECT_REPLAY = "SIGNER_TIMESTAMP_CONNECT_REPLAY";


	public static TimeStampConfig instance = new TimeStampConfig();

	// default is 30 seconds
	private int timeOut = 30000;

	private int connectReplay = 3;

	public static TimeStampConfig getInstance() {
		if (instance == null) {
			instance = new TimeStampConfig();
		}
		return instance;
	}

	private TimeStampConfig() {
		try {
			String varTimeOut = System.getenv(ENV_TIMESTAMP_TIMEOUT);
			if (varTimeOut == null || varTimeOut.isEmpty()) {
				varTimeOut = (String) System.getProperties().get(TIMESTAMP_TIMEOUT);
				if (varTimeOut == null || varTimeOut.isEmpty()) {
					LOGGER.debug("DEFAULT");
					LOGGER.debug(timeStampMessagesBundle.getString("info.timestamp.timeout.value", getTimeOut()));
				} else {
					LOGGER.debug("key");
					setTimeOut(Integer.valueOf(varTimeOut));
				}
			} else {
				LOGGER.debug("ENV");
				setTimeOut(Integer.valueOf(varTimeOut));
			}
		} catch (Exception e) {
			LOGGER.debug(timeStampMessagesBundle.getString("info.timestamp.timeout.value", getTimeOut()));

		}
		try {
			String varConnectReplay = System.getenv(ENV_TIMESTAMP_CONNECT_REPLAY);
			if (varConnectReplay == null || varConnectReplay.isEmpty()) {
				varConnectReplay = (String) System.getProperties().get(TIMESTAMP_CONNECT_REPLAY);
				if (varConnectReplay == null || varConnectReplay.isEmpty()) {
					LOGGER.debug("DEFAULT");
					LOGGER.debug(timeStampMessagesBundle.getString("info.timestamp.connect.replay.value", getConnectReplay()));
				} else {
					LOGGER.debug("key");
					setConnectReplay(Integer.valueOf(varConnectReplay));
				}
			} else {
				LOGGER.debug("ENV");
				setConnectReplay(Integer.valueOf(varConnectReplay));
			}
		} catch (Exception e) {
			LOGGER.debug(timeStampMessagesBundle.getString("info.timestamp.connect.replay.value", getConnectReplay()));

		}
	}

	/**
	 * @return the timeout.
	 */
	public int getTimeOut() {
		return timeOut;
	}

	public void setTimeOut(int parmTimeOut) {
		this.timeOut = parmTimeOut;
		LOGGER.debug(timeStampMessagesBundle.getString("info.timestamp.timeout.value", getTimeOut()));
	}

	public int getConnectReplay() {
		return connectReplay;
	}

	public void setConnectReplay(int connectReplay) {
		this.connectReplay = connectReplay;
		LOGGER.debug(timeStampMessagesBundle.getString("info.timestamp.connect.replay.value", getConnectReplay()));
	}
}
