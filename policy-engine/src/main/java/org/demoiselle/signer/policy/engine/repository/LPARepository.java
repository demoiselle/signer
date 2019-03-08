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
package org.demoiselle.signer.policy.engine.repository;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import org.apache.log4j.Logger;
import org.demoiselle.signer.core.repository.Configuration;
import org.demoiselle.signer.core.util.Downloads;
import org.demoiselle.signer.policy.engine.util.MessagesBundle;

/**
 * 
 * Class to persist LPA file on local directory
 *
 */
public class LPARepository {
	
	private static MessagesBundle policyMessagesBundle = new MessagesBundle("messages_policy");
	private final static Logger LOGGER = Logger.getLogger(LPARepository.class.getName());
	
	/**
	 * 
	 * to save file on user local directory 
	 * 
	 * @param urlConLPA Url for get the LPA file 
	 * @param lpaName the name of file to be saved
	 * @return true if file was saved
	 */
	
	public static boolean saveLocalLPA(final String urlConLPA, final String lpaName) {
		
		try {
			Configuration config = Configuration.getInstance();
			Path pathLPA = Paths.get(config.getLpaPath());
			Path pathLPAFile = Paths.get(config.getLpaPath(), lpaName);
			
			if (!Files.isDirectory(pathLPA)) {
				LOGGER.info(policyMessagesBundle.getString("warn.lpa.dir.not.found", pathLPA));				
				Files.createDirectories(pathLPA);
			}
			InputStream is = Downloads.getInputStreamFromURL(urlConLPA);	
			Files.copy(is, pathLPAFile, StandardCopyOption.REPLACE_EXISTING);
			is.close();
			return true;
		} catch (FileNotFoundException e) {
			LOGGER.error(e.getMessage());
			return false;
		} catch (IOException e) {
			LOGGER.error(e.getMessage());
			return false;
		}		
	}	
	
}




