package org.demoiselle.signer.core.repository;

import java.net.Proxy;
import java.security.NoSuchProviderException;
import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;

import org.demoiselle.signer.core.extension.ICPBR_CRL;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Representa um repositório online que mantem um cache das CRLs consultadas
 * recentemente.
 */
public class CachedOnLineCRLRepository extends OnLineCRLRepository {

	private static ConcurrentHashMap<String, ICPBR_CRL> map = new ConcurrentHashMap<>();

	private final Logger logger = LoggerFactory.getLogger(CachedOnLineCRLRepository.class);
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	public CachedOnLineCRLRepository() {
		super();
	}

	public CachedOnLineCRLRepository(Proxy proxy) {
		super(proxy);
	}

	@Override
	protected ICPBR_CRL getICPBR_CRL(String uRLCRL) throws NoSuchProviderException {
		ICPBR_CRL crl = map.get(uRLCRL);

		if (crl == null) {
			// Se não existir, fazer o download e instalar no mapa
			logger.debug(coreMessagesBundle.getString("info.creating.crl", uRLCRL));
		} else if (crl.getCRL().getNextUpdate().before(new Date())) {
			// Se estiver expirado, atualiza com a CRL mais nova
			logger.info(coreMessagesBundle.getString("info.update.crl"));
		} else {
			// Se existir e for válida, utilizar
			return crl;
		}
		crl = super.getICPBR_CRL(uRLCRL);
		map.put(uRLCRL, crl);
		return crl;
	}

}
