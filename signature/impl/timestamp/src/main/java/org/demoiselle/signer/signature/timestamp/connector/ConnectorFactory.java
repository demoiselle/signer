package org.demoiselle.signer.signature.timestamp.connector;

import org.demoiselle.signer.signature.timestamp.enumeration.ConnectionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConnectorFactory {

    private static final Logger logger = LoggerFactory.getLogger(ConnectorFactory.class);

    public static Connector buildConnector(ConnectionType connectionType) {

        switch (connectionType) {

            case HTTP: {
                logger.info("Retornando a conexao HTTP da fabrica");
                return new HttpConnector();
            }

            case SOCKET: {
                logger.info("Retornando a conexao Socket da fabrica");
                return new SocketConnector();
            }

            default: {
                logger.info("Retornando a conexao padrao da fábrica");
                return new SocketConnector();
            }
        }
    }

    private ConnectorFactory() {

    }
}
