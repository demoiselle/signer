package org.demoiselle.signer.signature.timestamp.connector;

import java.io.InputStream;

/**
 *
 * @author 07721825741
 */
public interface Connector {

    InputStream connect(byte[] content);

    void close();

    void setHostname(String hostname);

    void setPort(int port);
}
