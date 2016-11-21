package org.demoiselle.signer.signature.timestamp.connector;

import java.io.InputStream;

/**
 *
 * @author 07721825741
 */
public class HttpConnector implements Connector {

    @Override
    public InputStream connect(byte[] content) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setHostname(String hostname) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setPort(int port) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void close() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
