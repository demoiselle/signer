# How to use

```javascript
KeyStore keyStore = null;
		
KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
loader.setCallbackHandler(new PinHandler("",""));
keyStore = loader.getKeyStore();
String fileName = "/tmp/teste.xml";
String alias = "";
		
try {
  createXMLtoSign();
	XMLSigner xades = new XMLSigner();
	alias = new CryptoCommand().getAlias("", keyStore);
	xades.setAlias(alias);
	xades.setKeyStore(keyStore);
	//xades.setPolicyId("2.16.76.1.7.1.6.2.4");
	Document doc = xades.sign(fileName);
			
	String signedFile = fileName.replaceFirst(".xml$", "_signed.xml");
	OutputStream os = new FileOutputStream(signedFile);
	TransformerFactory tf = TransformerFactory.newInstance();
	Transformer trans = tf.newTransformer();
	trans.transform(new DOMSource(doc), new StreamResult(os));
			
} catch (ParserConfigurationException e) {
	e.printStackTrace();
} catch (TransformerException e) {
  e.printStackTrace();
} catch (Throwable e) {
  e.printStackTrace();
}
    ```
