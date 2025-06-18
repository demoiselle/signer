# How to use

```java
KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
loader.setCallbackHandler(new PinHandler("",""));
KeyStore keyStore = loader.getKeyStore();
File file = new File(System.getProperty("user.dir") + "/document.xml");
String alias = "";		


Signer signer = new XMLSigner();
signer.setCertificateChain(keyStore.getCertificateChain(alias));
Document resp = signer.signEnveloped(true, file.getAbsolutePath());

TransformerFactory tf = TransformerFactory.newInstance();
Transformer trans = tf.newTransformer();
trans.transform(new DOMSource(resp), new StreamResult(System.out));
```
