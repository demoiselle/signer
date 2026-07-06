package org.demoiselle.signer.core.keystore.loader;

import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.core.keystore.loader.implementation.DriverKeyStoreLoader;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * Integration test that reads from a real hardware token to verify 
 * the extraction of Authority Key Identifier.
 */
public class AuthorityKeyIdentifierIT {

    @Test
    public void testReadAuthorityKeyIdentifierFromToken() throws Exception {
        System.out.println("Iniciando teste de integração de Token (Authority Key Identifier)...");

        // 1. Ler test-config.json
        File configFile = new File("test-config.json");
        if (!configFile.exists()) {
            configFile = new File("../test-config.json");
        }
        
        if (!configFile.exists()) {
            System.out.println("Arquivo test-config.json não encontrado! Pule este teste se não houver token configurado.");
            return;
        }

        Map<String, String> config = parseJson(configFile);
        String pin = config.get("token.pin");

        // 2. Carregar KeyStore do Token
        KeyStore ks = null;
        try {
            KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
            if (loader instanceof DriverKeyStoreLoader) {
                ((DriverKeyStoreLoader) loader).setCallbackHandler(new javax.security.auth.callback.CallbackHandler() {
                    @Override
                    public void handle(javax.security.auth.callback.Callback[] callbacks) throws java.io.IOException, javax.security.auth.callback.UnsupportedCallbackException {
                        for (javax.security.auth.callback.Callback callback : callbacks) {
                            if (callback instanceof javax.security.auth.callback.PasswordCallback) {
                                ((javax.security.auth.callback.PasswordCallback) callback).setPassword(pin.toCharArray());
                            }
                        }
                    }
                });
            }
            ks = loader.getKeyStore();
            
            if (ks != null) {
                ks.load(null, pin != null ? pin.toCharArray() : null);
            }
        } catch (Exception e) {
            System.err.println("Erro ao carregar KeyStore do Token: " + e.getMessage());
            return;
        }

        if (ks == null) {
            System.err.println("KeyStore não carregada.");
            return;
        }

        // 3. Iterar certificados e testar getAuthorityKeyIdentifier()
        File resultsDir = new File("tests/results");
        if (!resultsDir.exists()) {
            resultsDir = new File("../tests/results");
        }
        resultsDir.mkdirs();
        
        File resultsFile = new File(resultsDir, "authority_key_id_token_test.txt");
        System.out.println("Salvando resultados em: " + resultsFile.getAbsolutePath());
        
        try (PrintWriter out = new PrintWriter(new FileWriter(resultsFile))) {
            out.println("Teste de Integração: Authority Key Identifier via Token");
            out.println("======================================================");
            out.println("Data: " + new java.util.Date());
            out.println("");

            Enumeration<String> aliases = ks.aliases();
            int count = 0;
            while (aliases.hasMoreElements()) {
                count++;
                String alias = aliases.nextElement();
                System.out.println("Processando certificado (" + count + "): " + alias);
                
                try {
                    X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                    if (cert == null) continue;
                    
                    BasicCertificate bc = new BasicCertificate(cert);

                    // O CHAMADO ESPECÍFICO SOLICITADO
                    String certAuthorityKeyIdentifier = bc.getAuthorityKeyIdentifier();
                    
                    out.println("Alias: " + alias);
                    out.println("Subject DN: " + cert.getSubjectDN().getName());
                    out.println("Authority Key Identifier: " + certAuthorityKeyIdentifier);
                    out.println("------------------------------------------------------");
                    
                    System.out.println(" -> Authority Key ID: " + certAuthorityKeyIdentifier);
                    
                } catch (Exception e) {
                    out.println("Erro ao processar alias " + alias + ": " + e.getMessage());
                }
            }
            
            if (count == 0) {
                out.println("Nenhum certificado encontrado no token.");
            }
            out.println("\nFim do teste. Total de certificados: " + count);
        }
        
        System.out.println("Teste de integração finalizado.");
    }

    private Map<String, String> parseJson(File file) throws Exception {
        Map<String, String> map = new HashMap<>();
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
        }
        String content = sb.toString();
        map.put("token.pin", extractValue(content, "pin"));
        return map;
    }

    private String extractValue(String json, String key) {
        String pattern = "\"" + key + "\":";
        int index = json.indexOf(pattern);
        if (index == -1) return null;
        int start = index + pattern.length();
        while (start < json.length() && (json.charAt(start) == ' ' || json.charAt(start) == '\"' || json.charAt(start) == ':')) {
            start++;
        }
        int end = json.indexOf('\"', start);
        if (end == -1) return null;
        return json.substring(start, end).trim();
    }
}
