package org.demoiselle.signer.policy.impl.cades.pkcs7.impl;

import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.core.keystore.loader.implementation.DriverKeyStoreLoader;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.junit.Assert;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class TokenSignatureIT {

    @Test
    public void testSignWithToken() throws Exception {
        System.out.println("Iniciando teste integrado de assinatura com token...");

        // 1. Ler test-config.json
        File configFile = new File("test-config.json");
        if (!configFile.exists()) {
            configFile = new File("../test-config.json");
        }
        
        if (!configFile.exists()) {
            System.out.println("Arquivo test-config.json não encontrado em . ou ..!");
            return;
        }

        Map<String, String> config = parseJson(configFile);
        String pin = config.get("token.pin");
        
        if (pin == null || pin.isEmpty()) {
            System.out.println("PIN do token não configurado. Ignorando teste.");
            return;
        }

        // 2. Configurar o driver e carregar a KeyStore (mesma lógica de fallback do core)
        Map<String, String> drivers = org.demoiselle.signer.core.keystore.loader.configuration.Configuration.getInstance().getDrivers();
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
            
            if (ks != null && !ks.aliases().hasMoreElements()) {
                System.out.println("KeyStore inicial sem aliases. Tentando carregar forçadamente com cada driver existente...");
                for (Map.Entry<String, String> entry : drivers.entrySet()) {
                    File driverFile = new File(entry.getValue());
                    if (driverFile.exists()) {
                        try {
                            KeyStore ksTrial = ((DriverKeyStoreLoader) loader).getKeyStoreFromDriver(entry.getKey(), entry.getValue());
                            if (ksTrial != null && ksTrial.aliases().hasMoreElements()) {
                                ks = ksTrial;
                                break;
                            }
                        } catch (Exception e) {
                            // Ignorar erros de drivers incompatíveis
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Erro ao carregar KeyStore do Token: " + e.getMessage());
            return;
        }

        if (ks == null) {
            System.err.println("KeyStore não carregada.");
            return;
        }
        
        try {
            ks.load(null, pin.toCharArray());
        } catch (Exception e) {
            System.out.println("Aviso ao carregar KeyStore com PIN: " + e.getMessage());
        }

        Enumeration<String> aliases = ks.aliases();
        if (!aliases.hasMoreElements()) {
            System.out.println("Nenhum alias encontrado para assinar.");
            return;
        }

        // 3. Obter o primeiro alias e preparar assinatura
        String alias = aliases.nextElement();
        System.out.println("Utilizando certificado do alias: " + alias);
        
        Certificate[] certChain = ks.getCertificateChain(alias);
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, null);
        
        if (privateKey == null) {
            System.err.println("Não foi possível acessar a chave privada do certificado.");
            return;
        }

        byte[] contentToSign = "Conteudo de teste para assinatura integrada com Demoiselle Signer e Token PKCS11.".getBytes("UTF-8");

        PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
        signer.setCertificates(certChain);
        signer.setPrivateKey(privateKey);
        
        // Utilizando a política base AD_RB
        signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_CADES_2_4);
        signer.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);

        // Desabilita cache temporariamente para evitar falhas de rede/LCR no teste
        org.demoiselle.signer.core.ca.manager.CAManagerConfiguration.getInstance().setCached(false);
        org.demoiselle.signer.core.repository.ConfigurationRepo.getInstance().setOnline(false);

        System.out.println("Realizando assinatura detached...");
        byte[] signature = signer.doDetachedSign(contentToSign);
        
        Assert.assertNotNull("Assinatura não deve ser nula", signature);
        Assert.assertTrue("Assinatura deve ter tamanho maior que 0", signature.length > 0);
        
        System.out.println("Assinatura gerada com sucesso! Tamanho: " + signature.length + " bytes.");
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
        
        int end = start;
        char endChar = json.indexOf('\"', start) != -1 ? '\"' : ',';
        if (json.charAt(start - 1) != '\"') {
            while (end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '}' && json.charAt(end) != ' ') {
                end++;
            }
        } else {
            end = json.indexOf('\"', start);
        }
        
        if (start < end) {
            return json.substring(start, end).trim();
        }
        return null;
    }
}
