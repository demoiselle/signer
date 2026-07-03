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

public class TokenIT {

    @Test
    public void testReadTokenCertificates() throws Exception {
        System.out.println("Iniciando teste de leitura de token...");
        System.out.println("Working Directory: " + System.getProperty("user.dir"));

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
        String tokenName = config.get("token.nome");
        String pin = config.get("token.pin");
        String indiceStr = config.get("token.indice");
        int indice = (indiceStr != null) ? Integer.parseInt(indiceStr) : 0;

        System.out.println("Configuração carregada:");
        System.out.println("Token Name: " + tokenName);
        System.out.println("Indice: " + indice);

        System.out.println("Drivers mapeados na Configuration:");
        Map<String, String> drivers = org.demoiselle.signer.core.keystore.loader.configuration.Configuration.getInstance().getDrivers();
        for (Map.Entry<String, String> entry : drivers.entrySet()) {
            File driverFile = new File(entry.getValue());
            System.out.println(" - " + entry.getKey() + ": " + entry.getValue() + (driverFile.exists() ? " [EXISTE]" : " [NÃO ENCONTRADO]"));
        }

        // 2. Configurar o driver
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
            
            // Se a KeyStore estiver vazia, tenta o fallback manual com todos os drivers que existem
            if (ks != null && !ks.aliases().hasMoreElements()) {
                System.out.println("KeyStore inicial sem aliases. Tentando carregar forçadamente com cada driver existente...");
                for (Map.Entry<String, String> entry : drivers.entrySet()) {
                    File driverFile = new File(entry.getValue());
                    if (driverFile.exists()) {
                        System.out.println("Tentando carregar com driver: " + entry.getKey());
                        try {
                            KeyStore ksTrial = ((DriverKeyStoreLoader) loader).getKeyStoreFromDriver(entry.getKey(), entry.getValue());
                            if (ksTrial != null && ksTrial.aliases().hasMoreElements()) {
                                System.out.println("Sucesso ao carregar com driver: " + entry.getKey());
                                ks = ksTrial;
                                break;
                            }
                        } catch (Exception e) {
                            System.out.println("Falha ao tentar driver " + entry.getKey() + ": " + e.getMessage());
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Erro ao carregar KeyStore do Token: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        if (ks == null) {
            System.err.println("KeyStore não carregada.");
            return;
        }

        System.out.println("KeyStore carregada com sucesso. Tipo: " + ks.getType());

        // Forçar o load com o PIN se possível para garantir visibilidade dos certificados
        try {
            System.out.println("Tentando ks.load com o PIN...");
            ks.load(null, pin.toCharArray());
            System.out.println("ks.load concluído.");
        } catch (Exception e) {
            System.out.println("Aviso ao carregar KeyStore com PIN: " + e.getMessage());
        }

        System.out.println("Provedores registrados:");
        for (java.security.Provider p : java.security.Security.getProviders()) {
            if (p.getName().contains("PKCS11")) {
                System.out.println(" - " + p.getName() + " (" + p.getInfo() + ")");
            }
        }

        // 3. Iterar certificados e extrair dados
        File resultsDir = new File("tests/results");
        if (!resultsDir.exists()) {
            resultsDir = new File("../tests/results");
        }
        if (!resultsDir.exists()) {
            System.out.println("Criando diretório de resultados: " + resultsDir.getAbsolutePath());
            resultsDir.mkdirs();
        }
        File resultsFile = new File(resultsDir, "token_certificates.txt");
        System.out.println("Salvando resultados em: " + resultsFile.getAbsolutePath());
        PrintWriter out = new PrintWriter(new FileWriter(resultsFile));

        out.println("Relatório de Certificados do Token");
        out.println("================================");
        out.println("Data da execução: " + new java.util.Date());
        out.println("");

        Enumeration<String> aliases = ks.aliases();
        int count = 0;
        if (!aliases.hasMoreElements()) {
            System.out.println("Nenhum alias encontrado na KeyStore.");
            out.println("Nenhum certificado encontrado no token.");
        }

        while (aliases.hasMoreElements()) {
            count++;
            String alias = aliases.nextElement();
            System.out.println("Processando alias (" + count + "): " + alias);
            
            try {
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                if (cert == null) {
                    System.out.println("Aviso: Certificado nulo para o alias: " + alias);
                    continue;
                }
                BasicCertificate bc = new BasicCertificate(cert);

                out.println("Alias: " + alias);
                out.println("Level: " + (bc.getCertificateLevel() != null ? bc.getCertificateLevel() : "N/A"));
                out.println("Subject DN: " + cert.getSubjectDN().getName());
                out.println("Issuer DN: " + cert.getIssuerDN().getName());
                out.println("Serial Number: " + bc.getSerialNumber());
                
                String nameAR = bc.getNameAR();
                
                out.println("Nome da AR: " + (nameAR != null ? nameAR : "Não encontrado"));
                
                // Extração de OIDs extintos pela Resolução 211 para verificação
                out.println("--- OIDs Extintos (Resolução 211) ---");
                if (bc.hasCertificatePF()) {
                    org.demoiselle.signer.core.extension.ICPBRCertificatePF pf = bc.getICPBRCertificatePF();
                    out.println("Título de Eleitor (2.16.76.1.3.5): " + (pf.getElectoralDocument() != null ? pf.getElectoralDocument() : "N/A"));
                }
                
                // Verificação direta via CertificateExtra para campos que podem não ter getters em BasicCertificate
                org.demoiselle.signer.core.extension.CertificateExtra ce = new org.demoiselle.signer.core.extension.CertificateExtra(cert);
                
                // OID_2_16_76_1_3_9 não tem getter no CertificateExtra, então não podemos usar diretamente.
                // Mas sabemos que o RIC era esse OID. Vamos omitir se não tem getter.
                out.println("Nome Responsável PJ (2.16.76.1.3.2): " + (ce.getOID_2_16_76_1_3_2() != null ? ce.getOID_2_16_76_1_3_2().getData() : "N/A"));
                out.println("Dados Responsável PJ (2.16.76.1.3.4): " + (ce.getOID_2_16_76_1_3_4() != null ? ce.getOID_2_16_76_1_3_4().getData() : "N/A"));
                
                // SIGEPE não tem classe específica, verificamos se existe no map do CertificateExtra
                // Precisamos de reflexão ou de um método público que exponha o map, mas o ce não tem.
                // Como alternativa, podemos ver se o BasicCertificate extrai via SubjectAlternativeNames
                out.println("SIGEPE (2.16.76.1.3.11): " + (cert.getSubjectAlternativeNames() != null && cert.getSubjectAlternativeNames().toString().contains("2.16.76.1.3.11") ? "Presente" : "N/A"));
                
                if (bc.hasCertificatePF()) {
                    out.println("Tipo: Pessoa Física (PF)");
                    out.println("CPF: " + bc.getICPBRCertificatePF().getCPF());
                } else if (bc.hasCertificatePJ()) {
                    out.println("Tipo: Pessoa Jurídica (PJ)");
                    out.println("CNPJ: " + bc.getICPBRCertificatePJ().getCNPJ());
                } else if (bc.hasCertificateSE()) {
                    out.println("Tipo: Selo Eletrônico (SE)");
                    out.println("CNPJ: " + bc.getICPBRCertificateSE().getCNPJ());
                }
                
                out.println("Validade: " + bc.getBeforeDate() + " até " + bc.getAfterDate());
                out.println("--------------------------------");
            } catch (Exception e) {
                System.err.println("Erro ao processar alias " + alias + ": " + e.getMessage());
                out.println("Erro ao processar alias " + alias + ": " + e.getMessage());
            }
        }

        System.out.println("Total de certificados processados: " + count);
        out.println("");
        out.println("Fim do relatório. Total: " + count);
        out.flush();
        out.close();
        System.out.println("Relatório finalizado.");
    }

    /**
     * Parser JSON extremamente simples para evitar dependências.
     * Foca apenas nos campos necessários do test-config.json.
     */
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
        
        // Extração manual simplificada
        map.put("token.nome", extractValue(content, "nome"));
        map.put("token.pin", extractValue(content, "pin"));
        map.put("token.indice", extractValue(content, "indice"));
        
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
            // Provavelmente um número
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
