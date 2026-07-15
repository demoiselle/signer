package org.demoiselle.signer.core.validator;

import org.demoiselle.signer.core.exception.IncompatiblePolicyException;
import java.security.cert.X509Certificate;

public class RootCompatValidator {
    public static void validateRootCompatibility(X509Certificate signerCert, String policyName) throws IncompatiblePolicyException {
        if (signerCert == null || policyName == null) return;
        
        String issuerDN = signerCert.getIssuerDN().getName();
        // Identifica se é raiz v12 direta ou via intermediária
        if (issuerDN.contains("v12") || issuerDN.contains("V12")) {
            // Se for v12, a política DEVE ser 2.4 ou superior
            if (policyName.contains("2_0") || policyName.contains("2_1") || policyName.contains("2_2") || policyName.contains("2_3")
               || policyName.contains("1_0") || policyName.contains("1_1") || policyName.contains("1_2")) {
                throw new IncompatiblePolicyException(
                    "O certificado pertence a uma hierarquia da Raiz v12 da ICP-Brasil. " +
                    "A política solicitada (" + policyName + ") e incompatível. " +
                    "Utilize obrigatoriamente a versao 2.4 ou superior da politica."
                );
            }
        }
    }
}
