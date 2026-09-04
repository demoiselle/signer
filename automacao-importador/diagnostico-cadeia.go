package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	bksPath := flag.String("bks", "", "Caminho do arquivo BKS")
	bksPass := flag.String("bks-pass", "serprosigner", "Senha do BKS")
	bcprov := flag.String("bcprov", "", "Caminho do JAR bcprov")
	pfxPath := flag.String("pfx", "", "Opcional: PFX para comparar cadeia")
	pfxPass := flag.String("pfx-pass", "", "Senha do PFX")
	help := flag.Bool("help", false, "Exibe ajuda")
	flag.Parse()

	if *help || *bksPath == "" || *bcprov == "" {
		fmt.Println("Uso: go run diagnostico-cadeia.go -bks <cadeias.bks> -bcprov <bcprov.jar> [-pfx <cert.pfx> -pfx-pass <senha>]")
		os.Exit(1)
	}

	workDir, _ := os.MkdirTemp("", "diag-cadeia")
	defer os.RemoveAll(workDir)

	fmt.Println("===========================================")
	fmt.Println("  DIAGNÓSTICO DE CADEIA DE CERTIFICADOS")
	fmt.Println("===========================================")

	// 1. Extrai todos os certificados do BKS para PEM
	bksCerts := exportBKS(*bksPath, *bksPass, *bcprov, workDir)
	fmt.Printf("\n📦 BKS: %s\n", *bksPath)
	fmt.Printf("   Total de certificados: %d\n", len(bksCerts))

	// 2. Analisa os certificados
	analyzeCerts("BKS", bksCerts)

	// 3. Se PFX informado, analisa também e compara
	var pfxCerts []certInfo
	if *pfxPath != "" && *pfxPass != "" {
		pfxCerts = extractPFX(*pfxPath, *pfxPass, workDir)
		fmt.Printf("\n📜 PFX: %s\n", *pfxPath)
		fmt.Printf("   Total de certificados na cadeia: %d\n", len(pfxCerts))
		analyzeCerts("PFX", pfxCerts)
		compareCadeias(bksCerts, pfxCerts)
	}

	// 4. Verifica se todas as CAs do PFX estão no BKS
	if len(pfxCerts) > 0 {
		checkMissingCAs(bksCerts, pfxCerts)
	}

	fmt.Println("\n===========================================")
	fmt.Println("  DIAGNÓSTICO CONCLUÍDO")
	fmt.Println("===========================================")
}

type certInfo struct {
	Source     string
	Subject    string
	Issuer     string
	Serial     string
	IsCA       bool
	SelfSigned bool
	Raw        []byte
	CN         string
}

func exportBKS(bksPath, password, bcprov, workDir string) []certInfo {
	pemDir := filepath.Join(workDir, "bks_pem")
	os.MkdirAll(pemDir, 0755)

	// Usa keytool para exportar cada entrada
	listCmd := exec.Command("keytool", "-list", "-keystore", bksPath,
		"-storepass", password,
		"-storetype", "BKS",
		"-provider", "org.bouncycastle.jce.provider.BouncyCastleProvider",
		"-providerpath", bcprov,
		"-noprompt")
	output, err := listCmd.CombinedOutput()
	if err != nil {
		log.Printf("Aviso: erro ao listar BKS: %v", err)
		return nil
	}

	var aliases []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Tipo") || strings.HasPrefix(line, "Fornecedor") ||
			strings.HasPrefix(line, "Sua area") || strings.Contains(line, "contem") ||
			strings.HasPrefix(line, "Aviso") || strings.HasPrefix(line, "WARNING") {
			continue
		}
		if idx := strings.Index(line, ","); idx > 0 {
			aliases = append(aliases, strings.TrimSpace(line[:idx]))
		}
	}

	var certs []certInfo
	for _, alias := range aliases {
		certFile := filepath.Join(pemDir, alias+".pem")
		exportCmd := exec.Command("keytool", "-exportcert", "-rfc", "-keystore", bksPath,
			"-storepass", password, "-alias", alias, "-file", certFile,
			"-storetype", "BKS",
			"-provider", "org.bouncycastle.jce.provider.BouncyCastleProvider",
			"-providerpath", bcprov,
			"-noprompt")
		var stderr bytes.Buffer
		exportCmd.Stderr = &stderr
		if err := exportCmd.Run(); err != nil {
			log.Printf("  Falha ao exportar %s: %v", alias, err)
			continue
		}

		cert, err := parsePEMFile(certFile)
		if err != nil {
			log.Printf("  Falha ao parsear PEM de %s: %v", alias, err)
			continue
		}
		cert.Source = fmt.Sprintf("BKS[%s]", alias)
		certs = append(certs, cert)
	}

	return certs
}

func extractPFX(pfxPath, password, workDir string) []certInfo {
	pemFile := filepath.Join(workDir, "pfx_certs.pem")

	cmd := exec.Command("openssl", "pkcs12",
		"-in", pfxPath,
		"-passin", fmt.Sprintf("pass:%s", password),
		"-nokeys", "-legacy",
		"-out", pemFile)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Tenta sem -legacy
		cmd2 := exec.Command("openssl", "pkcs12",
			"-in", pfxPath,
			"-passin", fmt.Sprintf("pass:%s", password),
			"-nokeys",
			"-out", pemFile)
		stderr.Reset()
		cmd2.Stderr = &stderr
		if err2 := cmd2.Run(); err2 != nil {
			log.Fatalf("Erro ao extrair PFX: %v", err2)
			return nil
		}
	}

	data, _ := os.ReadFile(pemFile)
	var certs []certInfo
	block := data
	for i := 0; ; i++ {
		var p *pem.Block
		p, block = pem.Decode(block)
		if p == nil {
			break
		}
		if p.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			continue
		}
		ci := certInfo{
			Source:     fmt.Sprintf("PFX[%d]", i),
			Subject:    cert.Subject.String(),
			Issuer:     cert.Issuer.String(),
			Serial:     cert.SerialNumber.String(),
			IsCA:       cert.IsCA,
			SelfSigned: cert.Subject.String() == cert.Issuer.String(),
			Raw:        p.Bytes,
			CN:         extractCN(cert.Subject.String()),
		}
		certs = append(certs, ci)
	}
	return certs
}

func parsePEMFile(path string) (certInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return certInfo{}, err
	}
	// Tenta PEM primeiro
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			return certInfo{
				Subject:    cert.Subject.String(),
				Issuer:     cert.Issuer.String(),
				Serial:     cert.SerialNumber.String(),
				IsCA:       cert.IsCA,
				SelfSigned: cert.Subject.String() == cert.Issuer.String(),
				Raw:        block.Bytes,
				CN:         extractCN(cert.Subject.String()),
			}, nil
		}
	}
	// Tenta DER (keytool sem -rfc, ou binario)
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return certInfo{}, fmt.Errorf("PEM invalido (tambem falhou DER: %v)", err)
	}
	return certInfo{
		Subject:    cert.Subject.String(),
		Issuer:     cert.Issuer.String(),
		Serial:     cert.SerialNumber.String(),
		IsCA:       cert.IsCA,
		SelfSigned: cert.Subject.String() == cert.Issuer.String(),
		Raw:        data,
		CN:         extractCN(cert.Subject.String()),
	}, nil
}

func extractCN(subject string) string {
	upper := strings.ToUpper(subject)
	idx := strings.Index(upper, "CN=")
	if idx < 0 {
		return ""
	}
	rest := subject[idx:]
	end := strings.Index(rest, ",")
	if end < 0 {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(rest[:end])
}

func analyzeCerts(source string, certs []certInfo) {
	fmt.Printf("\n--- Análise dos certificados (%s) ---\n", source)

	// Agrupa por CN para detectar conflitos de case
	cnMap := make(map[string][]certInfo)
	for _, c := range certs {
		key := strings.ToUpper(c.CN)
		cnMap[key] = append(cnMap[key], c)
	}

	hasIssues := false

	for _, group := range cnMap {
		if len(group) > 1 {
			fmt.Printf("\n⚠️  CONFLITO: %d certificados com mesmo CN (case-insensitive):\n", len(group))
			for _, c := range group {
				fmt.Printf("   - Source: %s\n", c.Source)
				fmt.Printf("     Subject: %s\n", c.Subject)
				fmt.Printf("     Serial:  %s\n", c.Serial)
				fmt.Printf("     Issuer:  %s\n", c.Issuer)

				// Verifica se as chaves são diferentes
				if len(group) > 1 && c.SelfSigned {
					fmt.Printf("     ➜ AUTOASSINADO (Raiz)\n")
				}
			}

			// Verifica conflito de case
			names := ""
			for _, c := range group {
				if names != "" {
					names += "  vs  "
				}
				names += fmt.Sprintf("\"%s\" (serial %s)", c.CN, c.Serial)
			}
			fmt.Printf("   ➜ CNs conflitantes: %s\n", names)

			// Verifica se o conflito é só de case
			caseConflict := true
			firstCN := group[0].CN
			for _, c := range group {
				if strings.EqualFold(firstCN, c.CN) && firstCN != c.CN {
					// Case difference found
				} else if firstCN == c.CN {
					// Exact same CN - different serial/key
				} else {
					caseConflict = false
				}
			}
			if caseConflict {
				fmt.Printf("   ➜ Conflito é APENAS de CASE (upcase/downcase)\n")
			}
			hasIssues = true
		}
	}

	// Verifica certificados expirados
	for _, c := range certs {
		if c.SelfSigned {
			fmt.Printf("\n🔒 RAIZ: %s\n", c.Subject)
			fmt.Printf("     Serial: %s\n", c.Serial)
		}
	}

	// Resumo por tipo
	raizes := 0
	intermediarias := 0
	finais := 0
	for _, c := range certs {
		if c.SelfSigned {
			raizes++
		} else if c.IsCA {
			intermediarias++
		} else {
			finais++
		}
	}
	fmt.Printf("\n📊 Resumo: %d raízes, %d intermediárias, %d finais\n", raizes, intermediarias, finais)

	if !hasIssues {
		fmt.Printf("\n✅ Nenhum conflito de CN encontrado no %s\n", source)
	}
}

func compareCadeias(bks, pfx []certInfo) {
	fmt.Println("\n--- Comparação: BKS vs PFX ---")

	// Para cada cert do PFX, verifica se tem correspondente no BKS
	for _, pc := range pfx {
		found := false
		for _, bc := range bks {
			if strings.EqualFold(pc.Subject, bc.Subject) {
				if pc.Serial == bc.Serial {
					fmt.Printf("✅ PFX[%s] tem correspondente EXATO no BKS (serial %s)\n", pc.CN, pc.Serial)
				} else {
					fmt.Printf("⚠️  PFX[%s] (serial %s) vs BKS (serial %s) - MESMO SUBJECT, SERIAL DIFERENTE!\n",
						pc.CN, pc.Serial, bc.Serial)
					fmt.Printf("   PFX issuer: %s\n", pc.Issuer)
					fmt.Printf("   BKS issuer: %s\n", bc.Issuer)
				}
				found = true
				break
			}
		}
		if !found {
			// Tenta por CN
			for _, bc := range bks {
				if strings.EqualFold(pc.CN, bc.CN) {
					fmt.Printf("⚠️  PFX[%s] (serial %s) encontrado por CN mas com subject diferente!\n", pc.CN, pc.Serial)
					fmt.Printf("   PFX subject: %s\n", pc.Subject)
					fmt.Printf("   BKS subject: %s\n", bc.Subject)
					fmt.Printf("   PFX issuer: %s\n", pc.Issuer)
					fmt.Printf("   BKS issuer: %s\n", bc.Issuer)
					found = true
					break
				}
			}
		}
		if !found {
			fmt.Printf("❌ PFX[%s] (serial %s) AUSENTE do BKS!\n", pc.CN, pc.Serial)
			fmt.Printf("   Subject: %s\n", pc.Subject)
			fmt.Printf("   Issuer:  %s\n", pc.Issuer)
		}
	}
}

func checkMissingCAs(bks, pfx []certInfo) {
	fmt.Println("\n--- Verificação de integridade da cadeia ---")

	if len(pfx) < 2 {
		fmt.Println("PFX nao tem cadeia completa (precisa de pelo menos 2 certificados)")
		return
	}

	// Verifica: cada certificado do PFX (exceto o primeiro) precisa estar no BKS
	// Pula o primeiro (end-entity) e o ultimo (root - pode vir de outro provider)
	for i := 1; i < len(pfx); i++ {
		pc := pfx[i]
		found := false
		for _, bc := range bks {
			if bc.Serial == pc.Serial {
				found = true
				break
			}
		}
		if !found {
			if pc.SelfSigned {
				fmt.Printf("❌ Raiz \"%s\" (serial %s) AUSENTE do BKS!\n", pc.CN, pc.Serial)
				fmt.Printf("   Esta raiz PRECISA estar no BKS de homologacao, pois a raiz de producao tem chave DIFERENTE\n")
			} else {
				fmt.Printf("❌ CA Intermediaria \"%s\" (serial %s) AUSENTE do BKS!\n", pc.CN, pc.Serial)
			}
		}
	}

	// Verifica se ha "Hom" vs "HOM" conflict
	for _, bc := range bks {
		if strings.Contains(bc.Subject, "SERPRO Final v6") {
			if bc.CN == "CN=Autoridade Certificadora do SERPRO Final v6 - Hom" ||
				bc.CN == "CN=Autoridade Certificadora do SERPRO Final v6 - HOM" {
				// Verifica se o outro tambem existe
				for _, bc2 := range bks {
					if bc2.Subject != bc.Subject && strings.EqualFold(bc.CN, bc2.CN) {
						fmt.Printf("\n⚠️  CONFLITO DE CASE DETECTADO:\n")
						fmt.Printf("   1) \"%s\" serial %s\n", bc.Subject, bc.Serial)
						fmt.Printf("   2) \"%s\" serial %s\n", bc2.Subject, bc2.Serial)
						fmt.Printf("   ➜ O CAManager pode encontrar a CA errada por case-insensitive CN match!\n")
					}
				}
			}
		}
	}
}
