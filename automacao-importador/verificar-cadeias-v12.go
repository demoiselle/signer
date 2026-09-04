package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	INDEX_URL = "https://repositoriohom.serpro.gov.br/cadeias/index.html"
	BASE_URL  = "https://repositoriohom.serpro.gov.br/cadeias/"
)

type CAInfo struct {
	Subject    string
	Serial     string
	Issuer     string
	SelfSigned bool
	SourceFile string
}

var v12Expected = []struct {
	CN      string
	Subject string
	Serial  string
	Role    string
}{
	{
		CN:      "Autoridade Certificadora Raiz Brasileira v12 - HOM",
		Subject: "CN=Autoridade Certificadora Raiz Brasileira v12 - HOM,OU=Instituto Nacional de Tecnologia da Informacao - ITI,O=ICP-Brasil,C=BR",
		Serial:  "14083423439450162859",
		Role:    "RAIZ (Root CA) - AC Raiz Brasileira v12 HOM",
	},
	{
		CN:      "Autoridade Certificadora SERPRO v5 - Hom",
		Subject: "CN=Autoridade Certificadora SERPRO v5 - Hom,OU=Autoridade Certificadora Raiz Brasileira v12 - HOM,O=ICP-Brasil,C=BR",
		Serial:  "15904888841235244081",
		Role:    "INTERMEDIARIA - AC SERPRO v5 HOM (emitida pela Raiz v12 HOM)",
	},
	{
		CN:      "Autoridade Certificadora do Serpro Final v6 - Hom",
		Subject: "CN=Autoridade Certificadora do Serpro Final v6 - Hom,OU=Servico Federal de Processamento de Dados - SERPRO,O=ICP-Brasil,C=BR",
		Serial:  "8889727753282084105",
		Role:    "FINAL - AC SERPRO Final v6 HOM (emite certificados SURJ)",
	},
}

var v2Subjects = []string{
	"CN=Autoridade Certificadora Raiz Hom do SERPRO",
	"OU=Autoridade Certificadora Raiz Hom do SERPRO",
	"CN=Autoridade Certificadora Raiz Hom do SERPRO v2",
	"CN=Autoridade Certificadora SERPRO v2 - HOM",
	"CN=Autoridade Certificadora do SERPRO Final v6 - Hom",
}

func main() {
	fmt.Println("================================================================")
	fmt.Println("  VERIFICADOR: PRESENCA DA CADEIA v12 NO REPOSITORIO HOM")
	fmt.Println("  URL:", INDEX_URL)
	fmt.Println("  Data:", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("================================================================")

	files := fetchP7BList()
	if files == nil {
		fmt.Println("ERRO: Nao foi possivel obter a lista do repositorio.")
		fmt.Println("Verifique VPN/conexao com rede SERPRO.")
		os.Exit(1)
	}

	fmt.Printf("\nTotal de arquivos .p7b encontrados: %d\n", len(files))
	for i, f := range files {
		fmt.Printf("  %2d. %s\n", i+1, f)
	}

	workDir, _ := os.MkdirTemp("", "v12-check")
	defer os.RemoveAll(workDir)

	type fileCAs struct {
		file string
		cas  []CAInfo
		err  string
	}

	var results []fileCAs
	for _, f := range files {
		cas, err := downloadConvertParse(f, workDir)
		if err != "" {
			results = append(results, fileCAs{file: f, err: err})
		} else {
			results = append(results, fileCAs{file: f, cas: cas})
		}
	}

	fmt.Println("\n\n================================================================")
	fmt.Println("  CONTEUDO DE CADA ARQUIVO .P7B")
	fmt.Println("================================================================")

	var allCAs []CAInfo
	for _, r := range results {
		if r.err != "" {
			fmt.Printf("\n  --- %s ---\n  ERRO: %s\n", r.file, r.err)
			continue
		}
		if len(r.cas) == 0 {
			fmt.Printf("\n  --- %s --- (vazio/invalido)\n", r.file)
			continue
		}
		fmt.Printf("\n  >>> %s (%d certificado(s)) <<<\n", r.file, len(r.cas))
		for _, ca := range r.cas {
			ss := ""
			if ca.SelfSigned {
				ss = " [RAIZ]"
			}
			fmt.Printf("  Subject: %s%s\n", ca.Subject, ss)
			fmt.Printf("  Serial:  %s\n", ca.Serial)
			fmt.Printf("  Issuer:  %s\n", ca.Issuer)
			fmt.Println()
		}
		allCAs = append(allCAs, r.cas...)
	}

	fmt.Println("\n\n================================================================")
	fmt.Println("  VERIFICACAO: CADEIA v12")
	fmt.Println("================================================================")

	v12Count := 0
	for _, e := range v12Expected {
		found := false
		for _, ca := range allCAs {
			if ca.Serial == e.Serial {
				found = true
				break
			}
		}
		if found {
			v12Count++
			fmt.Printf("  [OK] %s\n", e.Role)
		} else {
			fmt.Printf("  [FALTA] %s\n", e.Role)
		}
	}

	fmt.Println()
	fmt.Println("  Arquivos .p7b que contem CAs da CADEIA v2 (antiga):")
	v2Found := false
	seen := make(map[string]bool)
	for _, ca := range allCAs {
		for _, sub := range v2Subjects {
			if strings.Contains(ca.Subject, sub) && !seen[ca.Subject+ca.Serial] {
				seen[ca.Subject+ca.Serial] = true
				v2Found = true
				fmt.Printf("    %s (serial %s) em %s\n", ca.Subject, ca.Serial, ca.SourceFile)
				break
			}
		}
	}
	if !v2Found {
		fmt.Println("    (nenhuma CA da cadeia v2 identificada)")
	}

	fmt.Println("\n\n================================================================")
	fmt.Println("  RESUMO FINAL")
	fmt.Println("================================================================")
	if v12Count == 3 {
		fmt.Println("  CADEIA v12 COMPLETA presente no repositorio.")
	} else if v12Count > 0 {
		fmt.Printf("  CADEIA v12 PARCIAL (%d/3 CAs encontradas).\n", v12Count)
	} else {
		fmt.Println("\n  >>>>>> CADEIA v12 COMPLETAMENTE AUSENTE <<<<<<")
		fmt.Println("")
		fmt.Println("  O repositorio HOM soh possui a CADEIA v2 (antiga):")
		fmt.Println("    AC Raiz Hom do SERPRO v2 (fake) -> AC SERPRO v2 - HOM -> AC SERPRO Final v6 - Hom")
		fmt.Println("")
		fmt.Println("  Faltam as 3 CAs da CADEIA v12:")
		fmt.Println("    AC Raiz Brasileira v12 (ICP-Brasil oficial)")
		fmt.Println("    AC SERPRO v5 - HOM")
		fmt.Println("    AC SERPRO Final v6 - HOM (com 'HOM' maiusculo)")
	}

	fmt.Println("\n================================================================")
}

func fetchP7BList() []string {
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(INDEX_URL)
	if err != nil {
		fmt.Printf("Erro ao acessar %s: %v\n", INDEX_URL, err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(`href="([^"]+\.p7b)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var files []string
	for _, m := range matches {
		parts := strings.Split(m[1], "/")
		fn := parts[len(parts)-1]
		if !seen[fn] {
			seen[fn] = true
			files = append(files, fn)
		}
	}
	return files
}

func downloadConvertParse(filename, workDir string) ([]CAInfo, string) {
	url := BASE_URL + filename
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Sprintf("download falhou: %v", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if len(data) == 0 {
		return nil, "arquivo vazio"
	}

	p7bFile := filepath.Join(workDir, filename)
	os.WriteFile(p7bFile, data, 0644)

	pemFile := filepath.Join(workDir, filename+".pem")
	cmd := exec.Command("openssl", "pkcs7", "-in", p7bFile, "-inform", "DER",
		"-out", pemFile, "-outform", "PEM", "-print_certs")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Tenta como PEM
		cmd2 := exec.Command("openssl", "pkcs7", "-in", p7bFile, "-inform", "PEM",
			"-out", pemFile, "-outform", "PEM", "-print_certs")
		output2, err2 := cmd2.CombinedOutput()
		if err2 != nil {
			return nil, fmt.Sprintf("openssl pkcs7 falhou (DER e PEM): %v\n%s", err, string(output))
		}
		_ = output2
	}

	pemData, _ := os.ReadFile(pemFile)
	if len(pemData) == 0 {
		return nil, "openssl nao gerou saida PEM"
	}

	var cas []CAInfo
	seen := make(map[string]bool)
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		key := cert.Subject.String() + cert.SerialNumber.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		cas = append(cas, CAInfo{
			Subject:    cert.Subject.String(),
			Serial:     cert.SerialNumber.String(),
			Issuer:     cert.Issuer.String(),
			SelfSigned: cert.Subject.String() == cert.Issuer.String(),
			SourceFile: filename,
		})
	}
	return cas, ""
}
