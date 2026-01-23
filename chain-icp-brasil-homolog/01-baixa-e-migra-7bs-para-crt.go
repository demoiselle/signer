package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/net/html"
)

const (
	baseURL   = "https://repositoriohom.serpro.gov.br/cadeias/"
	p7bFolder = "novosp7bs"
	crtFolder = "novascadeias"
	logFile   = "log_importacao.txt"
)

func main() {
	// Apaga o conteúdo dos diretórios
	os.RemoveAll(p7bFolder)
	os.RemoveAll(crtFolder)
	// Cria pastas
	os.MkdirAll(p7bFolder, 0755)
	os.MkdirAll(crtFolder, 0755)

	// Apaga o log anterior
	os.Remove(logFile)
	// Cria novo log
	logf, err := os.Create(logFile)
	if err != nil {
		fmt.Println("Erro ao criar log:", err)
		return
	}
	defer logf.Close()

	resp, err := http.Get(baseURL)
	if err != nil {
		fmt.Println("Erro ao acessar a URL:", err)
		return
	}
	defer resp.Body.Close()

	z := html.NewTokenizer(resp.Body)
	var p7bLinks []string
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		t := z.Token()
		if t.Type == html.StartTagToken && t.Data == "a" {
			for _, a := range t.Attr {
				if a.Key == "href" && strings.HasSuffix(a.Val, ".p7b") {
					p7bLinks = append(p7bLinks, a.Val)
				}
			}
		}
	}

	fmt.Println("Links .p7b encontrados:")
	var errosConversao []string
	for _, link := range p7bLinks {
		fmt.Println(link)
		logf.WriteString(fmt.Sprintf("Link encontrado: %s\n", link))
	}

	for _, link := range p7bLinks {
		fileURL := link
		req, err := http.NewRequest("GET", fileURL, nil)
		if err != nil {
			msg := fmt.Sprintf("[ERRO] Requisição: %s | %v\n", fileURL, err)
			fmt.Print(msg)
			logf.WriteString(msg)
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36")
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			msg := fmt.Sprintf("[ERRO] Download: %s | %v\n", fileURL, err)
			fmt.Print(msg)
			logf.WriteString(msg)
			continue
		}
		defer resp.Body.Close()

		fileName := filepath.Base(link)
		p7bPath := filepath.Join(p7bFolder, fileName)
		out, err := os.Create(p7bPath)
		if err != nil {
			msg := fmt.Sprintf("[ERRO] Criar arquivo: %s | %v\n", p7bPath, err)
			fmt.Print(msg)
			logf.WriteString(msg)
			continue
		}
		_, err = io.Copy(out, resp.Body)
		out.Close()
		if err != nil {
			msg := fmt.Sprintf("[ERRO] Salvar arquivo: %s | %v\n", p7bPath, err)
			fmt.Print(msg)
			logf.WriteString(msg)
			continue
		}
		msg := fmt.Sprintf("[OK] Download: %s -> %s\n", fileURL, p7bPath)
		fmt.Print(msg)
		logf.WriteString(msg)

		// Detecta se o arquivo está em PEM PKCS7
		isPEM := false
		f, err := os.Open(p7bPath)
		if err == nil {
			buf := make([]byte, 2048)
			n, _ := f.Read(buf)
			f.Close()
			content := string(buf[:n])
			if strings.Contains(content, "-----BEGIN PKCS7-----") || strings.Contains(content, "-----BEGIN CERTIFICATE-----") {
				isPEM = true
			}
		}

		// crtPath removido, não é mais utilizado
		var cmd *exec.Cmd
		if isPEM {
			// PKCS7 em PEM
			cmd = exec.Command("openssl", "pkcs7", "-print_certs", "-in", p7bPath)
			output, err := cmd.CombinedOutput()
			if err != nil {
				// Se falhar, tenta extrair manualmente os certificados
				pemData, errRead := os.ReadFile(p7bPath)
				if errRead == nil {
					pemStr := string(pemData)
					certBlocks := strings.Split(pemStr, "-----END CERTIFICATE-----")
					count := 0
					for _, block := range certBlocks {
						beginIdx := strings.Index(block, "-----BEGIN CERTIFICATE-----")
						if beginIdx != -1 {
							cert := block[beginIdx:] + "-----END CERTIFICATE-----\n"
							count++
							crtPathN := filepath.Join(crtFolder, fmt.Sprintf("%s_%d.crt", strings.TrimSuffix(fileName, ".p7b"), count))
							errWrite := os.WriteFile(crtPathN, []byte(cert), 0644)
							if errWrite == nil {
								msg := fmt.Sprintf("[OK] Extraído manualmente: %s -> %s\n", p7bPath, crtPathN)
								fmt.Print(msg)
								logf.WriteString(msg)
							} else {
								msg := fmt.Sprintf("[ERRO] Escrever manual: %s -> %s | %v\n", p7bPath, crtPathN, errWrite)
								fmt.Print(msg)
								logf.WriteString(msg)
							}
						}
					}
					if count == 0 {
						msg := fmt.Sprintf("[ERRO] Nenhum certificado encontrado manualmente em: %s\n", p7bPath)
						fmt.Print(msg)
						logf.WriteString(msg)
					}
					continue
				} else {
					msg := fmt.Sprintf("[ERRO] Ler PEM manual: %s | %v\n", p7bPath, errRead)
					fmt.Print(msg)
					logf.WriteString(msg)
					continue
				}
			}
			// Se o OpenSSL funcionar, divide a saída em múltiplos certificados
			outputStr := string(output)
			certBlocks := strings.Split(outputStr, "-----END CERTIFICATE-----")
			count := 0
			for _, block := range certBlocks {
				beginIdx := strings.Index(block, "-----BEGIN CERTIFICATE-----")
				if beginIdx != -1 {
					cert := block[beginIdx:] + "-----END CERTIFICATE-----\n"
					count++
					crtPathN := filepath.Join(crtFolder, fmt.Sprintf("%s_%d.crt", strings.TrimSuffix(fileName, ".p7b"), count))
					errWrite := os.WriteFile(crtPathN, []byte(cert), 0644)
					if errWrite == nil {
						msg := fmt.Sprintf("[OK] Convertido via OpenSSL: %s -> %s\n", p7bPath, crtPathN)
						fmt.Print(msg)
						logf.WriteString(msg)
					} else {
						msg := fmt.Sprintf("[ERRO] Escrever OpenSSL: %s -> %s | %v\n", p7bPath, crtPathN, errWrite)
						fmt.Print(msg)
						logf.WriteString(msg)
					}
				}
			}
			if count == 0 {
				msg := fmt.Sprintf("[ERRO] Nenhum certificado encontrado via OpenSSL em: %s\n", p7bPath)
				fmt.Print(msg)
				logf.WriteString(msg)
			}
			continue
		} else {
			// PKCS7 em DER
			cmd = exec.Command("openssl", "pkcs7", "-inform", "DER", "-print_certs", "-in", p7bPath)
			output, err := cmd.CombinedOutput()
			if err != nil {
				msg := fmt.Sprintf("[ERRO] Converter: %s | %v\nSaída OpenSSL: %s\n", p7bPath, err, string(output))
				fmt.Print(msg)
				logf.WriteString(msg)
				// Log específico para falha de conversão
				erroMsg := fmt.Sprintf("%s | Motivo: %v\nSaída OpenSSL: %s", p7bPath, err, string(output))
				errosConversao = append(errosConversao, erroMsg)
				continue
			}
			// Divide a saída em múltiplos certificados
			outputStr := string(output)
			certBlocks := strings.Split(outputStr, "-----END CERTIFICATE-----")
			count := 0
			for _, block := range certBlocks {
				beginIdx := strings.Index(block, "-----BEGIN CERTIFICATE-----")
				if beginIdx != -1 {
					cert := block[beginIdx:] + "-----END CERTIFICATE-----\n"
					count++
					crtPathN := filepath.Join(crtFolder, fmt.Sprintf("%s_%d.crt", strings.TrimSuffix(fileName, ".p7b"), count))
					errWrite := os.WriteFile(crtPathN, []byte(cert), 0644)
					if errWrite == nil {
						msg := fmt.Sprintf("[OK] Convertido via OpenSSL: %s -> %s\n", p7bPath, crtPathN)
						fmt.Print(msg)
						logf.WriteString(msg)
					} else {
						msg := fmt.Sprintf("[ERRO] Escrever OpenSSL: %s -> %s | %v\n", p7bPath, crtPathN, errWrite)
						fmt.Print(msg)
						logf.WriteString(msg)
					}
				}
			}
			if count == 0 {
				msg := fmt.Sprintf("[ERRO] Nenhum certificado encontrado via OpenSSL em: %s\n", p7bPath)
				fmt.Print(msg)
				logf.WriteString(msg)
			}
		}
		// Ao final, lista de erros de conversão
		if len(errosConversao) > 0 {
			logf.WriteString("\n==== Lista de erros de conversão p7b ====" + "\n")
			for _, erro := range errosConversao {
				logf.WriteString(erro + "\n")
			}
		} else {
			logf.WriteString("\nNenhum erro de conversão p7b encontrado.\n")
		}
	}
}
