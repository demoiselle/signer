package cadeias

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/net/html"
	"automacao-importador/pkg/utils"
)

// Config contém as configurações do ambiente
type Config struct {
	Env              string
	ZipURL           string
	HomologURL       string
	TargetKeystore   string
	KeystorePass     string
	BouncyCastlePath string
}

func AtualizarCadeias(cfg Config) error {
	log.Printf("[CADEIAS] Iniciando atualização para ambiente: %s", cfg.Env)
	workDir := "tmp_cadeias"
	os.RemoveAll(workDir)
	os.MkdirAll(workDir, 0755)
	defer os.RemoveAll(workDir)

	if cfg.Env == "pro" {
		if err := baixarEExtrairZip(cfg.ZipURL, workDir); err != nil {
			return fmt.Errorf("erro ao baixar/extrair zip de produção: %v", err)
		}
	} else if cfg.Env == "hom" {
		if err := baixarEExtrairHomolog(cfg.HomologURL, workDir); err != nil {
			return fmt.Errorf("erro ao baixar cadeias de homologação: %v", err)
		}
	}

	if err := normalizarCertificados(workDir); err != nil {
		return fmt.Errorf("erro ao normalizar certificados: %v", err)
	}

	if err := gerarKeystore(workDir, cfg.TargetKeystore, cfg.KeystorePass, cfg.BouncyCastlePath); err != nil {
		return fmt.Errorf("erro ao gerar keystore BKS: %v", err)
	}

	log.Printf("[CADEIAS] Cadeias atualizadas com sucesso em: %s", cfg.TargetKeystore)
	return nil
}

func baixarEExtrairZip(url, dest string) error {
	zipPath := filepath.Join(dest, "cadeias.zip")
	log.Printf("[CADEIAS] Baixando %s...", url)
	if err := utils.DownloadFile(url, zipPath); err != nil {
		return err
	}

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		lowerName := strings.ToLower(f.Name)
		if !strings.HasSuffix(lowerName, ".crt") && !strings.HasSuffix(lowerName, ".cer") {
			continue
		}
		fpath := filepath.Join(dest, filepath.Base(f.Name))
		if err := extrairArquivo(f, fpath); err != nil {
			return err
		}
	}
	return nil
}

func extrairArquivo(f *zip.File, dest string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, rc)
	return err
}

func baixarEExtrairHomolog(baseURL, dest string) error {
	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	z := html.NewTokenizer(resp.Body)
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		t := z.Token()
		if t.Type == html.StartTagToken && t.Data == "a" {
			for _, a := range t.Attr {
				if a.Key == "href" && strings.HasSuffix(a.Val, ".p7b") {
					p7bURL := a.Val
					if !strings.HasPrefix(p7bURL, "http") {
						p7bURL = baseURL + a.Val
					}

					fileName := filepath.Base(a.Val)
					p7bPath := filepath.Join(dest, fileName)
					log.Printf("[CADEIAS] Baixando p7b homolog: %s", p7bURL)
					if err := utils.DownloadFile(p7bURL, p7bPath); err != nil {
						log.Printf("[CADEIAS] Erro ao baixar %s: %v", p7bURL, err)
						continue
					}

					// Converte p7b para crt
					cmd := exec.Command("openssl", "pkcs7", "-print_certs", "-in", p7bPath)
					output, err := cmd.CombinedOutput()
					if err != nil {
						cmdDER := exec.Command("openssl", "pkcs7", "-inform", "DER", "-print_certs", "-in", p7bPath)
						output, err = cmdDER.CombinedOutput()
					}
					if err == nil {
						certBlocks := strings.Split(string(output), "-----END CERTIFICATE-----")
						for i, block := range certBlocks {
							if idx := strings.Index(block, "-----BEGIN CERTIFICATE-----"); idx != -1 {
								cert := block[idx:] + "-----END CERTIFICATE-----\n"
								crtPath := filepath.Join(dest, fmt.Sprintf("%s_%d.crt", strings.TrimSuffix(fileName, ".p7b"), i))
								os.WriteFile(crtPath, []byte(cert), 0644)
							}
						}
					}
					os.Remove(p7bPath)
				}
			}
		}
	}
	return nil
}

// normalizarCertificados reescreve os PEMs usando OpenSSL para garantir que o keytool do Java os aceite.
func normalizarCertificados(dir string) error {
	log.Println("[CADEIAS] Normalizando certificados (correção OpenSSL)...")
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".crt") || strings.HasSuffix(f.Name(), ".cer") {
			path := filepath.Join(dir, f.Name())
			tmpPath := path + ".tmp"
			// Usa openssl para ler e regravar o PEM, limpando o formato para o Java
			cmd := exec.Command("openssl", "x509", "-in", path, "-out", tmpPath)
			if err := cmd.Run(); err == nil {
				os.Rename(tmpPath, path)
			} else {
				os.Remove(tmpPath)
			}
		}
	}
	return nil
}

func gerarKeystore(certDir, keystore, password, providerPath string) error {
	os.MkdirAll(filepath.Dir(keystore), 0755)
	os.Remove(keystore)
	
	log.Printf("[CADEIAS] Gerando Keystore BKS em %s...", keystore)
	
	files, err := os.ReadDir(certDir)
	if err != nil {
		return err
	}
	
	countOk := 0
	countErr := 0

	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".crt") || strings.HasSuffix(f.Name(), ".cer") {
			alias := strings.TrimSuffix(f.Name(), filepath.Ext(f.Name()))
			certPath := filepath.Join(certDir, f.Name())
			
			cmd := exec.Command("keytool", "-importcert", "-keystore", keystore, "-storepass", password, "-file", certPath, "-alias", alias, "-storetype", "BKS", "-provider", "org.bouncycastle.jce.provider.BouncyCastleProvider", "-providerpath", providerPath, "-noprompt")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				log.Printf("[CADEIAS] Falha ao importar %s: %s", f.Name(), stderr.String())
				countErr++
			} else {
				countOk++
			}
		}
	}
	log.Printf("[CADEIAS] Total importados: %d. Falhas: %d.", countOk, countErr)
	return nil
}
