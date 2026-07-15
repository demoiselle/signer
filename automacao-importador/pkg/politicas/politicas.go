package politicas

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"automacao-importador/pkg/utils"
)

type Config struct {
	Env           string
	PoliticasFile string
	TargetDir     string
}

func AtualizarPoliticas(cfg Config) error {
	log.Printf("[POLÍTICAS] Iniciando atualização para ambiente: %s", cfg.Env)

	if cfg.Env == "hom" {
		log.Println("[POLÍTICAS] Homologação não processa políticas nesta ferramenta no momento.")
		return nil
	}

	workDir := "tmp_politicas"
	os.RemoveAll(workDir)
	os.MkdirAll(workDir, 0755)
	defer os.RemoveAll(workDir)

	os.MkdirAll(cfg.TargetDir, 0755)

	f, err := os.Open(cfg.PoliticasFile)
	if err != nil {
		return fmt.Errorf("não foi possível abrir lista de políticas %s: %v", cfg.PoliticasFile, err)
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.Index(line, "http"); idx != -1 {
			urls = append(urls, line[idx:])
		}
	}

	var wg sync.WaitGroup
	for _, url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			fileName := filepath.Base(u)
			tmpFile := filepath.Join(workDir, fileName)

			if err := utils.DownloadFile(u, tmpFile); err != nil {
				log.Printf("[ERRO] Baixando %s: %v", u, err)
				return
			}

			if !strings.HasSuffix(fileName, "-sha256.txt") {
				hashURL := u + "-sha256.txt"
				hashFile := filepath.Join(workDir, fileName+"-sha256.txt")
				if err := utils.DownloadFile(hashURL, hashFile); err == nil {
					valid, expected, actual := validateSHA256(tmpFile, hashFile)
					if valid {
						dest := filepath.Join(cfg.TargetDir, fileName)
						os.Rename(tmpFile, dest)
						log.Printf("[OK] %s", fileName)
					} else {
						log.Printf("[ERRO] Hash %s (Esp: %s, Calc: %s)", fileName, expected, actual)
					}
				} else {
					log.Printf("[AVISO] Arquivo %s sem hash disponível", fileName)
					// Copia mesmo sem hash se não tem
					dest := filepath.Join(cfg.TargetDir, fileName)
					os.Rename(tmpFile, dest)
				}
			}
		}(url)
	}
	wg.Wait()
	log.Println("[POLÍTICAS] Processo concluído.")
	return nil
}

func validateSHA256(filePath, hashPath string) (bool, string, string) {
	hashF, err := os.Open(hashPath)
	if err != nil {
		return false, "", ""
	}
	defer hashF.Close()
	scanner := bufio.NewScanner(hashF)
	scanner.Scan()
	expected := strings.Fields(scanner.Text())[0]

	f, err := os.Open(filePath)
	if err != nil {
		return false, expected, ""
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	actual := hex.EncodeToString(h.Sum(nil))
	return actual == expected, expected, actual
}
