package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	hashDir   = "validacao-hash"
	targetDir = "../src/main/resources/org/demoiselle/signer/policy/engine/artifacts"
)

func main() {
	os.MkdirAll(hashDir, 0755)
	os.MkdirAll(targetDir, 0755)
	logFile, err := os.OpenFile("baixar-politicas.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Println("[ERRO] Não foi possível criar o arquivo de log:", err)
		return
	}
	defer logFile.Close()

	var mu sync.Mutex
	logMsg := func(format string, a ...interface{}) {
		mu.Lock()
		msg := fmt.Sprintf(format, a...)
		fmt.Print(msg)
		logFile.WriteString(msg)
		mu.Unlock()
	}

	f, err := os.Open("politicas.txt")
	if err != nil {
		logMsg("[ERRO] Não foi possível abrir politicas.txt: %v\n", err)
		return
	}
	defer f.Close()

	var wg sync.WaitGroup
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url == "" || !(strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")) {
			continue
		}
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			logMsg("Baixando arquivo: %s\n", url)
			fileName := filepath.Base(url)
			tmpFile := filepath.Join(hashDir, fileName)
			err := downloadFile(url, tmpFile)
			if err != nil {
				logMsg("[ERRO] Falha ao baixar %s: %v\n", url, err)
				return
			}
			// Só valida hash se não for arquivo '-sha256.txt'
			if !strings.HasSuffix(fileName, "-sha256.txt") {
				// Tenta baixar o hash
				hashURL := url + "-sha256.txt"
				hashFile := filepath.Join(hashDir, fileName+"-sha256.txt")
				err = downloadFile(hashURL, hashFile)
				if err != nil {
					logMsg("[ERRO] Falha ao baixar hash %s: %v\n", hashURL, err)
					os.Remove(tmpFile)
					return
				}
				// Valida hash
				valid, err, expected, actual := validateSHA256(tmpFile, hashFile)
				if err != nil {
					logMsg("[ERRO] Falha ao validar hash de %s: %v\n", tmpFile, err)
					os.Remove(tmpFile)
					os.Remove(hashFile)
					return
				}
				if valid {
					dest := filepath.Join(targetDir, fileName)
					err := os.Rename(tmpFile, dest)
					if err != nil {
						logMsg("[ERRO] Falha ao mover %s para %s: %v\n", tmpFile, dest, err)
						os.Remove(tmpFile)
					} else {
						logMsg("[OK] Hash válido para %s\n[OK] Esperado: %s\n[OK] Calculado: %s\n[OK] Arquivo %s validado e movido para %s\n", fileName, expected, actual, fileName, dest)
					}
				} else {
					logMsg("[ERRO] Hash inválido para %s\n[ERRO] Esperado: %s\n[ERRO] Calculado: %s\n", fileName, expected, actual)
					// Mantém arquivo e hash em validacao-hash para análise
				}
				os.Remove(hashFile)
			} else {
				// Apenas baixa o arquivo de hash, não valida
				logMsg("[INFO] Arquivo de hash baixado: %s\n", tmpFile)
			}
		}(url)
	}
	wg.Wait()
}
func downloadFile(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func validateSHA256(filePath, hashPath string) (bool, error, string, string) {
	hashF, err := os.Open(hashPath)
	if err != nil {
		return false, err, "", ""
	}
	defer hashF.Close()
	scanner := bufio.NewScanner(hashF)
	scanner.Scan()
	expected := strings.Fields(scanner.Text())[0]
	// Detecta se o arquivo de hash é HTML (erro de download)
	if strings.HasPrefix(expected, "<html>") {
		return false, fmt.Errorf("Arquivo de hash baixado é HTML (erro de download ou 404)."), expected, ""
	}

	f, err := os.Open(filePath)
	if err != nil {
		return false, err, expected, ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err, expected, ""
	}
	actual := hex.EncodeToString(h.Sum(nil))
	return actual == expected, nil, expected, actual
}
