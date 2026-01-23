
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
		hashDir      = "validacao-hash"
		politicasDir = "politicas-baixadas"
		targetDir    = "../src/main/resources/org/demoiselle/signer/policy/engine/artifacts"
		logFile      = "baixar-politicas.log"
		politicasTxt = "politicas.txt"
	)

	var logMutex sync.Mutex

	func logMsg(format string, args ...interface{}) {
		logMutex.Lock()
		defer logMutex.Unlock()
		msg := fmt.Sprintf(format, args...)
		fmt.Print(msg)
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			defer f.Close()
			f.WriteString(msg)
		}
	}

	func cleanDir(dir string) {
		files, _ := os.ReadDir(dir)
		for _, file := range files {
			os.RemoveAll(filepath.Join(dir, file.Name()))
		}
	}

	func main() {
		os.MkdirAll(hashDir, 0755)
		os.MkdirAll(politicasDir, 0755)
		os.MkdirAll(targetDir, 0755)
		cleanDir(hashDir)
		cleanDir(politicasDir)

		f, err := os.Open(politicasTxt)
		if err != nil {
			logMsg("[ERRO] Não foi possível abrir %s: %v\n", politicasTxt, err)
			return
		}
		defer f.Close()

		var wg sync.WaitGroup
		var total, baixadas, erros int
		var muCount sync.Mutex
		var urls []string
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if idx := strings.Index(line, "http"); idx != -1 {
				urls = append(urls, line[idx:])
			}
		}
		total = len(urls)
		total = len(urls)
		for _, url := range urls {
			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				fileName := filepath.Base(url)
				var tmpFile string
				if strings.HasSuffix(fileName, "-sha256.txt") {
					tmpFile = filepath.Join(hashDir, fileName)
				} else {
					tmpFile = filepath.Join(politicasDir, fileName)
				}
				logMsg("Baixando arquivo: %s\n", url)
				err := downloadFile(url, tmpFile)
				if err != nil {
					logMsg("[ERRO] Falha ao baixar %s: %v\n", url, err)
					muCount.Lock()
					erros++
					muCount.Unlock()
					return
				}
				muCount.Lock()
				baixadas++
				muCount.Unlock()
				// Só valida hash se não for arquivo '-sha256.txt'
				if !strings.HasSuffix(fileName, "-sha256.txt") {
					// Tenta baixar o hash
					hashURL := url + "-sha256.txt"
					hashFile := filepath.Join(hashDir, fileName+"-sha256.txt")
					err = downloadFile(hashURL, hashFile)
					if err != nil {
						logMsg("[ERRO] Falha ao baixar hash %s: %v\n", hashURL, err)
						// Mantém política baixada mesmo com erro de hash
						return
					}
					// Valida hash
					valid, err, expected, actual := validateSHA256(tmpFile, hashFile)
					if err != nil {
						logMsg("[ERRO] Falha ao validar hash de %s: %v\n", tmpFile, err)
						// Mantém política baixada mesmo com erro de hash
						os.Remove(hashFile)
						return
					}
					if valid {
						dest := filepath.Join(targetDir, fileName)
						err := os.Rename(tmpFile, dest)
						if err != nil {
							logMsg("[ERRO] Falha ao mover %s para %s: %v\n", tmpFile, dest, err)
							// Mantém política baixada mesmo com erro de mover
						}
						logMsg("[OK] Hash válido para %s\n[OK] Esperado: %s\n[OK] Calculado: %s\n[OK] Arquivo %s validado e movido para %s\n", fileName, expected, actual, fileName, dest)
					}
					if !valid {
						logMsg("[ERRO] Hash inválido para %s\n[ERRO] Esperado: %s\n[ERRO] Calculado: %s\n", fileName, expected, actual)
						// Mantém política baixada mesmo com erro de hash
					}
					os.Remove(hashFile)
				} else {
					// Apenas baixa o arquivo de hash, não valida
					logMsg("[INFO] Arquivo de hash baixado: %s\n", tmpFile)
				}
			}(url)
		}
		wg.Wait()
		logMsg("\nResumo:\nTotal de políticas a serem baixadas: %d\nTotal baixadas: %d\nTotal com erro de download: %d\n", total, baixadas, erros)
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
