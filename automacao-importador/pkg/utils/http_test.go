package utils

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestDownloadFile(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("teste download"))
	}))
	defer ts.Close()

	testFile := "teste_download.txt"
	err := DownloadFile(ts.URL, testFile)
	if err != nil {
		t.Fatalf("Esperava nil, recebeu %v", err)
	}
	defer os.Remove(testFile)

	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Erro ao ler arquivo criado: %v", err)
	}

	if string(content) != "teste download" {
		t.Fatalf("Esperava 'teste download', recebeu %s", content)
	}
}
