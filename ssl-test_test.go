package main

import "testing"

func Test_getServerURL(t *testing.T) {
	testURLs := [5]string{
		"http://www.javacha.com",
		"https://www.javacha.com",
		"www.javacha.com",
		"www.javacha.com/index",
		"https://www.javacha.com/files:443/12",
	}

	for _, url := range testURLs {
		result := getServerURL(url)
		expected := "www.javacha.com"
		if result != expected {
			t.Errorf("getServerURL(%s) ==> %s, expected %s", url, result, expected)
		}
	}

}

func Test_loadCacerts(t *testing.T) {
	pemFile := "testing/ok.pem"
	result := loadCacerts(pemFile)
	//expected := "hola"
	if result == nil {
		t.Errorf("loadCacerts(%s) => nil, expected []byte", pemFile)
	}

	pemFile = "testing/DO_NOT_EXISTs.pem"
	result = loadCacerts(pemFile)
	if result != nil {
		t.Errorf("loadCacerts(%s) => []byte, expected nil", pemFile)
	}
}
