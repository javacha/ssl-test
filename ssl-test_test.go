package main

import "testing"

func Test_getServerURL(t *testing.T) {
	testURLs := [5]string{
		"http://www.javacha.com",
		"https://www.javacha.com",
		"www.javacha.com",
		"www.javacha.com/index",
		"https://www.javacha.com/files/12",
	}

	for _, url := range testURLs {
		result := getServerURL(url)
		expected := "www.javacha.com"
		if result != expected {
			t.Errorf("getServerURL(%s) ==> %s, expected %s", url, result, expected)
		}
	}

}
