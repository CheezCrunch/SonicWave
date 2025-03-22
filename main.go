package main

import (
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

type Config struct {
	Wordlist  string   `json:"wordlist"`
	Hashes    []string `json:"hashes"`
	Algorithm string   `json:"algorithm"`
}

func hashAreEqual(hash1 []byte, hash2 []byte) int {
	return subtle.ConstantTimeCompare(hash1, hash2)
}

func createDictionary(configFile string) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalln("[!] ", err)
	}

	var config Config

	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatalln("[!] ", err)
	}

	data, err = os.ReadFile(config.Wordlist)
	if err != nil {
		log.Fatalln("[!] ", err)
	}

	words := strings.Split(string(data), "\n")

	hash := sha256.New()
	switch config.Algorithm {
	case "sha512":
		hash = sha512.New()
	case "sha1":
		hash = sha1.New()
	case "md5":
		hash = md5.New()
	case "blake2":
		hash = crypto.BLAKE2b_256.New()
	}

	for _, word := range words {
		hash.Write([]byte(word))
		bytes := hash.Sum(nil)
		hexData := hex.EncodeToString(bytes)

		for _, hash := range config.Hashes {
			if hashAreEqual([]byte(hash), []byte(hexData)) == 1 {
				fmt.Println("[+] FOUND MATCHING HASH!")
				fmt.Println("[-] ORIGINAL HASH:", hash)
				fmt.Println("[-] USER HASH:", hexData)
				fmt.Println("[-] WORD:", word)
			}
		}
	}
}

func main() {
	configFile := flag.String("c", "config.json", "The config file to parse")

	flag.Parse()

	createDictionary(*configFile)
}
