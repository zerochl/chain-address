package bip39Helper

import (
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
	"strings"
	"regexp"
)

func isChineseMnemonic(mnemonic string) (bool) {
	words := strings.Fields(mnemonic)
	var hzRegexp = regexp.MustCompile("^[\u4e00-\u9fa5]$")
	if hzRegexp.MatchString(words[0]) {
		return true
	} else {
		return false
	}
}

func EntropyFromMnemonic(mnemonic string) ([]byte, error) {
	SetWordListByMnemonic(mnemonic)
	return bip39.EntropyFromMnemonic(mnemonic)
}

func NewEnglishMnemonic(entropy []byte) (string, error) {
	bip39.SetWordList(wordlists.English)
	return bip39.NewMnemonic(entropy)
}

func NewChineseMnemonic(entropy []byte) (string, error) {
	bip39.SetWordList(wordlists.ChineseSimplified)
	return bip39.NewMnemonic(entropy)
}

func GetEnglishMnemonic(mnemonic string) (string, error) {
	entropy, err := EntropyFromMnemonic(mnemonic)
	if err != nil {
		return "", err
	}
	return NewEnglishMnemonic(entropy)
}

func GetChineseMnemonic(mnemonic string) (string, error) {
	entropy, err := EntropyFromMnemonic(mnemonic)
	if err != nil {
		return "", err
	}
	return NewChineseMnemonic(entropy)
}

func SetWordListByMnemonic(mnemonic string)  {
	isChinese := isChineseMnemonic(mnemonic)
	if isChinese {
		bip39.SetWordList(wordlists.ChineseSimplified)
	} else {
		bip39.SetWordList(wordlists.English)
	}
}