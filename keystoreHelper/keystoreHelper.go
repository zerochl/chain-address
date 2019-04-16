package keystoreHelper

import (
	"os"
	"io/ioutil"
	"log"
	"convertAddress/bip39Helpher"
	"github.com/tyler-smith/go-bip39"
	"mykey/thirdparty/go-ethereum/accounts/keystore"
	"mykey/thirdparty/go-ethereum/crypto"
)

func prepareKeystore(keystorePath, password string) (encryptPassword string, ks *keystore.KeyStore, err error) {
	os.MkdirAll(keystorePath, 0777)
	dir, err := ioutil.TempDir(keystorePath, "zero-keystore")
	if err != nil {
		log.Println("in prepareKeystore TempDir error:", err.Error())
		return "", nil, err
	}
	// 创建ETH Keystore对象
	ks = keystore.NewKeyStore(
		dir,
		keystore.LightScryptN,
		keystore.LightScryptP)
	return password, ks, nil
}

func CreateMnemonicKeystore(mnemonic, keystorePath, password string) {
	englishMnemonic, err := bip39Helper.GetEnglishMnemonic(mnemonic)
	if err != nil {
		return
	}
	encryptPassword, ks, err := prepareKeystore(keystorePath, password)
	if err != nil {
		log.Println("in CreateMnemonicKeystore prepareKeystore error:", err.Error())
		return
	}
	entropy, err := bip39Helper.EntropyFromMnemonic(englishMnemonic)
	if err != nil {
		log.Println("in CreateMnemonicKeystore EntropyFromMnemonic error:", err.Error())
		return
	}
	privateByte, err := getPrivateByteByEntropy(entropy)
	if err != nil {
		log.Println("in CreateMnemonicKeystore getPrivateByteByEntropy error:", err.Error())
		return
	}
	keystoreJson, err := keystoreHexAccountByPrivateByte(privateByte, ks, password, encryptPassword)
	if err != nil {
		log.Println("in CreateKeystoreByPrivateHex keystoreHexAccountByPrivateByte error:", err.Error())
		return
	}
	log.Println("keystore json:", keystoreJson)
}

func getPrivateByteByEntropy(entropy []byte) ([]byte, error) {
	newEntropy, err := bip39.NewEntropy(128)
	if err != nil {
		return nil, err
	}
	privateByte := make([]byte, 32)
	for index, realItem := range entropy {
		privateByte[index] = realItem
	}
	for index, newItem := range newEntropy {
		privateByte[index + 16] = newItem
	}
	return privateByte, nil
}

func keystoreHexAccountByPrivateByte(privateByte []byte, ks *keystore.KeyStore, passwordKey, operationKeyEncryptPassword string) (string, error) {
	privateKey, err := crypto.ToECDSA(privateByte)
	if err != nil {
		log.Println("in CreateKeystoreInMemory crypto.ToECDSA error:", err.Error())
		return "", err
	}
	// 生成以太坊keystore的一条记录
	_, encryptKeyJson, err := ks.ImportECDSAInMemory(privateKey, passwordKey)
	if err != nil {
		log.Println("in CreateKeystoreInMemory ks.ImportECDSAInMemory error:", err.Error())
		return "", err
	}
	return string(encryptKeyJson), nil
}