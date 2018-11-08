package hdwallet

import (
	"github.com/tyler-smith/go-bip39"
	"log"
	"errors"
)

var (
	deriveFromStringError = errors.New("in deriveFromString error, length less than zero")
)

// bitSize must be a multiple of 32
func NewMnemonic(bitSize int) (string, error) {
	entropy, e := bip39.NewEntropy(bitSize)
	if e != nil {
		return "", e
	}
	m, e := bip39.NewMnemonic(entropy)
	return m, e
}

func NewSeed() ([]byte, error) {
	mnemonic, err := NewMnemonic(128)
	if err != nil {
		log.Println("in NewMnemonic error:", err.Error())
		return nil, err
	}
	return NewSeedFromMnemonic(mnemonic)
}

func NewSeedFromMnemonicWithPassword(mnemonic, password string) ([]byte, error) {
	return bip39.NewSeedWithErrorChecking(mnemonic, password)
}

// NewSeedFromMnemonic returns a BIP-39 seed based on a BIP-39 mnemonic.
func NewSeedFromMnemonic(mnemonic string) ([]byte, error) {
	return NewSeedFromMnemonicWithPassword(mnemonic, "")
}

func NewWalletFromMnemonic(mnemonic string) (*HDWallet, error)  {
	seed, err := NewSeedFromMnemonic(mnemonic)
	if err != nil {
		log.Println("in NewSeedFromMnemonic error:", err.Error())
		return nil, err
	}
	return MasterKey(seed), nil
}

func (w *HDWallet) GetChildByBip44(bip44Path string) (*HDWallet, error) {
	indexs, err := ParseDerivationPath(bip44Path)
	if err != nil {
		log.Println("in ParseDerivationPath error:", err.Error())
		return nil, err
	}
	if len(indexs) <= 0 {
		return nil, deriveFromStringError
	}
	subExtKey := w
	for _, index := range indexs {
		extKey, err := subExtKey.Child(index)
		if err != nil {
			return nil, err
		}
		subExtKey = extKey
		//log.Printf("subExtKey: %d, %s", index, subExtKey.String())
	}
	return subExtKey, nil
}