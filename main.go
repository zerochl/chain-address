package main

import (
	"encoding/hex"
	"github.com/eoscanada/eos-go/ecc"
	"convertAddress/thirdpart/hdwallet"
	"log"
	"github.com/eoscanada/eos-go/btcsuite/btcutil"
	"github.com/eoscanada/eos-go/btcsuite/btcd/btcec"
	"flag"
	"github.com/tyler-smith/go-bip39"
	"mykey/thirdparty/go-ethereum/common/hexutil"
	"convertAddress/bip39Helpher"
	"convertAddress/keystoreHelper"
	"mykey/thirdparty/go-ethereum/crypto"
)

//2018/11/07 20:32:16 mnemonic: middle market permit snow slight blanket card armed magic hole mammal enter
//2018/11/07 20:32:16 ETHPrivate: 948be7b7ac1ac60c7956184e81ae8a0082f884e6ec7f273e18e80eae0373602f
//2018/11/07 20:32:16 ETHAddress: 0xAcafB03aa4694F59DbE29aAF484eEbaBC529B97F
//2018/11/07 20:32:16 EosPrivate: 5Jwi16z6aoErWTL6jG7fASDLPaaib2AjT5NM9o4esVEuuCwJ9Eu
//2018/11/07 20:32:16 EosAddress: EOS6NpLe5YRbx7Wg47gQCFMp6SnnReta7xUrYUanYbWYWX2QZgxSa
func main()  {
	cmd := flag.String("cmd", "", "create or ethtoeos or eostoeth")
	private := flag.String("private", "", "私钥")
	public := flag.String("public", "", "私钥")
	entropy := flag.String("entropy", "", "entropy")
	mnemonic := flag.String("mnemonic", "", "助记词")
	path := flag.String("path", "", "本机文件路径")
	password := flag.String("password", "", "密码")
	flag.Parse()
	switch *cmd {
	case "create":
		ethPrivate()
		break
	case "ethtoeos":
		// 948be7b7ac1ac60c7956184e81ae8a0082f884e6ec7f273e18e80eae0373602f
		ethPrivateToEosPrivate(*private)
		break
	case "ethpubtoeos":
		// 948be7b7ac1ac60c7956184e81ae8a0082f884e6ec7f273e18e80eae0373602f
		ethPublicToEosPub(*public)
		break
	case "eostoeth":
		// 5Jwi16z6aoErWTL6jG7fASDLPaaib2AjT5NM9o4esVEuuCwJ9Eu
		eosPrivateToETHPrivate(*private)
		break
	case "eospubtoeth":
		// 5Jwi16z6aoErWTL6jG7fASDLPaaib2AjT5NM9o4esVEuuCwJ9Eu
		eosPrivateToETHPrivate(*private)
		break
	case "bitpie":
		recoveryMnemonic(*entropy)
		break
	case "toEnglish":
		toEnglishMnemonic(*mnemonic)
		break
	case "toChinese":
		toChineseMnemonic(*mnemonic)
		break
	case "saveMnemonic":
		saveMnemonic(*mnemonic, *path, *password)
		break
	}
}

func saveMnemonic(mnemonic, path, password string)  {
	log.Println("mnemonic:", mnemonic)
	keystoreHelper.CreateMnemonicKeystore(mnemonic, path, password)
}

func toEnglishMnemonic(mnemonic string) {
	englishMnemonic, err := bip39Helper.GetEnglishMnemonic(mnemonic)
	if err != nil {
		log.Println("GetEnglishMnemonic error:", err.Error())
		return
	}
	log.Println("englishMnemonic:", englishMnemonic)
	return
}


func toChineseMnemonic(mnemonic string) {
	chineseMnemonic, err := bip39Helper.GetChineseMnemonic(mnemonic)
	if err != nil {
		log.Println("GetChineseMnemonic error:", err.Error())
		return
	}
	log.Println("chineseMnemonic:", chineseMnemonic)
	return
}

func recoveryMnemonic(entropy string)  {
	entropyByte, _ :=  hex.DecodeString(entropy)
	str, _ := bip39.NewMnemonic(entropyByte)
	log.Println("mnemonic:", str)
}

func ethPrivate()  {
	mnemonic, _ := hdwallet.NewMnemonic(128)
	log.Println("mnemonic:", mnemonic)
	wallet, err := hdwallet.NewWalletFromMnemonic(mnemonic)
	if err != nil {
		return
	}
	log.Println("ETHPrivate:", hex.EncodeToString(wallet.Key[1:]))
	privateKey, err := crypto.ToECDSA(wallet.Key[1:])
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	log.Println("ETHAddress:", address.String())

	wifFromETH, err := convertToWif(hex.EncodeToString(wallet.Key))
	if err != nil {
		return
	}
	log.Println("EosPrivate:", wifFromETH.String())
	privatekey, err := ecc.NewPrivateKey(wifFromETH.String())
	if err != nil {
		log.Println("err:", err.Error())
		return
	}
	log.Println("EosAddress:", privatekey.PublicKey().String())
}

func ethPrivateToEosPrivate(ethPrivateHex string)  {
	wifFromETH, err := convertToWif(ethPrivateHex)
	if err != nil {
		log.Println("in ethPrivateToEosPrivate convertToWif err:", err.Error())
		return
	}
	privatekey, err := ecc.NewPrivateKey(wifFromETH.String())
	if err != nil {
		log.Println("in ethPrivateToEosPrivate NewPrivateKey err:", err.Error())
		return
	}
	log.Println("EOSPrivate:", wifFromETH.String())
	log.Println("EosAddress:", privatekey.PublicKey().String())
}

func ethPublicToEosPub(ethPubHex string) {
	ethPubByte, err := hexutil.Decode(ethPubHex)
	if err != nil {
		log.Println("error in ethPublicToEosPrivate:", err.Error())
		return
	}
	log.Println("length:", len(ethPubByte))
	eosPub := &ecc.PublicKey{Curve:ecc.CurveK1, Content:ethPubByte}
	log.Println("eos pub:", eosPub.String())
}

func eosPrivateToETHPrivate(eosPrivate string)  {
	ethPrivateHex, err := convertToETHPriKey(eosPrivate)
	if err != nil {
		log.Println("in eosPrivateToETHPrivate convertToETHPriKey err:", err.Error())
		return
	}
	ethPrivateByte, err := hex.DecodeString(ethPrivateHex)
	if err != nil {
		log.Println("in eosPrivateToETHPrivate DecodeString err:", err.Error())
		return
	}
	privateKey, err := crypto.ToECDSA(ethPrivateByte)
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	log.Println("ETHPrivate:", ethPrivateHex)
	log.Println("ETHAddress:", address.String())
}

func eosPublicToETHPrivate(eosPrivate string)  {
	ethPrivateHex, err := convertToETHPriKey(eosPrivate)
	if err != nil {
		log.Println("in eosPrivateToETHPrivate convertToETHPriKey err:", err.Error())
		return
	}
	ethPrivateByte, err := hex.DecodeString(ethPrivateHex)
	if err != nil {
		log.Println("in eosPrivateToETHPrivate DecodeString err:", err.Error())
		return
	}
	privateKey, err := crypto.ToECDSA(ethPrivateByte)
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	log.Println("ETHPrivate:", ethPrivateHex)
	log.Println("ETHAddress:", address.String())
}

func convertToWif(privateKeyHex string) (wifFromETH *btcutil.WIF, err error) {
	privateKeyByte, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, err
	}
	privateKeyForBTC, _ := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyByte)
	wifFromETH, err = btcutil.NewWIF(privateKeyForBTC, 0x80, false)
	if err != nil {
		return nil, err
	}
	return wifFromETH, err
}

func convertToETHPriKey(wif string) (string, error) {
	priKeyEOS, err := ecc.NewPrivateKey(wif)
	if err != nil {
		return "", err
	}
	privateKeyETH := priKeyEOS.PrivateKey()
	return hex.EncodeToString(privateKeyETH.Serialize()), nil
}
