package hdwallet

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/btcsuite/btcutil/base58"
	"strings"
	"fmt"
	"math"
)

var (
	//MainNet
	Public  []byte
	Private []byte
	//TestNet
	TestPublic  []byte
	TestPrivate []byte
	// DefaultRootDerivationPath is the root path to which custom derivation endpoints
	// are appended. As such, the first account will be at m/44'/60'/0'/0, the second
	// at m/44'/60'/0'/1, etc.
	DefaultRootDerivationPath = DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0}
)

type DerivationPath []uint32

// HDWallet defines the components of a hierarchical deterministic wallet
type HDWallet struct {
	Vbytes      []byte //4 bytes
	Depth       uint16 //1 byte
	Fingerprint []byte //4 bytes
	I           []byte //4 bytes
	Chaincode   []byte //32 bytes
	Key         []byte //33 bytes
}

func init() {
	Public, _ = hex.DecodeString("0488B21E")
	Private, _ = hex.DecodeString("0488ADE4")
	TestPublic, _ = hex.DecodeString("043587CF")
	TestPrivate, _ = hex.DecodeString("04358394")
}

// Child returns the ith child of wallet w. Values of i >= 2^31
// signify private key derivation. Attempting private key derivation
// with a public key will throw an error.
func (w *HDWallet) Child(i uint32) (*HDWallet, error) {
	var fingerprint, I, newkey []byte
	switch {
	case bytes.Compare(w.Vbytes, Private) == 0, bytes.Compare(w.Vbytes, TestPrivate) == 0:
		pub := privToPub(w.Key)
		mac := hmac.New(sha512.New, w.Chaincode)
		if i >= uint32(0x80000000) {
			mac.Write(append(w.Key, uint32ToByte(i)...))
		} else {
			mac.Write(append(pub, uint32ToByte(i)...))
		}
		I = mac.Sum(nil)
		iL := new(big.Int).SetBytes(I[:32])
		if iL.Cmp(curve.N) >= 0 || iL.Sign() == 0 {
			return &HDWallet{}, errors.New("Invalid Child")
		}
		newkey = addPrivKeys(I[:32], w.Key)
		fingerprint = hash160(privToPub(w.Key))[:4]

	case bytes.Compare(w.Vbytes, Public) == 0, bytes.Compare(w.Vbytes, TestPublic) == 0:
		mac := hmac.New(sha512.New, w.Chaincode)
		if i >= uint32(0x80000000) {
			return &HDWallet{}, errors.New("Can't do Private derivation on Public key!")
		}
		mac.Write(append(w.Key, uint32ToByte(i)...))
		I = mac.Sum(nil)
		iL := new(big.Int).SetBytes(I[:32])
		if iL.Cmp(curve.N) >= 0 || iL.Sign() == 0 {
			return &HDWallet{}, errors.New("Invalid Child")
		}
		newkey = addPubKeys(privToPub(I[:32]), w.Key)
		fingerprint = hash160(w.Key)[:4]
	}
	return &HDWallet{w.Vbytes, w.Depth + 1, fingerprint, uint32ToByte(i), I[32:], newkey}, nil
}

// Serialize returns the serialized form of the wallet.
func (w *HDWallet) Serialize() []byte {
	depth := uint16ToByte(uint16(w.Depth % 256))
	//bindata = vbytes||depth||fingerprint||i||chaincode||key
	bindata := append(w.Vbytes, append(depth, append(w.Fingerprint, append(w.I, append(w.Chaincode, w.Key...)...)...)...)...)
	chksum := dblSha256(bindata)[:4]
	return append(bindata, chksum...)
}

// Serialize returns the serialized form of the wallet.
// 所有参数均使用copy，防止内存共享造成异常
func (w *HDWallet) SerializeNoSense() []byte {
	depth := uint16ToByte(uint16(w.Depth % 256))
	//bindata = vbytes||depth||fingerprint||i||chaincode||key
	Vbytes := copyByte(w.Vbytes)

	Fingerprint := copyByte(w.Fingerprint)

	I := copyByte(w.I)

	Chaincode := copyByte(w.Chaincode)

	Key := copyByte(w.Key)

	bindata := append(Vbytes, append(depth, append(Fingerprint, append(I, append(Chaincode, Key...)...)...)...)...)
	chksum := dblSha256(bindata)[:4]
	return append(bindata, chksum...)
}

// String returns the base58-encoded string form of the wallet.
// 注意使用了此方法之后此钱包对象就失效了，因为byte参数被转换
func (w *HDWallet) String() string {
	return base58.Encode(w.Serialize())
}

// String returns the base58-encoded string form of the wallet.
// 无感转换string格式
func (w *HDWallet) StringNoSense() string {
	return base58.Encode(w.SerializeNoSense())
}

// StringWallet returns a wallet given a base58-encoded extended key
func StringWallet(data string) (*HDWallet, error) {
	dbin := base58.Decode(data)
	if err := ByteCheck(dbin); err != nil {
		return &HDWallet{}, err
	}
	if bytes.Compare(dblSha256(dbin[:(len(dbin) - 4)])[:4], dbin[(len(dbin) - 4):]) != 0 {
		return &HDWallet{}, errors.New("Invalid checksum")
	}
	vbytes := dbin[0:4]
	depth := byteToUint16(dbin[4:5])
	fingerprint := dbin[5:9]
	i := dbin[9:13]
	chaincode := dbin[13:45]
	key := dbin[45:78]
	return &HDWallet{vbytes, depth, fingerprint, i, chaincode, key}, nil
}

// Pub returns a new wallet which is the public key version of w.
// If w is a public key, Pub returns a copy of w
func (w *HDWallet) Pub() *HDWallet {
	if bytes.Compare(w.Vbytes, Public) == 0 {
		return &HDWallet{w.Vbytes, w.Depth, w.Fingerprint, w.I, w.Chaincode, w.Key}
	} else {
		return &HDWallet{Public, w.Depth, w.Fingerprint, w.I, w.Chaincode, privToPub(w.Key)}
	}
}

// StringChild returns the ith base58-encoded extended key of a base58-encoded extended key.
func StringChild(data string, i uint32) (string, error) {
	w, err := StringWallet(data)
	if err != nil {
		return "", err
	} else {
		w, err = w.Child(i)
		if err != nil {
			return "", err
		} else {
			return w.String(), nil
		}
	}
}

//StringToAddress returns the Bitcoin address of a base58-encoded extended key.
func StringAddress(data string) (string, error) {
	w, err := StringWallet(data)
	if err != nil {
		return "", err
	} else {
		return w.Address(), nil
	}
}

// Address returns bitcoin address represented by wallet w.
func (w *HDWallet) Address() string {
	x, y := expand(w.Key)
	four, _ := hex.DecodeString("04")
	padded_key := append(four, append(x.Bytes(), y.Bytes()...)...)
	var prefix []byte
	if bytes.Compare(w.Vbytes, TestPublic) == 0 || bytes.Compare(w.Vbytes, TestPrivate) == 0 {
		prefix, _ = hex.DecodeString("6F")
	} else {
		prefix, _ = hex.DecodeString("00")
	}
	addr_1 := append(prefix, hash160(padded_key)...)
	chksum := dblSha256(addr_1)
	return base58.Encode(append(addr_1, chksum[:4]...))
}

// GenSeed returns a random seed with a length measured in bytes.
// The length must be at least 128.
func GenSeed(length int) ([]byte, error) {
	b := make([]byte, length)
	if length < 128 {
		return b, errors.New("length must be at least 128 bits")
	}
	_, err := rand.Read(b)
	return b, err
}

// MasterKey returns a new wallet given a random seed.
func MasterKey(seed []byte) *HDWallet {
	key := []byte("Bitcoin seed")
	mac := hmac.New(sha512.New, key)
	mac.Write(seed)
	I := mac.Sum(nil)
	secret := I[:len(I)/2]
	chain_code := I[len(I)/2:]
	depth := 0
	i := make([]byte, 4)
	fingerprint := make([]byte, 4)
	zero := make([]byte, 1)
	return &HDWallet{Private, uint16(depth), fingerprint, i, chain_code, append(zero, secret...)}
}

// StringCheck is a validation check of a base58-encoded extended key.
func StringCheck(key string) error {
	return ByteCheck(base58.Decode(key))
}

func ByteCheck(dbin []byte) error {
	// check proper length
	if len(dbin) != 82 {
		return errors.New("invalid string")
	}
	// check for correct Public or Private vbytes
	if bytes.Compare(dbin[:4], Public) != 0 && bytes.Compare(dbin[:4], Private) != 0 && bytes.Compare(dbin[:4], TestPublic) != 0 && bytes.Compare(dbin[:4], TestPrivate) != 0 {
		return errors.New("invalid string")
	}
	// if Public, check x coord is on curve
	x, y := expand(dbin[45:78])
	if bytes.Compare(dbin[:4], Public) == 0 || bytes.Compare(dbin[:4], TestPublic) == 0 {
		if !onCurve(x, y) {
			return errors.New("invalid string")
		}
	}
	return nil
}

func ParseDerivationPath(path string) (DerivationPath, error) {
	var result DerivationPath

	// Handle absolute or relative paths
	components := strings.Split(path, "/")
	switch {
	case len(components) == 0:
		return nil, errors.New("empty derivation path")

	case strings.TrimSpace(components[0]) == "":
		return nil, errors.New("ambiguous path: use 'm/' prefix for absolute paths, or no leading '/' for relative ones")

	case strings.TrimSpace(components[0]) == "m":
		components = components[1:]

	default:
		result = append(result, DefaultRootDerivationPath...)
	}
	// All remaining components are relative, append one by one
	if len(components) == 0 {
		return nil, errors.New("empty derivation path") // Empty relative paths
	}
	for _, component := range components {
		// Ignore any user added whitespace
		component = strings.TrimSpace(component)
		var value uint32

		// Handle hardened paths
		if strings.HasSuffix(component, "'") {
			value = 0x80000000
			component = strings.TrimSpace(strings.TrimSuffix(component, "'"))
		}
		// Handle the non hardened component
		bigval, ok := new(big.Int).SetString(component, 0)
		if !ok {
			return nil, fmt.Errorf("invalid component: %s", component)
		}
		max := math.MaxUint32 - value
		if bigval.Sign() < 0 || bigval.Cmp(big.NewInt(int64(max))) > 0 {
			if value == 0 {
				return nil, fmt.Errorf("component %v out of allowed range [0, %d]", bigval, max)
			}
			return nil, fmt.Errorf("component %v out of allowed hardened range [0, %d]", bigval, max)
		}
		value += uint32(bigval.Uint64())

		// Append and repeat
		result = append(result, value)
	}
	return result, nil
}
