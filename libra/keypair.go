// Copyright © 2019 Immutability, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package libra

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"github.com/ebfe/keccak"
	"github.com/keybase/go-crypto/ed25519"
	"github.com/sethvargo/go-diceware/diceware"
	"golang.org/x/crypto/hkdf"
)

const (

	// LibraSalt is the default Libra salt
	LibraSalt string = "LIBRA"
	// PassphraseWords is for big passphrases
	PassphraseWords int = 9
	// PassphraseSeparator is how we separate words
	PassphraseSeparator string = " "
)

var (
	// ErrVerificationFailed is the message for an
	ErrVerificationFailed = errors.New("signature verification failed")
)

// HKDFReader returns the Reader, from which keys can be read, using the given hash,
// secret, salt and context info. Salt and info can be nil.
func HKDFReader(seed []byte, salt string) (io.Reader, error) {
	hash := keccak.NewSHA3256

	if _, err := rand.Read([]byte(salt)); err != nil {
		return nil, err
	}

	return hkdf.New(hash, seed, []byte(salt), nil), nil
}

// KeyPair provides the central interface.
type KeyPair interface {
	Seed() ([]byte, error)
	PublicKey() (string, error)
	Address() (string, error)
	PrivateKey() ([]byte, error)
	Sign(input []byte) ([]byte, error)
	Verify(input []byte, sig []byte) error
	Wipe()
}

// kp is the internal struct for a kepypair using seed.
type kp struct {
	seed []byte
}

// keys will return a 32 byte public key and a 64 byte private key utilizing the seed.
func (pair *kp) keys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	reader, err := HKDFReader(pair.seed, LibraSalt)
	if err != nil {
		return nil, nil, err
	}
	return ed25519.GenerateKey(reader)
}

// Wipe will randomize the contents of the seed key
func (pair *kp) Wipe() {
	io.ReadFull(rand.Reader, pair.seed)
	pair.seed = nil
}

// Seed will return the encoded seed.
func (pair *kp) Seed() ([]byte, error) {
	return Encode(pair.seed)
}

// PublicKey will return the encoded public key associated with the KeyPair.
// All KeyPairs have a public key.
func (pair *kp) PublicKey() (string, error) {
	reader, err := HKDFReader(pair.seed, LibraSalt)
	if err != nil {
		return "", err
	}
	pub, _, err := ed25519.GenerateKey(reader)
	if err != nil {
		return "", err
	}
	pk, err := Encode(pub)
	if err != nil {
		return "", err
	}
	return string(pk), nil
}

// Address will return the encoded public key associated with the KeyPair.
func (pair *kp) Address() (string, error) {
	pk, err := pair.PublicKey()
	if err != nil {
		return "", err
	}
	hash := keccak.NewSHA3256()
	hash.Write([]byte(pk))
	addressRaw := hash.Sum(nil)
	address, err := Encode(addressRaw)
	if err != nil {
		return "", err
	}
	return string(address), nil
}

// PrivateKey will return the encoded private key for KeyPair.
func (pair *kp) PrivateKey() ([]byte, error) {
	_, priv, err := pair.keys()
	if err != nil {
		return nil, err
	}
	return Encode(priv)
}

// Sign will sign the input with KeyPair's private key.
func (pair *kp) Sign(input []byte) ([]byte, error) {
	_, priv, err := pair.keys()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, input), nil
}

// Verify will verify the input against a signature utilizing the public key.
func (pair *kp) Verify(input []byte, sig []byte) error {
	pub, _, err := pair.keys()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, input, sig) {
		return ErrVerificationFailed
	}
	return nil
}

// CreatePair will create a KeyPair based on the rand entropy
func CreatePair() (KeyPair, error) {
	gen, err := diceware.NewGenerator(nil)
	if err != nil {
		return nil, err
	}

	list, err := gen.Generate(16)
	if err != nil {
		return nil, err
	}
	passphrase := strings.Join(list, PassphraseSeparator)

	return &kp{[]byte(passphrase)}, nil
}

// CreatePairFromSeed will create a KeyPair based on the input seed
func CreatePairFromSeed(seed string) (KeyPair, error) {
	return &kp{[]byte(seed)}, nil
}

// Encode will encode a raw key or seed
func Encode(src []byte) ([]byte, error) {
	buf := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(buf, src)

	return buf[:], nil
}

// Decode will decode the hex
func Decode(src []byte) ([]byte, error) {
	raw := make([]byte, hex.EncodedLen(len(src)))
	n, err := hex.Decode(raw, src)
	if err != nil {
		return nil, err
	}
	raw = raw[:n]
	return raw[:], nil
}
