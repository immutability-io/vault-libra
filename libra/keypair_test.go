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
	"testing"
)

const (
	KnownSeed      string = "acetone sprint brewery busload affluent pauper cupid chant repossess tiring skier unlivable thaw blurred impose cofounder"
	KnownAddress   string = "06e71fb78a39e1a2591cedfa6fdb976299550bde3c21570d38fc5c0b40191fc9"
	KnownPublicKey string = "4dadadae5524c274b6389c1bf25c966feb6b9fd3c24909bfa466637925d5902a"
)

func TestCreatePair(t *testing.T) {
	kp, err := CreatePair()
	if err != nil {
		t.Errorf("ERROR: %s\n", err)
	}
	if kp == nil {
		t.Error("ERROR: KeyPair is nil")
	}
	rawSeed, err := kp.Seed()
	if err != nil {
		t.Errorf("ERROR: %s\n", err)
	}
	decoded, err := Decode(rawSeed)
	if err != nil {
		t.Errorf("ERROR: %s\n", err)
	}
	t.Logf("SEED: %s\n", decoded)
}
func TestCreatePairFromSeed(t *testing.T) {
	kp, err := CreatePairFromSeed(KnownSeed)
	if err != nil {
		t.Errorf("ERROR: %s\n", err)
	}
	if kp == nil {
		t.Error("ERROR: KeyPair is nil")
	}
}

func TestPrivateKey(t *testing.T) {
	kp, err := CreatePairFromSeed(KnownSeed)
	if err != nil {
		t.Errorf("ERROR: %s\n", err)
	}
	if kp == nil {
		t.Error("ERROR: KeyPair is nil")
	}
	privKey, err := kp.PrivateKey()
	if err != nil {
		t.Errorf("ERROR: %s\n", err)
	}
	if privKey == nil {
		t.Error("ERROR: PrivateKey is nil")
	}
	encoded, err := Encode(privKey)
	if err != nil {
		t.Errorf("ERROR: %s\n", err)
	}
	t.Logf("PRIVATE KEY: %s\n", encoded)
}

func TestKnownPublicKey(t *testing.T) {
	kp, err := CreatePairFromSeed(KnownSeed)
	if err != nil {
		t.Errorf("ERROR: %s\n", err)
	}
	if kp == nil {
		t.Error("ERROR: KeyPair is nil")
	}
	pubKey, err := kp.PublicKey()
	if err != nil {
		t.Errorf("ERROR: %s\n", err)
	}
	t.Logf("PUBLIC KEY: %s\n", pubKey)
	if pubKey != KnownPublicKey {
		t.Errorf("ERROR: %s != %s\n", pubKey, KnownPublicKey)
	}
}

func TestKnownAddress(t *testing.T) {
	kp, err := CreatePairFromSeed(KnownSeed)
	if err != nil {
		t.Errorf("ERROR: %s\n", err)
	}
	if kp == nil {
		t.Error("ERROR: KeyPair is nil")
	}
	address, err := kp.Address()
	if err != nil {
		t.Errorf("ERROR: %s\n", err)
	}
	t.Logf("ADDRESS: %s\n", address)
	if address != KnownAddress {
		t.Errorf("ERROR: %s != %s\n", address, KnownAddress)
	}
}

func TestSignAndVerify(t *testing.T) {
	kp, err := CreatePairFromSeed(KnownSeed)
	if err != nil {
		t.Errorf("ERROR: %s\n", err)
	}
	if kp == nil {
		t.Error("ERROR: KeyPair is nil")
	}
	signature, err := kp.Sign([]byte(KnownAddress))
	if err != nil {
		t.Errorf("ERROR: %s\n", err)
	}
	err = kp.Verify([]byte(KnownAddress), signature)
	if err != nil {
		t.Errorf("ERROR: %s\n", err)
	}
}
