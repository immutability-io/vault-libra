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
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// Empty is the empty string
	Empty string = ""
)

// Account is an Libra account
type Account struct {
	Seed      string   `json:"seed"`
	Salt      string   `json:"salt"`
	Whitelist []string `json:"whitelist"`
	Blacklist []string `json:"blacklist"`
}

func accountsPaths(b *BackendLibra) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "accounts/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathAccountsList,
			},
			HelpSynopsis: "List all the Libra accounts at a path",
			HelpDescription: `
			All the Libra accounts will be listed.
			`,
		},
		&framework.Path{
			Pattern:      "accounts/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Create an Libra account using a generated or provided passphrase",
			HelpDescription: `

Creates (or updates) an Libra account: an account controlled by a private key. Also
The generator produces a high-entropy passphrase with the provided length and requirements.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"whitelist": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: "The list of accounts that this account can send transactions to.",
				},
				"blacklist": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: "The list of accounts that this account can't send transactions to.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathAccountsRead,
				logical.CreateOperation: b.pathAccountsCreate,
				logical.UpdateOperation: b.pathAccountUpdate,
				logical.DeleteOperation: b.pathAccountsDelete,
			},
		},
		&framework.Path{
			Pattern:      "accounts/" + framework.GenericNameRegex("name") + "/sign",
			HelpSynopsis: "Sign a provided transaction. ",
			HelpDescription: `

Sign a raw transaction.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"data": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The data to sign.",
				},
				"encoding": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "utf8",
					Description: "The encoding of the data to sign.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathSign,
				logical.UpdateOperation: b.pathSign,
			},
		},
	}
}

func (b *BackendLibra) pathAccountsList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	vals, err := req.Storage.List(ctx, "accounts/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}

func (b *BackendLibra) readAccount(ctx context.Context, req *logical.Request, name string) (*Account, error) {
	path := fmt.Sprintf("accounts/%s", name)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var account Account
	err = entry.DecodeJSON(&account)

	if entry == nil {
		return nil, fmt.Errorf("failed to deserialize account at %s", path)
	}

	return &account, nil
}

func (b *BackendLibra) pathAccountsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	account, err := b.readAccount(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("Error reading account")
	}
	if account == nil {
		return nil, nil
	}
	kp, err := CreatePairFromSeed(account.Seed)
	if err != nil {
		return nil, err
	}
	address, err := kp.Address()
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address":   "0x" + address,
			"whitelist": account.Whitelist,
			"blacklist": account.Blacklist,
			"balance":   "not implemented yet",
		},
	}, nil
}

func (b *BackendLibra) pathAccountsDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	account, err := b.readAccount(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("Error reading account")
	}
	if account == nil {
		return nil, nil
	}
	kp, err := CreatePairFromSeed(account.Seed)
	if err != nil {
		return nil, err
	}
	address, err := kp.Address()
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Delete(ctx, req.Path); err != nil {
		return nil, err
	}
	b.removeCrossReference(ctx, req, name, address)
	return nil, nil
}

func (b *BackendLibra) pathAccountsCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	var whiteList []string
	if whiteListRaw, ok := data.GetOk("whitelist"); ok {
		whiteList = whiteListRaw.([]string)
	}
	var blackList []string
	if blackListRaw, ok := data.GetOk("blacklist"); ok {
		blackList = blackListRaw.([]string)
	}

	kp, err := CreatePair()
	if err != nil {
		return nil, err
	}
	defer kp.Wipe()
	seed, err := kp.Seed()
	if err != nil {
		return nil, err
	}
	address, err := kp.Address()
	if err != nil {
		return nil, err
	}

	accountJSON := &Account{
		Seed:      string(seed),
		Whitelist: Dedup(whiteList),
		Blacklist: Dedup(blackList),
		Salt:      LibraSalt,
	}
	entry, err := logical.StorageEntryJSON(req.Path, accountJSON)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}
	b.crossReference(ctx, req, name, address)
	return &logical.Response{
		Data: map[string]interface{}{
			"address":   "0x" + address,
			"whitelist": accountJSON.Whitelist,
			"blacklist": accountJSON.Blacklist,
		},
	}, nil
}

func (b *BackendLibra) pathAccountUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}

	name := data.Get("name").(string)
	account, err := b.readAccount(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("Error reading account")
	}
	if account == nil {
		return nil, nil
	}
	kp, err := CreatePairFromSeed(account.Seed)
	if err != nil {
		return nil, err
	}
	address, err := kp.Address()
	if err != nil {
		return nil, err
	}
	var whiteList []string
	if whiteListRaw, ok := data.GetOk("whitelist"); ok {
		whiteList = whiteListRaw.([]string)
	}
	var blackList []string
	if blackListRaw, ok := data.GetOk("blacklist"); ok {
		blackList = blackListRaw.([]string)
	}
	account.Whitelist = whiteList
	account.Blacklist = blackList

	entry, err := logical.StorageEntryJSON(req.Path, account)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"address":   "0x" + address,
			"whitelist": account.Whitelist,
			"blacklist": account.Blacklist,
		},
	}, nil

}

func (b *BackendLibra) verifySignature(ctx context.Context, req *logical.Request, data *framework.FieldData, name string) (*logical.Response, error) {
	account, err := b.readAccount(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("error reading account")
	}
	if account == nil {
		return nil, nil
	}
	kp, err := CreatePairFromSeed(account.Seed)
	if err != nil {
		return nil, err
	}
	defer kp.Wipe()

	signature := data.Get("signature").(string)
	dataToVerify := data.Get("data").(string)
	signatureBytes, err := Decode([]byte(signature))
	if err != nil {
		return nil, err
	}
	err = kp.Verify([]byte(dataToVerify), signatureBytes)
	if err != nil {
		return nil, err
	}
	address, err := kp.Address()
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"verified":  true,
			"signature": signature,
			"address":   "0x" + address,
		},
	}, nil

}

func (b *BackendLibra) pathVerify(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}

	name := data.Get("name").(string)
	return b.verifySignature(ctx, req, data, name)
}

func (b *BackendLibra) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}

	name := data.Get("name").(string)
	account, err := b.readAccount(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("error reading account")
	}
	if account == nil {
		return nil, nil
	}
	kp, err := CreatePairFromSeed(account.Seed)
	if err != nil {
		return nil, err
	}
	defer kp.Wipe()
	var txDataToSign []byte
	payload := data.Get("data").(string)
	encoding := data.Get("encoding").(string)
	if encoding == "hex" {
		txDataToSign, err = Decode([]byte(payload))
		if err != nil {
			return nil, err
		}
	} else if encoding == "utf8" {
		txDataToSign = []byte(payload)
	} else {
		return nil, fmt.Errorf("invalid encoding encountered - %s", encoding)
	}

	signatureBytes, err := kp.Sign(txDataToSign)
	if err != nil {
		return nil, err
	}
	address, err := kp.Address()
	if err != nil {
		return nil, err
	}
	signature, err := Encode(signatureBytes)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"signature": signature,
			"address":   "0x" + address,
		},
	}, nil

}
