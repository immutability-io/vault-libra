// Copyright © 2018 Immutability, LLC
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

// Factory returns the backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(conf)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// FactoryType returns the factory
func FactoryType(backendType logical.BackendType) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b, err := Backend(conf)
		if err != nil {
			return nil, err
		}
		b.BackendType = backendType
		if err = b.Setup(ctx, conf); err != nil {
			return nil, err
		}
		return b, nil
	}
}

// Backend returns the backend
func Backend(conf *logical.BackendConfig) (*BackendLibra, error) {
	var b BackendLibra
	b.Backend = &framework.Backend{
		Help: "",
		Paths: framework.PathAppend(
			configPaths(&b),
			addressesPaths(&b),
			namesPaths(&b),
			accountsPaths(&b),
		),
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"addresses/*",
				"names/*",
			},
			SealWrapStorage: []string{
				"accounts/",
			},
		},
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
	}
	return &b, nil
}

// BackendLibra implements the Backend for this plugin
type BackendLibra struct {
	*framework.Backend
}

func (b *BackendLibra) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %v", err)
	}

	return out != nil, nil
}
