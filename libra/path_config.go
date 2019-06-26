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

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// LibraTestnet is the default for EthereumMainnet
	LibraTestnet string = "ac.testnet.libra.org:8000"
	// Local is the default for localhost
	Local string = "localhost:8000"
)

// Config contains the configuration for each mount
type Config struct {
	BoundCIDRList []string `json:"bound_cidr_list_list" structs:"bound_cidr_list" mapstructure:"bound_cidr_list"`
	RPC           string   `json:"rpc_url"`
}

func configPaths(b *BackendLibra) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "config",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathWriteConfig,
				logical.UpdateOperation: b.pathWriteConfig,
				logical.ReadOperation:   b.pathReadConfig,
			},
			HelpSynopsis: "Configure the Vault Libra plugin.",
			HelpDescription: `
			Configure the Vault Libra plugin.
			`,
			Fields: map[string]*framework.FieldSchema{
				"rpc_url": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: `The RPC address of the Libra network.`,
				},
				"bound_cidr_list": &framework.FieldSchema{
					Type: framework.TypeCommaStringSlice,
					Description: `Comma separated string or list of CIDR blocks. If set, specifies the blocks of
IP addresses which can perform the login operation.`,
				},
			},
		},
	}
}

func (config *Config) getRPCURL() string {
	return config.RPC
}

func getDefaultNetwork() string {
	return LibraTestnet
}

func (b *BackendLibra) pathWriteConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rpcURL := data.Get("rpc_url").(string)
	if rpcURL == "" {
		rpcURL = getDefaultNetwork()
	}
	var boundCIDRList []string
	if boundCIDRListRaw, ok := data.GetOk("bound_cidr_list"); ok {
		boundCIDRList = boundCIDRListRaw.([]string)
	}
	configBundle := Config{
		BoundCIDRList: boundCIDRList,
		RPC:           rpcURL,
	}
	entry, err := logical.StorageEntryJSON("config", configBundle)

	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"bound_cidr_list": configBundle.BoundCIDRList,
			"rpc_url":         configBundle.RPC,
		},
	}, nil
}

func (b *BackendLibra) pathReadConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	configBundle, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if configBundle == nil {
		return nil, nil
	}

	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"bound_cidr_list": configBundle.BoundCIDRList,
			"rpc_url":         configBundle.RPC,
		},
	}, nil
}

// Config returns the configuration for this BackendLibra.
func (b *BackendLibra) readConfig(ctx context.Context, s logical.Storage) (*Config, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, fmt.Errorf("the Libra backend is not configured properly")
	}

	var result Config
	if entry != nil {
		if err := entry.DecodeJSON(&result); err != nil {
			return nil, fmt.Errorf("error reading configuration: %s", err)
		}
	}

	return &result, nil
}

func (b *BackendLibra) configured(ctx context.Context, req *logical.Request) (*Config, error) {
	config, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if validConnection, err := b.validIPConstraints(config, req); !validConnection {
		return nil, err
	}

	return config, nil
}

func (b *BackendLibra) validIPConstraints(config *Config, req *logical.Request) (bool, error) {
	if len(config.BoundCIDRList) != 0 {
		if req.Connection == nil || req.Connection.RemoteAddr == "" {
			return false, fmt.Errorf("failed to get connection information")
		}

		belongs, err := cidrutil.IPBelongsToCIDRBlocksSlice(req.Connection.RemoteAddr, config.BoundCIDRList)
		if err != nil {
			return false, errwrap.Wrapf("failed to verify the CIDR restrictions set on the role: {{err}}", err)
		}
		if !belongs {
			return false, fmt.Errorf("source address %q unauthorized through CIDR restrictions on the role", req.Connection.RemoteAddr)
		}
	}
	return true, nil
}
