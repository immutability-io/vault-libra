# A Vault plugin for Libra

Documentation to come...

```sh
vault secrets disable libra
vault delete sys/plugins/catalog/libra
cd ..
go build
mv vault-libra $HOME/etc/vault.d/vault_plugins/libra
export SHA256=$(shasum -a 256 "$HOME/etc/vault.d/vault_plugins/libra" | cut -d' ' -f1)
vault write sys/plugins/catalog/libra \
      sha_256="${SHA256}" \
      command="libra --ca-cert=$HOME/etc/vault.d/root.crt --client-cert=$HOME/etc/vault.d/vault.crt --client-key=$HOME/etc/vault.d/vault.key"
vault secrets enable -path=libra -plugin-name=libra plugin
```
