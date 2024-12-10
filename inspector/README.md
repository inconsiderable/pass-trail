# inspector

The inspector is a simple tool for examining the offline pass trail data

## To install

1. Make sure you have the new Go modules support enabled: `export GO111MODULE=on`
2. `go install github.com/inconsiderable/pass-trail/inspector`

The `inspector` application is now in `$HOME/go/bin/inspector`.

## Basic command line arguments

`inspector -datadir <pass trail data directory> -command <command> [other flags required per command]`

## Commands

* **height** - Display the current pass trail height.
* **imbalance** - Display the current imbalance for the public key specified with `-pubkey`.
* **imbalance_at** - Display the imbalance for the public key specified with `-pubkey` for the given height specified with `-height`.
* **pass** - Display the pass specified with `-pass_id`.
* **pass_at** - Display the pass at the pass trail height specified with `-height`.
* **tx** - Display the consideration specified with `-tx_id`.
* **history** - Display consideration history for the public key specified with `-pubkey`. Other options for this command include `-start_height`, `-end_height`, `-start_index`, and `-limit`.
* **verify** - Verify the sum of all public key imbalances matches what's expected dictated by the pass point schedule. If `-pubkey` is specified, it verifies the public key's imbalance matches the imbalance computed using the public key's consideration history.
