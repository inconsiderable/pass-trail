# Quickstart

## Overview

Using pass-trail requires two components: a client and a heart.

### Heart

The heart component is the user facing component for account management. It's responsible for private key management and user-driven network considerations (such as viewing imbalance or sending/receiving considerations).

### Client

The client is the component responsible for maintaining a peering connection to the network (i.e. running a node) and tracking. The client uses a peer discovery protocol to bootstrap itself onto the network and then cooperates with other nodes to manage the distributed ledger.

Trackers running in the client are responsible for tracking new passes in coordination with the network. When a tracker running on your local node tracks a new pass it will automatically create a consideration on the network sending the pass point to one of your heart-managed public keys. 
## Pre-requisites

To build and install, you'll need the [Go language](https://golang.org/doc/install) runtime and compilation tools. You can get that by installing [Go](https://golang.org/doc/install#install) using the latest installation guide:

- https://golang.org/doc/install#install

Or using the [Linux Quickstart](https://gist.github.com/setanimals/f562ed7dd1c69af3fbe960c7b9502615).

## Installation

To get started, let's build and install both the `client` and `heart` components:

```
$ export GO111MODULE=on
$ go get -v github.com/inconsiderable/pass-trail/client github.com/inconsiderable/pass-trail/heart
$ go install -v github.com/inconsiderable/pass-trail/client github.com/inconsiderable/pass-trail/heart
```

The bins should now be available in your Go-managed `$GOPATH/bin` (which is hopefully also on your `$PATH`). You can test this by running e.g. `client -h` or `$GOPATH/bin/client -h` to print the CLI help screen.

## Heart Setup

First, we'll need to initialize the heart database and setup a heart passphrase that will be used to encrypt the private keys. The heart will need a secure dir that should be backed up (after generating any new keys) to avoid loss of private keys. Be sure to quit the heart session before conducting any backups. Start up the heart like so:

```
$ heart -heartdb pass-heart
Starting up...
Genesis pass ID: 00000000e29a7850088d660489b7b9ae2da763bc3bd83324ecc54eee04840adb

Enter passphrase: <enter new passphrase here>
Confirm passphrase: <enter new passphrase here>

Please select a command.
To connect to your heart peer you need to issue a command requiring it, e.g. imbalance
>
```

!> Note: Once set, the passphrase will now be required to decrypt the heartdb in future runs - so make sure to remember it.

### Key Pair Generation

Generate one or more key pairs using the `genkeys` command:

```
Please select a command.
To connect to your heart peer you need to issue a command requiring it, e.g. imbalance
> genkeys
Count: 2
Generated 2 new keys
```

These keys will later be used to send and receive considerations on the network from tracker instances or other hearts.

### Create a Key File

Create a plaintext list of the newly generated public keys (in a `keys.txt` file) by using the `dumpkeys` command:

```
> dumpkeys
2 public keys saved to 'keys.txt'
```

## Running the Client

Given the newly created keyfile, we're ready to connect to run the client and begin tracking:

```
$ client -datadir pass-node -keyfile keys.txt -numtrackers 4 -upnp
```

!> Note: To enable constant tracking, make sure the `client` process stays running in either `screen` or another durable session.

## Check Your Imbalance

Once the client has spun up, you should now be able to issue the `imbalance` command in your heart to check your current imbalance:

```
> imbalance
   1: GVoqW1OmLD5QpnthuU5w4ZPNd6Me8NFTQLxfBsFNJVo=        0.00000000
   2: Y1ob+lgssGw7hDjhUvkM1XwAUr00EYQrAN2W3Z13T/g=       50.00000000
Total: 50.00000000
```

The heart will also watch for and notify you about new consideration confirmations to any of your configured public key addresses.

See the [Heart](heart.md) and [Client](client.md) help pages for more information on the CLI options.