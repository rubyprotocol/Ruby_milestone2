# Ruby Protocol

There are three modules under the repo:

* `zeropool-substrate-devnet` - A Substrate Node from the [zeropool-substrate](https://github.com/zeropoolnetwork/zeropool-substrate) project, **it only be used to verify zkSNARKs**;
* `ruby-api` - The Ruby API Server;
* `ruby-ui` - The Ruby Frontend;

## Install Substrate/Zeropool Node

### Requirements

1. [Install Rust](https://www.rust-lang.org/tools/install)

   `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
   
2. Install `make`

   * Ubuntu: `sudo apt-get install build-essential`
   * Mac OS: `xcode-select --install`

### Build and Run

To build and run the dev node, execute:

```bash
cd zeropool-substrate-devnet
make init
make run
```

## Ruby API Server

Open three terminals to run the following commands respectively and keep them open until the end. 

### Build Ruby API Service

```bash
cd ruby-api
cargo build --release
```

### Run Authority API Service

```bash
./target/release/authority-api
```

Authority API Service is running at http://localhost:3030

### Run Data Owner API Service

```bash
./target/release/owner-api
```

Data Owner API Service is running at http://localhost:3035

### Run Data Purchaser API Service

```bash
./target/release/purchaser-api
```

Data Purchaser API Service is running at http://localhost:3031

## Ruby Frontend

### Requirements

1. [Install Node.js](https://nodejs.dev/): 

### Build and Run

To build and connect to the running dev node, execute:

```bash
cd ruby-ui
npm i
npm run start
```

Access the Ruby Frontend via http://localhost:3000

Finally, you can refer to the [OPERATIONS](./OPERATIONS.md) document to practice and verify the function of Ruby Protocol.


