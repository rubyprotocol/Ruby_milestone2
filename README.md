# Ruby Protocol

There are two modules in this repo:

* `ruby-api` - The Ruby API Server;
* `ruby-ui` - The Ruby Frontend;

## Build and Run Instruction
### Environment setup
```sh
# Install Rust
curl --tlsv1.2 https://sh.rustup.rs -sSf | sh

# Build the project
cargo build
```


### Ruby API Server

Open three terminals to run the following commands respectively and keep them open until the end. 

* Build Ruby API Service

```bash
cd ruby-api
cargo build --release
```

* Run Authority API Service

```bash
./target/release/authority-api
```

Authority API Service is running at http://localhost:3030

* Run Data Owner API Service

```bash
./target/release/owner-api
```

Data Owner API Service is running at http://localhost:3035

* Run Data Purchaser API Service

```bash
./target/release/purchaser-api
```

Data Purchaser API Service is running at http://localhost:3031    

### zero-pool-node

Ruby invokes zeropool to perform zero-knowledge proof verification. You need to run a local node before moving to the next step.    
The instruction on how to run a zeropool node can be found in [here](https://github.com/lornacrevelingwgo23/zeropool_substrate_fork/blob/main/README.md)

### Ruby Frontend

* Environment setup

1. [Install Node.js](https://nodejs.dev/): 

* Build and Run

To build and connect to the running dev node, execute:

```bash
cd ruby-ui
npm i
npm run start
```

Access the Ruby Frontend via http://localhost:3000

Finally, you can refer to the [OPERATIONS](./OPERATIONS.md) document to practice and verify the function of Ruby Protocol.


