# gnark-transaction-tree
gnark-transaction-tree is a Go project that demonstrates how to use the gnark library and Polyhedra-ECC library to recreate a merkle transaction tree from a given Ethereum block in circuit, and generate a zero-knowledge proof that a given transaction is part of that block.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Architecture](#architecture)
- [Technical Details](#technical-details)
- [TODO](#todo)
- [Contributing](#contributing)
- [License](#license)
## Overview

The `gnark-transaction-tree` project showcases the following capabilities:

1. Fetching Ethereum block data using the Infura API
2. Re-constructing a transaction Merkle tree from transaction hashes
3. Generating a transaction tree Merkle path proof for a specific transaction
4. Creating a zero-knowledge circuit to reconstruct the transaction Merkle tree, verify the result against the public Merkle root hash
5. Generating and verifying a zero-knowledge proof of transaction inclusion

**Note:** This is a simplified demonstration and does not encompass the full complexity of Ethereum's block validation or consensus mechanisms. It primarily focuses on the transaction Merkle Tree verification aspect. Transaction's not actually proved, just reconstructed and checked against fetched root hash.
This project serves as a proof-of-concept for educational purposes. Do not use it in production. 

## Prerequisites
- Go execution environment
- Access to an Ethereum node (via Infura in this example, use your own API key)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/gnark-transaction-tree.git
   ```

2. Change to the project directory:
   ```
   cd gnark-transaction-tree
   ```

3. Install dependencies:
   ```
   go mod tidy
   ```

## Usage

To run the project, try the two variant (gnark/polyhedra_ecc) in the subdirectories to see the differences.

## Architecture

The code can be broken down into the following key components:

1. **Data Fetching:**
   - `getBlockByHash()`: Fetches a block from an Ethereum node (currently using Infura) via JSON-RPC, given the block hash. 
   - Extracts transaction hashes from the fetched block data.

2. **Transaction Merkle Tree Re-construction (Off-Circuit):**
   - Uses `github.com/consensys/gnark-crypto/accumulator/merkletree` to build a Merkle Tree from the transaction hashes.
   - Utilizes the standard Keccak-256 hash function (`golang.org/x/crypto/sha3`) to mimic Ethereum's hashing.
   - Generates a Merkle path proof for a specific transaction.

3. **Circuit Definition:**
   - `MerkleCircuit` struct: Defines the circuit's public and private inputs:
     - `MerkleRoot` (public): The Merkle Root of the block.
     - `Transaction` (private): The hash of the transaction being proven.
     - `Proof` (private): The Merkle proof path.
     - `Directions` (private): Bits indicating the direction (left or right) of each sibling in the proof path.
   - `MerkleCircuit.Define()`: Implements the circuit logic:
     - Initializes a Keccak-256 hasher within the circuit using [NewLegacyKeccack256 by gnark](https://github.com/Consensys/gnark/blob/master/std/hash/sha3/hashes.go). A different hasher implementation [ecgo/keccak](https://github.com/PolyhedraZK/ExpanderCompilerCollection/blob/master/ecgo/examples/keccak/main.go) will be used for Expander-rs, which is native operations to it, thus yields better performance.
     - Iterates through the proof elements, hashing the current hash with the sibling hash based on the direction bit. Essentially reconstructing the transaction merkle tree in-circuit.
     - Finally, asserts that the computed hash equals the `MerkleRoot` public input reteived from RPC endpoint.

4. **Circuit Compilation and Proof Generation:**
   - Compiles the circuit using `frontend.Compile` when using gnark. For ecgo, this [api](https://polyhedrazk.github.io/ExpanderCompilerCollection/docs/go/apis) is used instead.
   - Creates a witness (assignment of values to the circuit's inputs). For ecgo, `inputSolver := ccs.GetInputSolver()`, and `witness, _ := inputSolver.SolveInputAuto(&circuitDef)` are used instead.
   - Generates a Groth16 proof using `groth16.Prove` when using gnark. 

5. **Proof Verification:**
   - Verifies the generated proof using `groth16.Verify`. For ecgo, we use ```test.CheckCircuit(c, witness)``` to check the integrity of the circuit and witness we generated in previous steps. Further proving steps shall be referred to [Expander-rs](https://github.com/PolyhedraZK/Expander).

## Future Improvements

- **Optimization with Polyhedra's ECC:** Integrate Polyhedra's `ExpanderCompilerCollections/ecgo` and its native Keccak implementation for significantly faster performance.
- **Critical Bugs:** Currently the code is not in a working state. There's likely a bug in the merkle tree reconstruction, and field operations<>linear operations incompatible issues when generating witness.
- **Configuration:**  Externalize configuration parameters (e.g., Infura URL, block hash, transaction hash) through environment variables or a configuration file.
- **Testing:** Add comprehensive unit tests to ensure the correctness of the code.
- **Cross-chain capabilities:** Introduce the two parties Alice and Bob, represented as sender and receiver, and separate the prove generation from verification. 
- **Other metadata for proving circuit inputs:** For example, include Alice's signature in circuits, to confirm transaction's sender identity.

## License

This project is licensed under the MIT License.