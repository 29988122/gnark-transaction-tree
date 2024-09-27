package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"

	regularSha3 "golang.org/x/crypto/sha3"
)

// Transaction struct received from the Ethereum RPC client.
type Transaction struct {
	Hash             string `json:"hash"`
	BlockHash        string `json:"blockHash"`
	From             string `json:"from"`
	To               string `json:"to"`
	Nonce            string `json:"nonce"`
	Value            string `json:"value"`
	Gas              string `json:"gas"`
	GasPrice         string `json:"gasPrice"`
	Input            string `json:"input"`
	TransactionIndex string `json:"transactionIndex"`
}

// Block struct received from the Ethereum RPC client.
type Block struct {
	Hash         string        `json:"hash"`
	Transactions []Transaction `json:"transactions"`
}

// MerkleCircuit defines the structure of the gnark circuit.
// It reconstructs the Merkle Tree from the transaction hashes and verifies against the given Merkle Root.
// Todos: Use native operations in the future, instead of gnark gadgets.
// Such as the ones in ecgo package. PolyhedraZK/ExpanderCompilerCollection/ecgo/examples/keccak
type MerkleCircuit struct {
	MerkleRoot  [32]uints.U8        `gnark:"merkle_root"`
	Transaction [32]uints.U8        `gnark:"transaction"`
	Proof       [][32]uints.U8      `gnark:"proof"`
	Directions  []frontend.Variable `gnark:"directions"`
}

func (circuitDef *MerkleCircuit) Define(api frontend.API) error {
	// Initialize the Keccak256 hasher from gnark. Used for computing the Transaction Merkle Tree in Ethereum.
	hasher, err := sha3.NewLegacyKeccak256(api)
	if err != nil {
		return err
	}

	// Initialize currentHash with the transaction hash circuit input.
	currentHash := make([]uints.U8, 32)
	for i := 0; i < 32; i++ {
		currentHash[i].Val = circuitDef.Transaction[i].Val
	}

	// Iterate through each element in the Merkle proof.
	for idx, siblingHash := range circuitDef.Proof {
		// Get the direction bit for this proof element.
		if idx >= len(circuitDef.Directions) {
			return fmt.Errorf("insufficient direction bits for proof at index %d", idx)
		}
		direction := circuitDef.Directions[idx]

		// Depending on the direction, concatenate currentHash and siblingHash accordingly.
		// If direction == 0, sibling is on the left. Else, sibling is on the right.
		if direction == 0 {
			// Sibling is on the left.
			hasher.Write(siblingHash[:])
			hasher.Write(currentHash)
		} else {
			// Sibling is on the right.
			hasher.Write(currentHash)
			hasher.Write(siblingHash[:])
		}

		// Compute the new hash (parent node).
		computedHash := hasher.Sum()

		// Ensure the computed hash has exactly 32 bytes.
		if len(computedHash) != 32 {
			return fmt.Errorf("invalid hash length: expected 32, got %d", len(computedHash))
		}

		// Update currentHash with the newly computed parent hash.
		currentHash = computedHash
	}

	// At the end, currentHash should be equal to the MerkleRoot public input we retreived on chain.
	// Todos: ITS FALSE ATM. Check the bugs in current implementation.
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(currentHash[i].Val, circuitDef.MerkleRoot[i].Val)
	}

	return nil
}

func main() {
	// Step 1: Connect to the Ethereum RPC client via Infura.
	// Todos: Use env var, do not expose the infura api key.
	infuraURL := "https://sepolia.infura.io/v3/be0fc392100d41df98bedd9842227a3f"

	// Step 2: Use the specified block hash.
	blockHash := "0x8c635c3c1e9e5725438b155d1c1a2394997e07656545cf048a78817415b1c708"

	// Step 3: Fetch the block by its hash.
	block, err := getBlockByHash(infuraURL, blockHash)
	if err != nil {
		log.Fatalf("Failed to fetch block: %v", err)
	}

	// Step 4: Extract transaction hashes from the block.
	var txHashes [][]byte
	for _, tx := range block.Transactions {
		hashBytes, err := hex.DecodeString(tx.Hash[2:]) // Remove "0x" prefix.
		if err != nil {
			log.Fatalf("Failed to decode transaction hash: %v", err)
		}
		txHashes = append(txHashes, hashBytes)
	}

	// Step 5: Select a specific transaction leaf by hash.
	targetTxHash := "0x7588d9fe3602ac36ef10b72b9e8f6a56ca45d4ce9b95a15bd371b7072b683a76"
	targetHashBytes, err := hex.DecodeString(targetTxHash[2:]) // Remove "0x" prefix
	if err != nil {
		log.Fatalf("Failed to decode target transaction hash: %v", err)
	}

	selectedTxIndex := -1
	for i, txHash := range txHashes {
		if bytes.Equal(txHash, targetHashBytes) {
			selectedTxIndex = i
			break
		}
	}
	if selectedTxIndex == -1 {
		log.Fatalf("Target transaction hash not found in the block")
	}

	// Step 6: Initialize the Merkle tree with the appropriate hash function.
	// todos: understand gnark-crypto's merkle tree implementation more. Maybe I'm using it incorrectly.
	hashFunc := regularSha3.NewLegacyKeccak256() // Use standard sha3 for off-circuit
	merkleTree := merkletree.New(hashFunc)

	// Step 7: Set the index of the transaction to prove BEFORE pushing any data.
	// Todos: Understand why we need to set the index before pushing any data - the tree must be empty.
	// It's hard requirement of gnark-crypto merkle tree module atm.
	err = merkleTree.SetIndex(uint64(selectedTxIndex))
	if err != nil {
		log.Fatalf("Failed to set index: %v", err)
	}

	// Step 8: Push all transaction hashes to the Merkle tree.
	for _, txHash := range txHashes {
		merkleTree.Push(txHash)
	}

	// Step 9: Generate the Merkle path proof for the selected transaction leaf.
	merkleRoot, proofSet, proofIndex, _ := merkleTree.Prove()
	if len(proofSet) == 0 {
		log.Fatalf("No proof generated")
	}

	fmt.Printf("Computed Merkle Root: 0x%x\n", merkleRoot)

	// Step 10: Determine the direction bits for each proof element, prepared for circuit.
	directions, err := getProofDirections(int(proofIndex), len(proofSet))
	if err != nil {
		log.Fatalf("Failed to determine proof directions: %v", err)
	}

	// Step 11: Prepare the circuit inputs.
	var circuitDef MerkleCircuit

	// Assign the Merkle root as a public input.
	for i := 0; i < 32; i++ {
		circuitDef.MerkleRoot[i].Val = frontend.Variable(merkleRoot[i])
	}

	// Assign the transaction hashes as a private input.
	selectedTxHashBytes := txHashes[selectedTxIndex]
	for i := 0; i < 32; i++ {
		circuitDef.Transaction[i].Val = frontend.Variable(selectedTxHashBytes[i])
	}

	// Assign the Merkle proof path as private inputs.
	for _, p := range proofSet {
		var proofElement [32]uints.U8
		for i := 0; i < 32; i++ {
			proofElement[i].Val = frontend.Variable(p[i])
		}
		circuitDef.Proof = append(circuitDef.Proof, proofElement)
	}

	// Assign the direction bits as private inputs.
	circuitDef.Directions = directions

	// Step 12: Compile the circuit using the gnark builtin builder, Groth16.
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuitDef)
	if err != nil {
		log.Fatalf("Failed to compile circuit: %v", err)
	}

	// Step 13: Create a witness.
	witness, err := frontend.NewWitness(&circuitDef, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatalf("Failed to create witness: %v", err)
	}

	// Step 14: Setup the Groth16 proving and verification keys.
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("Failed to setup Groth16: %v", err)
	}

	// Step 15: Generate the proof.
	proofGenerated, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatalf("Failed to generate proof: %v", err)
	}

	// Step 16: Verify the proof.
	err = groth16.Verify(proofGenerated, vk, witness)
	if err != nil {
		log.Fatalf("Proof verification failed: %v", err)
	}

	fmt.Println("Proof successfully verified!")
}

// getBlockByHash fetches an Ethereum block by its hash using the specified RPC endpoint.
func getBlockByHash(rpcURL, blockHash string) (*Block, error) {
	// Define the RPC request structure.
	type RPCRequest struct {
		Jsonrpc string        `json:"jsonrpc"`
		Method  string        `json:"method"`
		Params  []interface{} `json:"params"`
		Id      int           `json:"id"`
	}

	// Define the RPC response structure.
	type RPCResponse struct {
		Jsonrpc string          `json:"jsonrpc"`
		Id      int             `json:"id"`
		Result  json.RawMessage `json:"result"`
	}

	// Prepare the request payload.
	reqBody := RPCRequest{
		Jsonrpc: "2.0",
		Method:  "eth_getBlockByHash",
		Params:  []interface{}{blockHash, true}, // true to include full transaction objects.
		Id:      1,
	}

	// Marshal the request into JSON.
	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RPC request: %v", err)
	}

	// Create the HTTP request.
	req, err := http.NewRequest("POST", rpcURL, bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Perform the HTTP request.
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Decode the response.
	var rpcResp RPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("failed to decode RPC response: %v", err)
	}

	// Check if the result is null.
	if string(rpcResp.Result) == "null" {
		return nil, fmt.Errorf("block not found or RPC error")
	}

	// Unmarshal the result into the Block struct.
	var block Block
	if err := json.Unmarshal(rpcResp.Result, &block); err != nil {
		return nil, fmt.Errorf("failed to unmarshal block data: %v", err)
	}

	return &block, nil
}

// getProofDirections determines the direction bits for each proof element.
// Returns 0 if the current node is a left child, 1 if it's a right child.
func getProofDirections(proofIndex int, numBits int) ([]frontend.Variable, error) {
	var directions []frontend.Variable
	index := proofIndex
	for i := 0; i < numBits; i++ {
		direction := index % 2
		directions = append(directions, frontend.Variable(direction))
		index = index / 2
	}
	return directions, nil
}
