package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/Consensys/gnark-crypto/accumulator/merkletree"
	"github.com/Consensys/gnark/backend/groth16"
	"github.com/Consensys/gnark/frontend"
	"github.com/Consensys/gnark/std/hash/sha3"
)

// Transaction represents an Ethereum transaction in the block.
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

// Block represents an Ethereum block.
type Block struct {
	Hash         string        `json:"hash"`
	Transactions []Transaction `json:"transactions"`
}

// MerkleCircuit defines the structure of the gnark circuit.
type MerkleCircuit struct {
	// Public Input: Merkle Root of the transaction tree.
	MerkleRoot [32]frontend.Variable `gnark:"merkle_root"`

	// Private Inputs:
	// Transaction Hash to verify.
	Transaction [32]frontend.Variable `gnark:"transaction"`

	// Merkle Proof Path (array of sibling hashes).
	Proof      [][32]frontend.Variable `gnark:"proof"`
	ProofIndex frontend.Variable       `gnark:"proof_index"`
}

// Define specifies the constraints of the circuit.
func (circuitDef *MerkleCircuit) Define(api frontend.API) error {
	// Initialize the current hash as the transaction hash.
	currentHash := circuitDef.Transaction

	// Initialize the Keccak256 hasher from gnark.
	hasher, err := sha3.NewLegacyKeccak256(api)
	if err != nil {
		return err
	}

	// Iterate through each element in the Merkle proof.
	for _, siblingHash := range circuitDef.Proof {
		// Concatenate currentHash and siblingHash.
		// The order of concatenation depends on whether the current node is a left or right child.
		// For simplicity, we'll assume that the sibling is always on the right.
		// In a complete implementation, you should include direction bits to handle both cases.

		// Absorb currentHash.
		for i := 0; i < 32; i++ {
			hasher.Write(currentHash[i])
		}

		// Absorb siblingHash.
		for i := 0; i < 32; i++ {
			hasher.Write(siblingHash[i])
		}

		// Compute the new hash.
		computedHash, err := hasher.Sum()
		if err != nil {
			return err
		}

		// Update currentHash with the newly computed hash.
		currentHash = computedHash
	}

	// Assert that the computed Merkle root matches the public input.
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(currentHash[i], circuitDef.MerkleRoot[i])
	}

	return nil
}

func main() {
	// Step 1: Connect to the Ethereum RPC client via Infura.
	infuraURL := "https://sepolia.infura.io/v3/be0fc392100d41df98bedd9842227a3f"

	// Define the block hash you want to fetch.
	blockHash := "0xYOUR_BLOCK_HASH_HERE" // Replace with an actual block hash.

	// Step 2: Fetch the block by its hash.
	block, err := getBlockByHash(infuraURL, blockHash)
	if err != nil {
		log.Fatalf("Failed to fetch block: %v", err)
	}

	// Step 3: Extract transaction hashes from the block.
	var txHashes [][]byte
	for _, tx := range block.Transactions {
		hashBytes, err := hex.DecodeString(tx.Hash[2:]) // Remove "0x" prefix.
		if err != nil {
			log.Fatalf("Failed to decode transaction hash: %v", err)
		}
		txHashes = append(txHashes, hashBytes)
	}

	// Step 4: Rebuild the Merkle tree from the transaction hashes.
	hashFunc := sha3.NewLegacyKeccak256(nil) // No API needed outside the circuit.
	merkleTree, err := merkletree.NewTree(txHashes, hashFunc)
	if err != nil {
		log.Fatalf("Failed to create Merkle tree: %v", err)
	}

	// Retrieve the Merkle root.
	merkleRoot := merkleTree.Root()
	fmt.Printf("Computed Merkle Root: 0x%x\n", merkleRoot)

	// Step 5: Select a transaction and generate its Merkle proof.
	selectedTxIndex := 0 // For example, the first transaction.
	if selectedTxIndex >= len(txHashes) {
		log.Fatalf("Selected transaction index %d out of bounds", selectedTxIndex)
	}

	selectedTxHash := txHashes[selectedTxIndex]

	// Generate the Merkle proof for the selected transaction.
	proof, err := merkleTree.Proof(selectedTxIndex)
	if err != nil {
		log.Fatalf("Failed to generate Merkle proof: %v", err)
	}

	// Get the index of the selected transaction.
	proofIndex := selectedTxIndex

	// Step 6: Prepare the circuit inputs.
	var circuitDef MerkleCircuit

	// Assign the Merkle root as a public input.
	for i := 0; i < 32; i++ {
		circuitDef.MerkleRoot[i] = frontend.Variable(merkleRoot[i])
	}

	// Assign the transaction hash as a private input.
	for i := 0; i < 32; i++ {
		circuitDef.Transaction[i] = frontend.Variable(selectedTxHash[i])
	}

	// Assign the Merkle proof path as private inputs.
	for _, p := range proof.Path {
		var proofElement [32]frontend.Variable
		for i := 0; i < 32; i++ {
			proofElement[i] = frontend.Variable(p[i])
		}
		circuitDef.Proof = append(circuitDef.Proof, proofElement)
	}

	// Assign the proof index as a private input.
	circuitDef.ProofIndex = frontend.Variable(proofIndex)

	// Step 7: Compile the circuit.
	ccs, err := frontend.Compile(frontend.BN254, &circuitDef)
	if err != nil {
		log.Fatalf("Failed to compile circuit: %v", err)
	}

	// Step 8: Create a witness.
	witness, err := frontend.NewWitness(&circuitDef, frontend.BN254)
	if err != nil {
		log.Fatalf("Failed to create witness: %v", err)
	}

	// Step 9: Setup the Groth16 proving and verification keys.
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("Failed to setup Groth16: %v", err)
	}

	// Step 10: Generate the proof.
	proofGenerated, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatalf("Failed to generate proof: %v", err)
	}

	// Step 11: Verify the proof.
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
