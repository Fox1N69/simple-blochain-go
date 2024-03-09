package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

type Block struct {
	Pos       int
	Data      CertyfCheckout
	Timestamp string
	Hash      string
	PrevHash  string
}

type CertyfCheckout struct {
	CertyfID     string `json:"Certyf_id"`
	User         string `json:"user"`
	CheckoutDate string `json:"checkout_date"`
	IsGenesis    bool   `json:"is_genesis"`
}

type Certyf struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Author      string `json:"author"`
	PublishDate string `json:"publish_date"`
	Code        string `json:"code:`
}

func (b *Block) generateHash() {
	bytes, _ := json.Marshal(b.Data)
	data := string(b.Pos) + b.Timestamp + string(bytes) + b.PrevHash
	hash := sha256.New()
	hash.Write([]byte(data))
	b.Hash = hex.EncodeToString(hash.Sum(nil))
}

func CreateBlock(prevBlock *Block, checkoutItem CertyfCheckout) *Block {
	block := &Block{}
	block.Pos = prevBlock.Pos + 1
	block.Timestamp = time.Now().String()
	block.Data = checkoutItem
	block.PrevHash = prevBlock.Hash
	block.generateHash()

	return block
}

type Blockchain struct {
	blocks []*Block
}

var BlockChain *Blockchain

func (bc *Blockchain) AddBlock(data CertyfCheckout) {

	prevBlock := bc.blocks[len(bc.blocks)-1]

	block := CreateBlock(prevBlock, data)

	if validBlock(block, prevBlock) {
		bc.blocks = append(bc.blocks, block)
	}
}

func GenesisBlock() *Block {
	return CreateBlock(&Block{}, CertyfCheckout{IsGenesis: true})
}

func NewBlockchain() *Blockchain {
	return &Blockchain{[]*Block{GenesisBlock()}}
}

func validBlock(block, prevBlock *Block) bool {

	if prevBlock.Hash != block.PrevHash {
		return false
	}

	if !block.validateHash(block.Hash) {
		return false
	}

	if prevBlock.Pos+1 != block.Pos {
		return false
	}
	return true
}

func (b *Block) validateHash(hash string) bool {
	b.generateHash()
	if b.Hash != hash {
		return false
	}
	return true
}

func getBlockchain(w http.ResponseWriter, r *http.Request) {
	jbytes, err := json.MarshalIndent(BlockChain.blocks, "", " ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(err)
		return
	}

	io.WriteString(w, string(jbytes))
}

func writeBlock(w http.ResponseWriter, r *http.Request) {
	var checkoutItem CertyfCheckout
	if err := json.NewDecoder(r.Body).Decode(&checkoutItem); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("could not write Block: %v", err)
		w.Write([]byte("could not write block"))
		return
	}

	BlockChain.AddBlock(checkoutItem)
	resp, err := json.MarshalIndent(checkoutItem, "", " ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("could not marshal payload: %v", err)
		w.Write([]byte("could not write block"))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func newCertyf(w http.ResponseWriter, r *http.Request) {
	var Certyf Certyf
	if err := json.NewDecoder(r.Body).Decode(&Certyf); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("could not create: %v", err)
		w.Write([]byte("could not create new Certyf"))
		return
	}

	h := md5.New()
	io.WriteString(h, Certyf.Code+Certyf.PublishDate)
	Certyf.ID = fmt.Sprintf("%x", h.Sum(nil))

	resp, err := json.MarshalIndent(Certyf, "", " ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("could not marshal payload: %v", err)
		w.Write([]byte("could not save Certyf data"))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func main() {

	BlockChain = NewBlockchain()

	r := mux.NewRouter()
	r.HandleFunc("/", getBlockchain).Methods("GET")
	r.HandleFunc("/", writeBlock).Methods("POST")
	r.HandleFunc("/new", newCertyf).Methods("POST")

	go func() {

		for _, block := range BlockChain.blocks {
			fmt.Printf("Prev. hash: %x\n", block.PrevHash)
			bytes, _ := json.MarshalIndent(block.Data, "", " ")
			fmt.Printf("Data: %v\n", string(bytes))
			fmt.Printf("Hash: %x\n", block.Hash)
			fmt.Println()
		}

	}()
	log.Println("Listening on port 3000")

	log.Fatal(http.ListenAndServe(":3000", r))
}
