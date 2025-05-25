import hashlib
import json
import time
from datetime import datetime
import os

class Block:
    def __init__(self, index, data, timestamp, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.chain_file = "blockchain_data.json"
        self.load_chain()
        
        if not self.chain:
            self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, {
            "filename": "Genesis Block",
            "result": "Initial Block",
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "file_type": "System",
            "is_malicious": False
        }, time.time(), "0")
        self.chain.append(genesis_block)
        self.save_chain()

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        previous_block = self.get_latest_block()
        new_block = Block(
            previous_block.index + 1,
            data,
            time.time(),
            previous_block.hash
        )
        self.chain.append(new_block)
        self.save_chain()
        return new_block

    def clear_chain(self):
        """Clear the blockchain and reset to genesis block"""
        self.chain = []
        self.create_genesis_block()
        return True

    def save_chain(self):
        chain_data = []
        for block in self.chain:
            chain_data.append({
                "index": block.index,
                "timestamp": block.timestamp,
                "data": block.data,
                "previous_hash": block.previous_hash,
                "hash": block.hash
            })
        
        try:
            with open(self.chain_file, 'w') as f:
                json.dump(chain_data, f, indent=4)
        except Exception as e:
            print(f"Error saving blockchain: {e}")

    def load_chain(self):
        if os.path.exists(self.chain_file):
            try:
                with open(self.chain_file, 'r') as f:
                    chain_data = json.load(f)
                
                for block_data in chain_data:
                    block = Block(
                        block_data["index"],
                        block_data["data"],
                        block_data["timestamp"],
                        block_data["previous_hash"]
                    )
                    block.hash = block_data["hash"]
                    self.chain.append(block)
            except Exception as e:
                print(f"Error loading blockchain: {e}")
                self.chain = []

    def get_chain_data(self):
        return [{
            "index": block.index,
            "timestamp": datetime.fromtimestamp(block.timestamp).strftime('%Y-%m-%d %H:%M:%S'),
            "data": block.data,
            "hash": block.hash
        } for block in self.chain[1:]]  # Skip genesis block 