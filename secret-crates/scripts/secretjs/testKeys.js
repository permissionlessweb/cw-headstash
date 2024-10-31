import { ethers } from 'ethers';
import Web3 from 'web3';

function generateEthKeyAndSignMessage(message) {
    // Generate a new Ethereum wallet
    const wallet = ethers.Wallet.createRandom();

    // Get the private key and address of the wallet
    const privateKey = wallet.privateKey;
    const address = wallet.address;

    // Sign the message with the private key
    const signature = wallet.signMessage(message);

    // Return the key pair and signature
    console.log(
        "key:", privateKey, "addr:", address, "sig:", signature)

}


import { Keypair, Transaction, SystemProgram, PublicKey } from '@solana/web3.js';
import { toBase64 } from 'secretjs';
import nacl from 'tweetnacl';


function generateSolanaKeyAndSignMessage(message) {
    // Generate a new Solana wallet
    const keypair = Keypair.generate();

    // Get the private key and public key of the wallet
    const privateKey = keypair.secretKey;
    const publicKey = keypair.publicKey.toBytes();

    // Sign the message with the private key
    const signature = nacl.sign.detached(Buffer.from(message), privateKey);
    

    // Return the key pair and signature
    console.log(
        "key:", privateKey, "pubkey:", toBase64(publicKey), "sig:", toBase64(signature))
}


export { generateSolanaKeyAndSignMessage, generateEthKeyAndSignMessage };