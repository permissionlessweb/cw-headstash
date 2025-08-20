#!/usr/bin/env node

/**
 * Quick Setup Script for Headstash SecretJS
 * 
 * This script helps developers get started quickly by:
 * 1. Checking if .env file exists
 * 2. Creating one from .env.example if needed
 * 3. Providing guidance on what needs to be configured
 * 4. Running initial validation checks
 */

import * as fs from 'fs';
import * as path from 'path';
import { config } from './config.js';

console.log('🚀 Headstash SecretJS Setup\n');

const envPath = path.resolve(process.cwd(), '..', '.env');
const envExamplePath = path.resolve(process.cwd(), '..', '.env.example');

// Check if .env file exists
if (!fs.existsSync(envPath)) {
  console.log('📋 Creating .env file from .env.example...');
  
  if (fs.existsSync(envExamplePath)) {
    fs.copyFileSync(envExamplePath, envPath);
    console.log('✅ .env file created successfully!\n');
  } else {
    console.log('⚠️  .env.example not found. Creating a basic .env file...\n');
    
    const basicEnvContent = `# Headstash SecretJS Configuration
# Copy values from your deployment or set them as needed

CHAIN_ID=secret-4
WALLET_PRIVATE_KEY=your-mnemonic-here
RPC_URL=https://rest.lavenderfive.com:443/secretnetwork

# Contract addresses (set these after deployment)
HEADSTASH_ADDRESS=
SNIP20_TERP_ADDRESS=
SNIP20_THIOL_ADDRESS=

# Contract code IDs and hashes (update after upload)
HEADSTASH_ID=2057
HEADSTASH_CODE_HASH=41cde6547e3e7cd2ff31f4365b707faa5d3026414c03664b903185d5538d90dc
SNIP20_CODE_ID=2056
SNIP20_CODE_HASH=3884f72403e5308db76748244d606dd8bfa98eb560b1906d5825fc7dd72f867e

# Token configurations
SNIP20_TERP_NATIVE=ibc/AF840D44CC92103AD006850542368B888D29C4D4FFE24086E767F161FBDDCE76
SNIP20_THIOL_NATIVE=ibc/7477828AC3E19352BA2D63352EA6D0680E3F29C126B87ACBDC27858CF7AF3A64
SNIP20_TERP_AMOUNT=7100000
SNIP20_THIOL_AMOUNT=7100000

# IBC Configuration
COUNTERPARTY_CHANNEL_ID=channel-165

# Security
ENTROPY=your-entropy-here
PERMIT_KEY=your-permit-key-here

# File paths (optional - defaults will be used)
# CW_HEADSTASH_WASM=./path/to/your/cw_headstash.wasm
# SNIP120U_WASM=./path/to/your/snip120u.wasm
`;
    
    fs.writeFileSync(envPath, basicEnvContent);
    console.log('✅ Basic .env file created!\n');
  }
}

console.log('🔧 Configuration Check:\n');

// Validate current configuration and provide guidance
const issues = [];
const suggestions = [];

// Check critical configurations
if (config.wallet.mnemonic.includes('amateur pond bubble')) {
  issues.push('Using default test mnemonic');
  suggestions.push('Set your own WALLET_PRIVATE_KEY in .env file');
}

if (!config.contracts.headstash.address) {
  issues.push('Headstash contract address not set');
  suggestions.push('Deploy headstash contract and set HEADSTASH_ADDRESS in .env');
}

if (config.security.entropy === 'eretskeretjableret') {
  issues.push('Using default entropy');
  suggestions.push('Set a secure ENTROPY value in .env file');
}

if (!config.files.cwHeadstashWasm) {
  issues.push('Headstash WASM file not found');
  suggestions.push('Build contracts and ensure WASM files are in the expected location');
}

// Display results
if (issues.length === 0) {
  console.log('✅ Configuration looks good!\n');
} else {
  console.log('⚠️  Configuration Issues Found:');
  issues.forEach(issue => console.log(`   • ${issue}`));
  console.log('\n💡 Suggestions:');
  suggestions.forEach(suggestion => console.log(`   • ${suggestion}`));
  console.log('');
}

// Display next steps
console.log('🎯 Quick Start Guide:\n');
console.log('1. Configure your .env file with proper values');
console.log('2. Build and upload contracts:');
console.log('   node main.js upload-headstash');
console.log('3. Initialize SNIP20 tokens:');
console.log('   node main.js init-snip20-terp');
console.log('   node main.js init-snip20-thiol');
console.log('4. Initialize headstash contract:');
console.log('   node main.js init-headstash');
console.log('5. Set viewing keys:');
console.log('   node main.js set-viewing-key-terp');
console.log('   node main.js set-viewing-key-thiol');
console.log('\nFor full command list: node main.js help\n');

console.log('📋 Current Configuration:');
config.display();