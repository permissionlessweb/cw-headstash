import * as fs from "fs";
import { EncryptionUtilsImpl } from "secretjs";
import * as path from "path";

/**
 * Configuration manager for SecretJS scripts
 * Provides a robust way to manage constants with environment variable support,
 * validation, and helpful error messages
 */
class Config {
  constructor() {
    this.loadEnvFile();
    this.initializeDefaults();
    this.validate();
  }

  loadEnvFile() {
    const envPath = path.resolve(process.cwd(), '..', '.env');
    if (fs.existsSync(envPath)) {
      const envContent = fs.readFileSync(envPath, 'utf8');
      envContent.split('\n').forEach(line => {
        const [key, value] = line.split('=');
        if (key && value) {
          process.env[key.trim()] = value.trim();
        }
      });
    }
  }

  initializeDefaults() {
    // Network configuration
    this.network = {
      chainId: this.getEnvOrDefault('CHAIN_ID', 'secret-4'),
      rpcUrl: this.getEnvOrDefault('RPC_URL', 'https://rpc.ankr.com/http/scrt_cosmos'),
    };

    // Wallet configuration
    this.wallet = {
      mnemonic: this.getEnvOrDefault(
        'WALLET_PRIVATE_KEY',
        'amateur pond bubble move field brain base candy kind oxygen glow bread robot domain tongue agree jazz increase bronze staff kangaroo piano uncle power'
      ),
    };

    // Contract configuration
    this.contracts = {
      headstash: {
        codeId: this.getEnvOrDefault('HEADSTASH_ID', 2057),
        codeHash: this.getEnvOrDefault('HEADSTASH_CODE_HASH', '41cde6547e3e7cd2ff31f4365b707faa5d3026414c03664b903185d5538d90dc'),
        address: this.getEnvOrDefault('HEADSTASH_ADDRESS', ''),
      },
      polytone: {
        note: {
          codeId: this.getEnvOrDefault('POLYTONE_NOTE_ID', 2057),
          codeHash: this.getEnvOrDefault('POLYTONE_NOTE_CODE_HASH', '41cde6547e3e7cd2ff31f4365b707faa5d3026414c03664b903185d5538d90dc'),
          address: this.getEnvOrDefault('POLYTONE_NOTE_ADDRESS', ''),
        },
        proxy: {
          codeId: this.getEnvOrDefault('POLYTONE_PROXY_ID', 2057),
          codeHash: this.getEnvOrDefault('POLYTONE_PROXY_CODE_HASH', '41cde6547e3e7cd2ff31f4365b707faa5d3026414c03664b903185d5538d90dc'),
          address: this.getEnvOrDefault('POLYTONE_PROXY_ADDRESS', ''),
        },
        voice: {
          codeId: this.getEnvOrDefault('POLYTONE_VOICE_ID', 2057),
          codeHash: this.getEnvOrDefault('POLYTONE_VOICE_CODE_HASH', '41cde6547e3e7cd2ff31f4365b707faa5d3026414c03664b903185d5538d90dc'),
          address: this.getEnvOrDefault('POLYTONE_VOICE_ADDRESS', ''),
        },
      },
      snip120u: {
        codeId: this.getEnvOrDefault('SNIP20_CODE_ID', 2056),
        codeHash: this.getEnvOrDefault('SNIP20_CODE_HASH', '3884f72403e5308db76748244d606dd8bfa98eb560b1906d5825fc7dd72f867e'),
        instances: [
          {
            name: 'TERP',
            address: this.getEnvOrDefault('SNIP20_TERP_ADDRESS', 'secret1d5d70hangvetxjtqdd5wrletwjr2s0864kx63l'),
            nativeToken: this.getEnvOrDefault('SNIP20_TERP_NATIVE', 'ibc/AF840D44CC92103AD006850542368B888D29C4D4FFE24086E767F161FBDDCE76'),
            totalAmount: this.getEnvOrDefault('SNIP20_TERP_AMOUNT', '7100000'),
          },
          {
            name: 'THIOL',
            address: this.getEnvOrDefault('SNIP20_THIOL_ADDRESS', 'secret17wg7nl0jft3d3zv5gzrxxqm79k607wphghf9g9'),
            nativeToken: this.getEnvOrDefault('SNIP20_THIOL_NATIVE', 'ibc/7477828AC3E19352BA2D63352EA6D0680E3F29C126B87ACBDC27858CF7AF3A64'),
            totalAmount: this.getEnvOrDefault('SNIP20_THIOL_AMOUNT', '7100000'),
          }
        ]
      }
    };

    // IBC configuration
    this.ibc = {
      counterpartyChannelId: this.getEnvOrDefault('COUNTERPARTY_CHANNEL_ID', 'channel-165'),
    };

    // Encryption and security
    this.security = {
      entropy: this.getEnvOrDefault('ENTROPY', 'eretskeretjableret'),
      permitKey: this.getEnvOrDefault('PERMIT_KEY', this.getEnvOrDefault('ENTROPY', 'eretskeretjableret')),
      txEncryptionSeed: EncryptionUtilsImpl.GenerateNewSeed(),
    };

    // File paths
    this.files = {
      cwHeadstashWasm: this.getWasmPath('CW_HEADSTASH_WASM', '../../public-crates/contracts/cw-glob/src/globs/cw_headstash.wasm'),
      snip120uWasm: this.getWasmPath('SNIP120U_WASM', '../../public-crates/contracts/cw-glob/src/globs/snip120u_impl.wasm.gz'),
      polytoneNoteWasm: this.getWasmPath('POLYTONE_NOTE_WASM', '../../public-crates/artifacts/polytone_note.wasm.gz'),
      polytoneVoiceWasm: this.getWasmPath('{POLYTONE_VOICE_WASM}', '../../secret-crates/optimized-wasm/polytone_voice.wasm.gz'),
      polytoneProxyWasm: this.getWasmPath('POLYTONE_PROXY_WASM', '../../secret-crates/optimized-wasm/polytone_proxy.wasm.gz'),
    };
  }

  getEnvOrDefault(key, defaultValue) {
    const value = process.env[key];
    if (value === undefined || value === '') {
      return defaultValue;
    }
    // Try to parse as number if it looks like one
    if (/^\d+$/.test(value)) {
      return parseInt(value, 10);
    }
    return value;
  }

  getWasmPath(envKey, defaultPath) {
    const envPath = process.env[envKey];
    const finalPath = envPath || defaultPath;

    try {
      if (fs.existsSync(finalPath)) {
        return fs.readFileSync(finalPath);
      }
    } catch (error) {
      // File doesn't exist, will be handled in validation
    }
    return null;
  }

  validate() {
    const errors = [];
    const warnings = [];

    // Check for missing critical values
    if (!this.contracts.headstash.address) {
      warnings.push('Headstash contract address is not set. Some operations may fail.');
    }

    if (!this.files.cwHeadstashWasm) {
      warnings.push('CW Headstash WASM file not found. Upload operations will fail.');
    }

    // Check for default values that should probably be changed
    if (this.wallet.mnemonic.includes('amateur pond bubble')) {
      warnings.push('Using default test mnemonic. Consider setting WALLET_PRIVATE_KEY environment variable.');
    }

    if (this.security.entropy === 'eretskeretjableret') {
      warnings.push('Using default entropy. Consider setting ENTROPY environment variable for production.');
    }

    // Display warnings and errors
    if (warnings.length > 0) {
      console.warn('⚠️  Configuration Warnings:');
      warnings.forEach(warning => console.warn(`   ${warning}`));
      console.warn('');
    }

    if (errors.length > 0) {
      console.error('❌ Configuration Errors:');
      errors.forEach(error => console.error(`   ${error}`));
      process.exit(1);
    }
  }

  // Helper methods for easy access
  getSnip120uByName(name) {
    return this.contracts.snip120u.instances.find(instance =>
      instance.name.toLowerCase() === name.toLowerCase()
    );
  }

  getSnip120uByIndex(index) {
    return this.contracts.snip120u.instances[index];
  }

  // Method to update configuration at runtime
  updateHeadstashAddress(address) {
    this.contracts.headstash.address = address;
    console.log(`✅ Updated headstash address to: ${address}`);
  }

  updateSnip120uAddress(name, address) {
    const instance = this.getSnip120uByName(name);
    if (instance) {
      instance.address = address;
      console.log(`✅ Updated ${name} SNIP120u address to: ${address}`);
    } else {
      console.error(`❌ SNIP120u instance '${name}' not found`);
    }
  }

  // Display current configuration
  display() {
    console.log('🔧 Current Configuration:');
    console.log(`   Network: ${this.network.chainId}`);
    console.log(`   RPC: ${this.network.rpcUrl}`);
    console.log(`   Headstash: ${this.contracts.headstash.address || 'NOT SET'}`);
    console.log(`   Polytone Note: ${this.contracts.polytone.note.address  || 'NOT SET'}`);
    console.log(`   Polytone Voice: ${this.contracts.polytone.voice.address || 'NOT SET'}`);
    console.log(`   Polytone Proxy: ${this.contracts.polytone.proxy.address || 'NOT SET'}`);
    console.log(`   SNIP120u instances: ${this.contracts.snip120u.instances.length}`);
    this.contracts.snip120u.instances.forEach((instance, i) => {
      console.log(`     ${i + 1}. ${instance.name}: ${instance.address}`);
    });
    console.log('');
  }
}

// Export singleton instance
export const config = new Config();

// Export individual components for backward compatibility
export const {
  network: { chainId, rpcUrl },
  wallet: { mnemonic },
  contracts: { headstash, snip120u },
  ibc: { counterpartyChannelId },
  security: { entropy, permitKey, txEncryptionSeed },
  files: { cwHeadstashWasm, snip120uWasm, polytoneNoteWasm, polytoneProxyWasm, polytoneVoiceWasm }
} = config;

// Legacy exports for backward compatibility
export const headstashCodeId = headstash.codeId;
export const headstashCodeHash = headstash.codeHash;
export const headstashAddr = headstash.address;
export const snip120uCodeId = snip120u.codeId;
export const snip120uCodeHash = snip120u.codeHash;
export const snip120uAddr1 = snip120u.instances[0].address;
export const snip120uAddr2 = snip120u.instances[1].address;
export const snip120uNative1 = snip120u.instances[0].nativeToken;
export const snip120uNative2 = snip120u.instances[1].nativeToken;
export const snip120us = snip120u.instances.map(instance => ({
  native_token: instance.nativeToken,
  addr: instance.address,
  total_amount: instance.totalAmount
}));
export const cw_headstash_blob = cwHeadstashWasm;
export const polytone_proxy_blob = polytoneProxyWasm;
export const polytone_voice_blob = polytoneVoiceWasm;
export const polytone_note_blob = polytoneNoteWasm;