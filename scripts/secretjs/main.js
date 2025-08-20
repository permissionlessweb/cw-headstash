import { Wallet, SecretNetworkClient } from "secretjs";
import {
  config, mnemonic, chainId, rpcUrl, txEncryptionSeed, entropy,
  headstashCodeId, snip120uCodeId, snip120uCodeHash,
  snip120uAddr1, snip120uAddr2,
  snip120uNative1, snip120uNative2,
  cw_headstash_blob, polytone_note_blob, polytone_proxy_blob, polytone_voice_blob
} from './config.js';

import { init_snip120u, query_contract_info, deposit_to_snip20, query_token_info, query_token_config, set_viewing_key, query_balance, fund_headstash, upload_snip120u } from './snip20.js'
import { upload_headstash_contract, instantiate_headstash_contract } from "./headstash.js";
import { upload_polytone_contracts } from "./polytone.js";
import { generateEthKeyAndSignMessage, generateSolanaKeyAndSignMessage } from './testKeys.js';

// Display current configuration on startup
config.display();

// Initialize wallet and client
export const wallet = new Wallet(mnemonic);

export const secretjs = new SecretNetworkClient({
  chainId: chainId,
  url: rpcUrl,
  wallet: wallet,
  walletAddress: wallet.address,
  // txEncryptionSeed: txEncryptionSeed
});

// Helper functions for better error handling
function requireArg(args, index, usage) {
  if (args.length <= index) {
    console.error(`❌ Missing required argument.`);
    console.error(`Usage: ${usage}`);
    process.exit(1);
  }
  return args[index];
}

async function handleAsyncCommand(promise, successMessage, errorPrefix = "Failed") {
  try {
    await promise;
    console.log(`✅ ${successMessage}`);
  } catch (error) {
    console.error(`❌ ${errorPrefix}:`, error.message || error);
    process.exit(1);
  }
}

function validateContractAddress(address, contractName) {
  if (!address || address === "") {
    console.error(`❌ ${contractName} address is not configured.`);
    console.error(`   Set it in your .env file or update the configuration.`);
    process.exit(1);
  }
}

// Command definitions for better organization and help
const commands = {
  // Upload commands
  'upload-headstash': {
    description: 'Upload headstash contract',
    usage: 'upload-headstash',
    go: () => {
      if (!cw_headstash_blob) {
        console.error('❌ Headstash WASM file not found. Check your configuration.');
        process.exit(1);
      }
      return handleAsyncCommand(
        upload_headstash_contract(cw_headstash_blob),
        'Headstash contract uploaded successfully'
      );
    }
  },
  'upload-polytone-proxy': {
    description: 'Upload polytone proxy contract on secret network',
    usage: 'upload-polytone-proxy',
    go: () => {
      if (!polytone_proxy_blob) {
        console.error('❌ Polytone proxy WASM not found. Check your configuration.');
        process.exit(1);
      }
      return handleAsyncCommand(
        upload_polytone_contracts(polytone_proxy_blob),
        'Polytone proxy contract uploaded successfully'
      );
    }
  },
  'upload-polytone-voice': {
    description: 'Upload polytone voice contract on secret network. ',
    usage: 'upload-polytone',
    go: () => {
      console.log(`Current working directory: ${process.cwd()}`);
      if (!polytone_voice_blob) {
        console.error('❌ Polytone voice WASM not found. Check your configuration.');
        process.exit(1);
      }
      return handleAsyncCommand(
        upload_polytone_contracts(polytone_voice_blob),
        'Polytone voice contract uploaded successfully'
      );
    }
  },

  // Instantiate commands
  'init-snip20-terp': {
    description: 'Initialize TERP SNIP20 token',
    usage: 'init-snip20-terp',
    go: () => handleAsyncCommand(
      init_snip120u("secret terp test", "scrtTERP", snip120uNative1),
      'TERP SNIP20 token created successfully'
    )
  },

  'init-snip20-thiol': {
    description: 'Initialize THIOL SNIP20 token',
    usage: 'init-snip20-thiol',
    go: () => handleAsyncCommand(
      init_snip120u("secret thioool test", "scrtTHIOL", snip120uNative2),
      'THIOL SNIP20 token created successfully'
    )
  },

  'init-headstash': {
    description: 'Instantiate headstash contract',
    usage: 'init-headstash',
    go: () => handleAsyncCommand(
      instantiate_headstash_contract(),
      'Headstash contract instantiated successfully'
    )
  },

  // Token conversion commands
  'convert-terp': {
    description: 'Convert native TERP to secret TERP',
    usage: 'convert-terp <amount>',
    go: (args) => {
      const amount = requireArg(args, 1, 'convert-terp <amount>');
      validateContractAddress(snip120uAddr1, 'TERP SNIP20');
      return handleAsyncCommand(
        deposit_to_snip20(snip120uAddr1, amount, snip120uNative1),
        `Converted ${amount} TERP to secret form`
      );
    }
  },

  'convert-thiol': {
    description: 'Convert native THIOL to secret THIOL',
    usage: 'convert-thiol <amount>',
    go: (args) => {
      const amount = requireArg(args, 1, 'convert-thiol <amount>');
      validateContractAddress(snip120uAddr2, 'THIOL SNIP20');
      return handleAsyncCommand(
        deposit_to_snip20(snip120uAddr2, amount, snip120uNative2),
        `Converted ${amount} THIOL to secret form`
      );
    }
  },

  // Viewing key commands
  'set-viewing-key-terp': {
    description: 'Set viewing key for TERP SNIP20',
    usage: 'set-viewing-key-terp',
    go: () => {
      validateContractAddress(snip120uAddr1, 'TERP SNIP20');
      return handleAsyncCommand(
        set_viewing_key(snip120uAddr1, entropy),
        'TERP viewing key created'
      );
    }
  },

  'set-viewing-key-thiol': {
    description: 'Set viewing key for THIOL SNIP20',
    usage: 'set-viewing-key-thiol',
    go: () => {
      validateContractAddress(snip120uAddr2, 'THIOL SNIP20');
      return handleAsyncCommand(
        set_viewing_key(snip120uAddr2, entropy),
        'THIOL viewing key created'
      );
    }
  },

  // Fee grant command
  'feegrant': {
    description: 'Grant fee allowance to an address (not implemented)',
    usage: 'feegrant <recipient-address>',
    go: (args) => {
      console.log('❌ Fee grant functionality not implemented yet.');
      console.log('   Implement the broadcastFeeGrant function or import it from the appropriate module.');
    }
  },
  // Query commands
  'query-terp-info': {
    description: 'Query TERP SNIP20 token info',
    usage: 'query-terp-info',
    go: () => {
      validateContractAddress(snip120uAddr1, 'TERP SNIP20');
      query_token_info(snip120uAddr1, snip120uCodeHash);
    }
  },

  'query-thiol-info': {
    description: 'Query THIOL SNIP20 token info',
    usage: 'query-thiol-info',
    go: () => {
      validateContractAddress(snip120uAddr2, 'THIOL SNIP20');
      query_token_info(snip120uAddr2, snip120uCodeHash);
    }
  },

  'query-terp-config': {
    description: 'Query TERP SNIP20 configuration',
    usage: 'query-terp-config',
    go: () => {
      validateContractAddress(snip120uAddr1, 'TERP SNIP20');
      query_token_config(snip120uAddr1, snip120uCodeHash);
    }
  },

  'query-thiol-config': {
    description: 'Query THIOL SNIP20 configuration',
    usage: 'query-thiol-config',
    go: () => {
      validateContractAddress(snip120uAddr2, 'THIOL SNIP20');
      query_token_config(snip120uAddr2, snip120uCodeHash);
    }
  },

  'query-snip20-hash': {
    description: 'Query SNIP20 contract code hash',
    usage: 'query-snip20-hash',
    go: () => query_contract_info(snip120uCodeId)
  },

  'query-headstash-hash': {
    description: 'Query headstash contract code hash',
    usage: 'query-headstash-hash',
    go: () => query_contract_info(headstashCodeId)
  },

  'query-terp-balance': {
    description: 'Query TERP SNIP20 balance',
    usage: 'query-terp-balance',
    go: () => {
      validateContractAddress(snip120uAddr1, 'TERP SNIP20');
      return handleAsyncCommand(
        query_balance(snip120uAddr1, entropy),
        'TERP balance queried successfully'
      );
    }
  },

  'query-thiol-balance': {
    description: 'Query THIOL SNIP20 balance',
    usage: 'query-thiol-balance',
    go: () => {
      validateContractAddress(snip120uAddr2, 'THIOL SNIP20');
      return handleAsyncCommand(
        query_balance(snip120uAddr2, entropy),
        'THIOL balance queried successfully'
      );
    }
  },


  // Headstash and utility commands (TODO: Implement these functions)
  'claim': {
    description: 'Claim airdrop for an account (not implemented)',
    usage: 'claim <account-id>',
    go: (args) => {
      console.log('❌ Claim functionality not implemented yet.');
      console.log('   Uncomment and implement the claim import from "./account.js"');
    }
  },

  'add-batch': {
    description: 'Generate batch entries (not implemented)',
    usage: 'add-batch',
    go: () => {
      console.log('❌ Batch functionality not implemented yet.');
      console.log('   Uncomment and implement the printBatch import from "./batch-add.js"');
    }
  },

  'gen-eth-signature': {
    description: 'Generate test Ethereum signature',
    usage: 'gen-eth-signature [message]',
    go: (args) => {
      const message = args[1] || "H.R.E.A.M. Sender: hs69";
      generateEthKeyAndSignMessage(message);
    }
  },

  'gen-sol-signature': {
    description: 'Generate test Solana signature',
    usage: 'gen-sol-signature [message]',
    go: (args) => {
      const message = args[1] || "H.R.E.A.M. Sender: hs3";
      generateSolanaKeyAndSignMessage(message);
    }
  },

  // Configuration commands
  'config': {
    description: 'Show current configuration',
    usage: 'config',
    go: () => config.display()
  },

  'help': {
    description: 'Show available commands',
    usage: 'help [command]',
    go: (args) => {
      if (args[1]) {
        const cmd = commands[args[1]];
        if (cmd) {
          console.log(`📖 ${args[1]}: ${cmd.description}`);
          console.log(`   Usage: node main.js ${cmd.usage}`);
        } else {
          console.error(`❌ Unknown command: ${args[1]}`);
        }
      } else {
        showHelp();
      }
    }
  }
};

// Help function
function showHelp() {
  console.log('🚀 Headstash SecretJS CLI\n');
  console.log('Available commands:\n');

  const categories = {
    'Upload': ['upload-headstash', 'upload-polytone-note', 'upload-polytone-voice', 'upload-polytone-proxy'],
    'Initialize': ['init-snip20-terp', 'init-snip20-thiol', 'init-headstash'],
    'Token Operations': ['convert-terp', 'convert-thiol', 'set-viewing-key-terp', 'set-viewing-key-thiol'],
    'Queries': ['query-terp-info', 'query-thiol-info', 'query-terp-config', 'query-thiol-config', 'query-snip20-hash', 'query-headstash-hash', 'query-terp-balance', 'query-thiol-balance'],
    'Headstash': ['claim', 'add-batch'],
    'Utilities': ['gen-eth-signature', 'gen-sol-signature', 'feegrant', 'config', 'help']
  };

  for (const [category, cmdList] of Object.entries(categories)) {
    console.log(`${category}:`);
    cmdList.forEach(cmd => {
      const command = commands[cmd];
      if (command) {
        console.log(`  ${cmd.padEnd(25)} ${command.description}`);
      }
    });
    console.log('');
  }

  console.log('For detailed usage of a specific command: node main.js help <command>');
  console.log('Example: node main.js help convert-terp\n');
}

// Process command line arguments
const args = process.argv.slice(2);

if (args.length < 1) {
  showHelp();
  process.exit(0);
}

const command = args[0];
const cmd = commands[command];

if (cmd) {
  try {
    cmd.go(args);
  } catch (error) {
    console.error(`❌ Error executing command '${command}':`, error.message || error);
    process.exit(1);
  }
} else {
  console.error(`❌ Unknown command: ${command}`);
  console.log('Run "node main.js help" to see available commands.');
  process.exit(1);
}



