mod batch;
pub mod msg;
pub mod receiver;
pub mod state;
mod transaction_history;
pub mod contract;


/// GOALS
/// 1. Broadcast messages on behalf of account with balance, via signature permit.
///     - set allowance during mint for (secret-headstash cw-ica-controller || heady-wallet)
/// 2. Implement claiming tokens in timelocked batches (tx mempool state)
/// 3. Implement Secret cw-ica-controller, owned by this contract, to route IBC tx from wallet claiming public tokens
///     - TransferFrom + IBCHooks: ensure destination wallet is same wallet that a generated signature is derived from, or else tx fails.
pub mod headstash;