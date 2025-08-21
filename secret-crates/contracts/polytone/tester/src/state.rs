use polytone::callbacks::CallbackMessage;
use secret_toolkit::storage::Item;

pub(crate) const CALLBACK_HISTORY: Item<Vec<CallbackMessage>> = Item::new(b"a");
pub(crate) const HELLO_CALL_HISTORY: Item<Vec<String>> = Item::new(b"b");
