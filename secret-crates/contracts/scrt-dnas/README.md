# Scrt-DNAS

## Goals
- implement API key storage contract complimenting a trust minimized DAO operated,decentralized network attached storage.
- implement storage-access-pattern migigation techniques

### Registering DNAS Keys
 <!-- Dnas keys storage makes use of the delayed-write-buffer design pattern, to obfusecate storage access patterns. All this means is that there is additional hardening to the privacy of the association between the registered api key and the key registering. -->
<!-- The API key is saved to the state as a dwb.  -->

Any DAO member registering a key to the dnas api endpoint will sign an offline signature in the adr-036 standard for cosmos-sdk. This will be signed by the dnas middlware keys used, and provided to the contract to save to the state.

 
### Querying DNAS Keys
Queries reuses the same 2-step authentication technique as the registration workflo, including nonce pretection.

 
### Standard SigDoc

```rs
#[cw_serde]
pub struct DmAuthSignDoc {
    pub chain_id: String,
    pub account_number: String,
    pub sequence: String,
    pub fee: StdFee,
    pub msgs: Vec<Binary>,
    pub memo: String,
    pub timeout_height: Option<String>,
}
```


 ### Message Signed By Dao Member
 The only object in the `msg` for the signDoc is the following:

 ```rs
pub struct DaoMemberAuth {
    pub data: Binary,
    pub auth: Auth,
}
 ```

 where the auth is:
 ```rs

#[cw_serde]
pub struct DaoMemberAuth {
    ///  `SignedDataDaoMember`
    pub data: Binary,
    ///  `Auth`
    pub auth: Binary,
}
#[cw_serde]
pub struct DaoMemberData {
    pub dao: String,
    pub mw_op_addr: String,
    pub scrt_dnas_addr: String,
    pub dnas: ProfileDnasKeyWithoutIds,
}

#[cw_serde]
pub struct ProfileDnasKeyWithoutIds {
    storage_type: String,
    key_metadata: String,
    upload_limit: String,
    scrt_dnas: String,
    api_key_value: String,
}
 ```
 

 ### Message Signed By Middleware

 ```rs
 #[cw_serde]
pub struct MiddlewareAuth {
    ///  `SignedDataDaoMember`
    pub data: Binary,
    ///  `Auth`
    pub auth: Binary,
}

#[cw_serde]
pub struct MiddlewareData {
    pub dm_addr: String,
    pub nonce: String,
}

 ```