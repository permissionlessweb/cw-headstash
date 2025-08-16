#[cosmwasm_schema::cw_serde]
pub enum HeadstashSeq {
    UploadHeadstash,
    InitSnips,
    InitHeadstash,
}

impl From<HeadstashSeq> for String {
    fn from(ds: HeadstashSeq) -> Self {
        match ds {
            HeadstashSeq::UploadHeadstash => "cw-headstash".to_string(),
            HeadstashSeq::InitSnips => "snip120u-init-".to_string(),
            HeadstashSeq::InitHeadstash => "cw-headstash-init".to_string(),
        }
    }
}
impl HeadstashSeq {
    pub fn indexed_snip(&self, i: usize) -> String {
        match self {
            HeadstashSeq::InitSnips => format!("snip120u-init-{}", i),
            _ => panic!("Invalid HeadstashSequence formatted_str value"),
        }
    }
}
