"use strict";(self.webpackChunkdocs=self.webpackChunkdocs||[]).push([[449],{9322:(e,s,t)=>{t.r(s),t.d(s,{assets:()=>a,contentTitle:()=>r,default:()=>o,frontMatter:()=>i,metadata:()=>c,toc:()=>h});var d=t(5893),n=t(1151);const i={title:"InstantiateMsg",sidebar_label:"InstantiateMsg",sidebar_position:1,slug:"/contract-api/cw-ica-owner/instantiate-msg"},r="InstantiateMsg",c={id:"contract-api/cw-ica-owner/instantiate-msg",title:"InstantiateMsg",description:"InstantiateMsg  | Description | Type |",source:"@site/docs/contract-api/cw-ica-owner/01-instantiate-msg.mdx",sourceDirName:"contract-api/cw-ica-owner",slug:"/contract-api/cw-ica-owner/instantiate-msg",permalink:"/main/contract-api/cw-ica-owner/instantiate-msg",draft:!1,unlisted:!1,editUrl:"https://github.com/permissionlessweb/cw-headstash/tree/feat/docusaurus-docs/docs/docs/contract-api/cw-ica-owner/01-instantiate-msg.mdx",tags:[],version:"current",sidebarPosition:1,frontMatter:{title:"InstantiateMsg",sidebar_label:"InstantiateMsg",sidebar_position:1,slug:"/contract-api/cw-ica-owner/instantiate-msg"},sidebar:"docsSidebar",previous:{title:"ExecuteMsg",permalink:"/main/contract-api/cw-headstash/execute-msg"},next:{title:"ExecuteMsg",permalink:"/main/contract-api/cw-ica-owner/execute-msg"}},a={},h=[{value:"<code>HeadstashParams</code>",id:"headstashparams",level:3},{value:"<code>HeadstashTokenParams</code>",id:"headstashtokenparams",level:3},{value:"<code>HeadstashInitConfig</code>",id:"headstashinitconfig",level:3}];function l(e){const s={code:"code",h1:"h1",h3:"h3",p:"p",table:"table",tbody:"tbody",td:"td",th:"th",thead:"thead",tr:"tr",...(0,n.a)(),...e.components};return(0,d.jsxs)(d.Fragment,{children:[(0,d.jsx)(s.h1,{id:"instantiatemsg",children:(0,d.jsx)(s.code,{children:"InstantiateMsg"})}),"\n",(0,d.jsxs)(s.table,{children:[(0,d.jsx)(s.thead,{children:(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.th,{children:"InstantiateMsg"}),(0,d.jsx)(s.th,{children:"Description"}),(0,d.jsx)(s.th,{children:"Type"})]})}),(0,d.jsxs)(s.tbody,{children:[(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"owner"})}),(0,d.jsx)(s.td,{children:"Owner of the contract"}),(0,d.jsxs)(s.td,{children:["Optional ",(0,d.jsx)(s.code,{children:"String"})]})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"feegranter"})}),(0,d.jsx)(s.td,{children:"Eligible address able to authorize feegrants on behalf of the ICA."}),(0,d.jsxs)(s.td,{children:["Optional ",(0,d.jsx)(s.code,{children:"String"})]})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"ica_controller_code_id"})}),(0,d.jsx)(s.td,{children:"Code-id off the cw-ica-controller contract"}),(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"u64"})})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"headstash_params"})}),(0,d.jsx)(s.td,{children:"Parameters for the cw-headstash contract"}),(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"HeadstashParams"})})]})]})]}),"\n",(0,d.jsx)(s.h3,{id:"headstashparams",children:(0,d.jsx)(s.code,{children:"HeadstashParams"})}),"\n",(0,d.jsxs)(s.table,{children:[(0,d.jsx)(s.thead,{children:(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.th,{children:"HeadstashParams"}),(0,d.jsx)(s.th,{children:"Description"}),(0,d.jsx)(s.th,{children:"Type"})]})}),(0,d.jsxs)(s.tbody,{children:[(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"cw_glob"})}),(0,d.jsx)(s.td,{children:"native x/bank token denomination for this snip120u"}),(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"String"})})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"headstash_code_id"})}),(0,d.jsx)(s.td,{children:"total amount of this to be distributed during this headstash"}),(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"Uint128"})})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"snip120u_code_id"})}),(0,d.jsx)(s.td,{children:"smart contract addr of snip120u"}),(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"Addr"})})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"snip120u_code_hash"})}),(0,d.jsx)(s.td,{children:"smart contract addr of snip120u"}),(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"Addr"})})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"token_params"})}),(0,d.jsx)(s.td,{children:"smart contract addr of snip120u"}),(0,d.jsxs)(s.td,{children:["Array of  ",(0,d.jsx)(s.code,{children:"HeadstashTokenParams"})]})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"headstash_addr"})}),(0,d.jsx)(s.td,{children:"Smart contract address of the headstash contract if already has been instantiated."}),(0,d.jsxs)(s.td,{children:["Optional ",(0,d.jsx)(s.code,{children:"String"})]})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"fee_granter"})}),(0,d.jsx)(s.td,{children:"Eligible address able to authorize feegrants on behalf of the ICA."}),(0,d.jsxs)(s.td,{children:["Optional ",(0,d.jsx)(s.code,{children:"String"})]})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"multiplier"})}),(0,d.jsx)(s.td,{children:"Enables reward multiplier for cw-headstash"}),(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"boolean"})})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"bloom_config"})}),(0,d.jsx)(s.td,{children:"Enables reward multiplier for cw-headstash"}),(0,d.jsxs)(s.td,{children:["Optional ",(0,d.jsx)(s.code,{children:"BloomConfig"})]})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"headstash_init_config"})}),(0,d.jsx)(s.td,{children:"The configuration used to instantiate cw-headstash"}),(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"HeadstashInitConfig"})})]})]})]}),"\n",(0,d.jsx)(s.p,{children:"Any existing snip120u used in HeadstashTokenParams should be defined first in the list of HeadstashParams."}),"\n",(0,d.jsx)(s.h3,{id:"headstashtokenparams",children:(0,d.jsx)(s.code,{children:"HeadstashTokenParams"})}),"\n",(0,d.jsxs)(s.table,{children:[(0,d.jsx)(s.thead,{children:(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.th,{children:"HeadstashTokenParams"}),(0,d.jsx)(s.th,{children:"Description"}),(0,d.jsx)(s.th,{children:"Type"})]})}),(0,d.jsxs)(s.tbody,{children:[(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"name"})}),(0,d.jsx)(s.td,{children:"name to use in the snip120u state"}),(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"String"})})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"symbol"})}),(0,d.jsx)(s.td,{children:"Snip120u symbol to use"}),(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"u64"})})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"native"})}),(0,d.jsx)(s.td,{children:"token denomination on its orgin providence chain"}),(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"String"})})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"ibc"})}),(0,d.jsx)(s.td,{children:"ibc token denomination of this token"}),(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"String"})})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"snip_addr"})}),(0,d.jsx)(s.td,{children:"smart contract address of the snip120u specific to this token"}),(0,d.jsxs)(s.td,{children:["Optional ",(0,d.jsx)(s.code,{children:"String"})]})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"total"})}),(0,d.jsx)(s.td,{children:"Total amount to be distributed for a specific snip"}),(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"Uint128"})})]})]})]}),"\n",(0,d.jsx)(s.h3,{id:"headstashinitconfig",children:(0,d.jsx)(s.code,{children:"HeadstashInitConfig"})}),"\n",(0,d.jsxs)(s.table,{children:[(0,d.jsx)(s.thead,{children:(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.th,{children:"HeadstashInitConfig"}),(0,d.jsx)(s.th,{children:"Description"}),(0,d.jsx)(s.th,{children:"Type"})]})}),(0,d.jsxs)(s.tbody,{children:[(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"claim_msg_plaintxt"})}),(0,d.jsx)(s.td,{children:"Snip120u symbol to use"}),(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"String"})})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"start_date"})}),(0,d.jsx)(s.td,{children:"Snip120u symbol to use"}),(0,d.jsxs)(s.td,{children:["Optional ",(0,d.jsx)(s.code,{children:"u64"})]})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"end_date"})}),(0,d.jsx)(s.td,{children:"Snip120u symbol to use"}),(0,d.jsxs)(s.td,{children:["Optional ",(0,d.jsx)(s.code,{children:"u64"})]})]}),(0,d.jsxs)(s.tr,{children:[(0,d.jsx)(s.td,{children:(0,d.jsx)(s.code,{children:"viewing_key"})}),(0,d.jsx)(s.td,{children:"Snip120u symbol to use"}),(0,d.jsx)(s.td,{children:"String"})]})]})]})]})}function o(e={}){const{wrapper:s}={...(0,n.a)(),...e.components};return s?(0,d.jsx)(s,{...e,children:(0,d.jsx)(l,{...e})}):l(e)}},1151:(e,s,t)=>{t.d(s,{Z:()=>c,a:()=>r});var d=t(7294);const n={},i=d.createContext(n);function r(e){const s=d.useContext(i);return d.useMemo((function(){return"function"==typeof e?e(s):{...s,...e}}),[s,e])}function c(e){let s;return s=e.disableParentContext?"function"==typeof e.components?e.components(n):e.components||n:r(e.components),d.createElement(i.Provider,{value:s},e.children)}}}]);