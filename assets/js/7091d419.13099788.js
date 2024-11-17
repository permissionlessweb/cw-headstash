"use strict";(self.webpackChunkdocs=self.webpackChunkdocs||[]).push([[763],{9392:(e,t,s)=>{s.r(t),s.d(t,{assets:()=>o,contentTitle:()=>i,default:()=>a,frontMatter:()=>d,metadata:()=>r,toc:()=>l});var c=s(5893),n=s(1151);const d={title:"ExecuteMsg",sidebar_label:"ExecuteMsg",sidebar_position:2,slug:"/contract-api/cw-glob/execute-msg"},i="ExecuteMsg",r={id:"contract-api/cw-glob/execute-msg",title:"ExecuteMsg",description:"The ExecuteMsg is the message that is used to interact with the cw-glob contract.",source:"@site/docs/contract-api/cw-glob/02-execute-msg.mdx",sourceDirName:"contract-api/cw-glob",slug:"/contract-api/cw-glob/execute-msg",permalink:"/main/contract-api/cw-glob/execute-msg",draft:!1,unlisted:!1,editUrl:"https://github.com/permissionlessweb/cw-headstash/tree/feat/docusaurus-docs/docs/docs/contract-api/cw-glob/02-execute-msg.mdx",tags:[],version:"current",sidebarPosition:2,frontMatter:{title:"ExecuteMsg",sidebar_label:"ExecuteMsg",sidebar_position:2,slug:"/contract-api/cw-glob/execute-msg"},sidebar:"docsSidebar",previous:{title:"InstantiateMsg",permalink:"/main/contract-api/cw-glob/instantiate-msg"},next:{title:"QueryMsg",permalink:"/main/contract-api/query-msg"}},o={},l=[{value:"<code>AddGlob</code>",id:"addglob",level:2},{value:"<code>Glob</code>",id:"glob",level:3},{value:"<code>HashGlob</code>",id:"hashglob",level:2},{value:"<code>TakeGlob</code>",id:"takeglob",level:2}];function h(e){const t={code:"code",h1:"h1",h2:"h2",h3:"h3",p:"p",strong:"strong",table:"table",tbody:"tbody",td:"td",th:"th",thead:"thead",tr:"tr",...(0,n.a)(),...e.components};return(0,c.jsxs)(c.Fragment,{children:[(0,c.jsx)(t.h1,{id:"executemsg",children:(0,c.jsx)(t.code,{children:"ExecuteMsg"})}),"\n",(0,c.jsxs)(t.p,{children:["The ",(0,c.jsx)(t.code,{children:"ExecuteMsg"})," is the message that is used to interact with the ",(0,c.jsx)(t.code,{children:"cw-glob"})," contract.\n",(0,c.jsx)(t.strong,{children:"All execute messages are only callable by the owner of the contract."})]}),"\n",(0,c.jsx)(t.h2,{id:"addglob",children:(0,c.jsx)(t.code,{children:"AddGlob"})}),"\n",(0,c.jsxs)(t.table,{children:[(0,c.jsx)(t.thead,{children:(0,c.jsxs)(t.tr,{children:[(0,c.jsx)(t.th,{children:"AddGlob"}),(0,c.jsx)(t.th,{children:"Description"}),(0,c.jsx)(t.th,{children:"Type"})]})}),(0,c.jsx)(t.tbody,{children:(0,c.jsxs)(t.tr,{children:[(0,c.jsx)(t.td,{children:(0,c.jsx)(t.code,{children:"globs"})}),(0,c.jsx)(t.td,{children:"array of storage keys and the wasm binary associated with the storage key"}),(0,c.jsxs)(t.td,{children:["Array of \t",(0,c.jsx)(t.code,{children:"Glob"})]})]})})]}),"\n",(0,c.jsx)(t.h3,{id:"glob",children:(0,c.jsx)(t.code,{children:"Glob"})}),"\n",(0,c.jsxs)(t.table,{children:[(0,c.jsx)(t.thead,{children:(0,c.jsxs)(t.tr,{children:[(0,c.jsx)(t.th,{children:"Glob"}),(0,c.jsx)(t.th,{children:"Description"}),(0,c.jsx)(t.th,{children:"Type"})]})}),(0,c.jsxs)(t.tbody,{children:[(0,c.jsxs)(t.tr,{children:[(0,c.jsx)(t.td,{children:(0,c.jsx)(t.code,{children:"key"})}),(0,c.jsx)(t.td,{children:"array of storage keys and the wasm binary associated with the storage key"}),(0,c.jsx)(t.td,{children:"String"})]}),(0,c.jsxs)(t.tr,{children:[(0,c.jsx)(t.td,{children:(0,c.jsx)(t.code,{children:"blob"})}),(0,c.jsx)(t.td,{children:"Wasm blob binary"}),(0,c.jsx)(t.td,{children:"Binary"})]})]})]}),"\n",(0,c.jsx)(t.h2,{id:"hashglob",children:(0,c.jsx)(t.code,{children:"HashGlob"})}),"\n",(0,c.jsx)(t.p,{children:"This message is used to generate the sha256sum of a wasm blob stored inside the contract state. It is only callable by the owner."}),"\n",(0,c.jsxs)(t.table,{children:[(0,c.jsx)(t.thead,{children:(0,c.jsxs)(t.tr,{children:[(0,c.jsx)(t.th,{children:"HashGlob"}),(0,c.jsx)(t.th,{children:"Description"}),(0,c.jsx)(t.th,{children:"Type"})]})}),(0,c.jsx)(t.tbody,{children:(0,c.jsxs)(t.tr,{children:[(0,c.jsx)(t.td,{children:(0,c.jsx)(t.code,{children:"keys"})}),(0,c.jsx)(t.td,{children:"array of storage keys associated to blob stored internally"}),(0,c.jsx)(t.td,{children:"Array of String"})]})})]}),"\n",(0,c.jsx)(t.h2,{id:"takeglob",children:(0,c.jsx)(t.code,{children:"TakeGlob"})}),"\n",(0,c.jsx)(t.p,{children:"This will retrieve a stored wasm blob. It is only callable by one of the owners."}),"\n",(0,c.jsxs)(t.table,{children:[(0,c.jsx)(t.thead,{children:(0,c.jsxs)(t.tr,{children:[(0,c.jsx)(t.th,{children:"TakeGlob"}),(0,c.jsx)(t.th,{children:"Description"}),(0,c.jsx)(t.th,{children:"Type"})]})}),(0,c.jsxs)(t.tbody,{children:[(0,c.jsxs)(t.tr,{children:[(0,c.jsx)(t.td,{children:(0,c.jsx)(t.code,{children:"sender"})}),(0,c.jsx)(t.td,{children:"Address to include in the CosmosMsg with the wasm blob. For cw-headstash, this will be the ica account on the host chain."}),(0,c.jsx)(t.td,{children:"String"})]}),(0,c.jsxs)(t.tr,{children:[(0,c.jsx)(t.td,{children:(0,c.jsx)(t.code,{children:"key"})}),(0,c.jsx)(t.td,{children:"The wasm blob key to upload."}),(0,c.jsx)(t.td,{children:"String"})]}),(0,c.jsxs)(t.tr,{children:[(0,c.jsx)(t.td,{children:(0,c.jsx)(t.code,{children:"memo"})}),(0,c.jsx)(t.td,{children:"Optional memo to pass in ica-account"}),(0,c.jsx)(t.td,{children:"Optional String"})]}),(0,c.jsxs)(t.tr,{children:[(0,c.jsx)(t.td,{children:(0,c.jsx)(t.code,{children:"timeout"})}),(0,c.jsx)(t.td,{children:"Optional timeout in seconds to include with the ibc packet."}),(0,c.jsx)(t.td,{children:"Optional u64"})]})]})]})]})}function a(e={}){const{wrapper:t}={...(0,n.a)(),...e.components};return t?(0,c.jsx)(t,{...e,children:(0,c.jsx)(h,{...e})}):h(e)}},1151:(e,t,s)=>{s.d(t,{Z:()=>r,a:()=>i});var c=s(7294);const n={},d=c.createContext(n);function i(e){const t=c.useContext(d);return c.useMemo((function(){return"function"==typeof e?e(t):{...t,...e}}),[t,e])}function r(e){let t;return t=e.disableParentContext?"function"==typeof e.components?e.components(n):e.components||n:i(e.components),c.createElement(d.Provider,{value:t},e.children)}}}]);