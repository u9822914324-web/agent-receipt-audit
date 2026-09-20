const MAX_ROWS = 500;
const TX_RE = /^0x[a-fA-F0-9]{64}$/;
const ADDR_RE = /^0x[a-fA-F0-9]{40}$/;
const money = (value: unknown) => { const n = Number(value); return Number.isFinite(n) ? n : null; };
export function auditLedger(input: any) {
  if (!input || typeof input !== "object" || !Array.isArray(input.entries)) throw new Error("Body must be an object with an entries array.");
  if (!input.entries.length || input.entries.length > MAX_ROWS) throw new Error(`entries must contain 1-${MAX_ROWS} rows.`);
  const findings: any[] = [], txSeen = new Map<string, number>(); let claimed=0, externallySettled=0, costs=0, settledRows=0;
  input.entries.forEach((row: any,index: number)=>{
    const amount=money(row.amountUsd); if(amount===null||amount<0){findings.push({index,severity:"error",code:"INVALID_AMOUNT",message:"amountUsd must be a non-negative number."});return;}
    const kind=String(row.kind||"").toLowerCase(); if(["cost","spend","expense"].includes(kind)){costs+=amount;return;} claimed+=amount;
    const status=String(row.status||"").toLowerCase(), external=row.external===true, txHash=String(row.txHash||""), payer=String(row.payer||""), receiver=String(row.receiver||"");
    const validTx=TX_RE.test(txHash), validParties=ADDR_RE.test(payer)&&ADDR_RE.test(receiver)&&payer.toLowerCase()!==receiver.toLowerCase(), settled=["settled","paid","confirmed"].includes(status);
    if(!settled)findings.push({index,severity:"warning",code:"NOT_SETTLED",message:"Revenue is not marked settled/paid/confirmed."});
    if(!external)findings.push({index,severity:"warning",code:"NOT_EXTERNAL",message:"Revenue is not explicitly marked external."});
    if(!validTx)findings.push({index,severity:"warning",code:"MISSING_TX_EVIDENCE",message:"A 0x-prefixed 32-byte transaction hash is required as settlement evidence."});
    if(!validParties)findings.push({index,severity:"warning",code:"PARTY_EVIDENCE_WEAK",message:"Provide distinct payer and receiver EVM addresses."});
    if(validTx){const key=txHash.toLowerCase();if(txSeen.has(key))findings.push({index,severity:"error",code:"DUPLICATE_TX",message:`Same transaction already used by row ${txSeen.get(key)}.`});else txSeen.set(key,index);}
    if(settled&&external&&validTx&&validParties&&!findings.some(f=>f.index===index&&f.code==="DUPLICATE_TX")){externallySettled+=amount;settledRows++;}
  });
  const round=(n:number)=>Math.round(n*1e6)/1e6;
  return {schemaVersion:"1.0",verdict:findings.some(f=>f.severity==="error")?"fail":findings.length?"review":"pass",summary:{rows:input.entries.length,externallySettledRows:settledRows,claimedRevenueUsd:round(claimed),evidenceBackedExternalRevenueUsd:round(externallySettled),costsUsd:round(costs),evidenceBackedNetUsd:round(externallySettled-costs),overcountUsd:round(Math.max(0,claimed-externallySettled))},findings,note:"Static evidence audit only. Transaction shape is checked, but chain inclusion is not queried."};
}
