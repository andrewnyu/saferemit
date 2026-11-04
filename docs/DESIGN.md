# Loop Remit: design

Loop Remit is a closed-loop remittance: it lets an overseas Filipino worker (OFW) pay the family's bills directly, under rules the OFW signs once, instead of sending cash. It is an entry for the PayPal AI Hackathon 2026 (deadline 2026-11-12 12:00 PT; judged equally on technical implementation, design, impact, innovation and presentation).

## Problem

- Cash remittances to the Philippines hit a record $35.63B in 2025 (BSP); personal remittances $39.6B, 7.3% of GDP. The US is the largest source (39.7%).
- BCG survey of 1,337 OFWs: they want more say over how remittances are spent; fewer than half consistently monitor how money is used; family conflict over financial support and children's education rose 11% after migration.
- Bill pay exists (Xoom via Bayad Center), but nothing gives the sender verifiable, purpose-bound control.

## Core idea

Treat a remittance plan as an AP2 v0.2 open Payment Mandate (https://github.com/google-agentic-commerce/AP2, `docs/ap2/`). The OFW signs constraints once on a Trusted Surface. An AI bill agent turns family-submitted bills into closed mandates signed with its own key. A deterministic gateway (never an LLM) verifies everything before PayPal moves money.

## Actors

- **Sender (OFW)**: abroad (US/SG/UAE), pays from a vaulted PayPal wallet.
- **Household**: family members in the Philippines who submit bills from a phone.
- **Payees**: school, power co-op, pharmacy, landlord; in the sandbox these are PayPal sandbox business accounts.
- **Bill agent (AI)**: extracts and checks bills, drafts closed mandates, signs them with its agent key.
- **Gateway**: deterministic verifier plus budget ledger.

## Flow

1. **Plan setup**
   - The OFW vaults their PayPal wallet once (Payment Method Tokens v3 setup token, then payment token; billing-agreement approval in sandbox).
   - The OFW signs an open Payment Mandate (`vct: mandate.payment.open.1`) as an SD-JWT. Signing uses a non-extractable WebCrypto ECDSA P-256 device key registered at onboarding (a passkey/WebAuthn variant is a stretch goal).
   - `cnf` holds the bill agent's public JWK; `exp` is short (about 30 days).
   - Built-in AP2 constraints: `payment.allowed_payees` (array elements selectively disclosable), `payment.budget` + `payment.agent_recurrence` (monthly), `payment.amount_range`, `payment.execution_date`.
   - Custom constraint types (AP2 allows new `type`s with schema + evaluation algorithm):
     - `loopremit.category_cap`: e.g. education ₱15k per term, medical ₱10k per month
     - `loopremit.evidence_required`: the bill image hash must be bound via `payment.reference`
     - `loopremit.step_up_over`: above a threshold, switch to human-present mode and the OFW signs the closed mandate
2. **Bill intake (AI, not a chatbot)**
   - Family uploads photos of bills, school statements (often handwritten), prescriptions, or official receipts for reimbursement, in Tagalog, Hiligaynon or Cebuano.
   - An AI vision model with structured output extracts: biller, account number, amount, currency, due date, line items, category.
   - Checks:
     - payee registry match (the biller is in the allowed payees and the account number matches history)
     - line items sum to the total
     - an anomaly score against per-payee seasonal history (median/MAD; tuition peaks June/Aug, power peaks in summer)
     - duplicate detection with a perceptual hash
   - Output: a closed Payment Mandate (`vct: mandate.payment.1`), agent-signed, presenting only the needed disclosures of the open mandate with a KB-JWT (`aud`, `nonce`, `sd_hash`).
3. **Gateway verification (deterministic)**
   - Checks: issuer signature against the OFW device key, disclosure digests, KB-JWT against `cnf`, the closed mandate signature, every constraint, the atomic budget ledger, and replay (AP2: no new presentation of an open mandate without a rejection receipt for the previous one; unique `transaction_id`).
   - Returns signed receipts. Every step is recorded so the UI can show a verification trace.
4. **Settlement on PayPal (sandbox)**
   - Charge the OFW's vaulted wallet in USD (Orders v2, `payment_source.paypal.vault_id`, intent CAPTURE).
   - Convert at a recorded FX rate (frankfurter.app with a cached fallback).
   - Pay the payee via Payouts in PHP (Philippines supports send/receive/withdraw in PHP; PHP is a Payouts currency). Reimbursements go to the family member's PayPal.
   - Payees that issue PayPal Invoices can be paid from the invoice as structured evidence.
5. **Visibility**: the OFW dashboard shows every peso, the verified payee, the bill image, the receipt and the verification trace. The family view shows the remaining budget per category.
6. **Disputes**: the mandate chain plus bill evidence is the evidence pack (Disputes API).

## Demo script (under 3 minutes)

The full narration and shot list are in [VIDEO_SCRIPT.md](VIDEO_SCRIPT.md).

1. OFW working abroad sets up the plan and signs.
2. Mom in San Carlos City, Negros Occidental uploads a tuition statement and a power bill. AI extracts both and flags the power bill +62% vs last October but within its cap. Both are paid automatically.
3. A cousin uploads a doctored "hospital bill" from an unknown clinic. AI flags tampering; the gateway rejects it (`payee not in allowed_payees`); it escalates to the OFW, who declines.
4. A prompt injection inside a bill tells the agent to pay a new payee. The AI model reports it, and the gateway holds the bill for the OFW, who declines. The red team shows that even a fooled model cannot add a payee.
5. Dashboard with every peso and signed receipts.

## Honest limits

- Real PH utilities would need a biller aggregator (e.g. Bayad); the sandbox uses PayPal business accounts as payees.
- A live service is money transmission and needs licensing or PayPal's multiparty model.
- Vaulting works in the sender's country (US/SG/EU/...), not PH, which fits because the sender is abroad.
