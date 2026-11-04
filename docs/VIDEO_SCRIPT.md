# Demo video script (under 3 minutes)

Record in PayPal sandbox mode with real bill reading (no yellow "Mock PayPal" banner). Bill reading takes about 10 seconds, so cut the waits. `scripts/make_narration.py` turns the narration below into audio; lines starting with `>` are shot notes and are not read aloud.

## Narration

> Title card: Padala. Then the home page.

Last year, Filipinos working abroad sent home more than thirty-five billion dollars in cash. Once that cash lands, the sender can't see where it goes. In a BCG survey of overseas Filipino workers, fewer than half consistently tracked how the money was used, and family conflict over money and school rose after they left.

Padala changes what a remittance is. Instead of sending cash, the worker signs a plan, and the plan pays the family's bills directly.

> OFW, Setup: create the device key, link PayPal on PayPal's own sandbox page. Then OFW, Plan.

Meet Ate Liza, a nurse in California. She links her PayPal wallet once. Then she sets the rules: who can be paid, a monthly budget, a cap for each category, and the amount above which she wants to decide herself. Her browser signs those rules with a key that can't leave her device. That signed plan is an AP2 payment mandate.

> Family: tap the tuition sample, show the bill page. Then OFW, the bill's verification trace.

In Bacolod, her mother photographs a tuition statement. Claude reads it into a strict schema. Plain code then checks it: is the payee registered, does the account match, do the items add up? The agent signs a payment, a deterministic gateway verifies the whole chain, and PayPal moves the money: dollars from Liza's saved wallet, pesos to the school.

> Family: Negros Power sample, point at the +62% warning.

The power bill is up sixty-two percent on last October. Padala flags it, but it's within her cap, so it's paid, and she sees the warning.

> Family: upload hospital-doctored.png as Cousin Jun. Point at the tampering lines and "Stopped by gateway".

Now the hard cases. A cousin uploads a hospital bill from a clinic Liza never approved. Claude notices the total looks pasted over and the items don't add up. But that decision isn't Claude's. The clinic isn't on the signed list, so the gateway refuses.

> Family: prompt-injection sample. Then OFW, Approvals: Decline. Then a quick cut of `python scripts/redteam.py` ending on 12/12.

This notice tells any AI reading it to send the money to a new account. Claude doesn't obey. It reports the attempt, and the gateway holds the bill until Liza decides. She declines. And if a model were fooled? The red team tests that too: a payee outside the signed list is refused, whatever the AI says.

> Family: Casa Maria rent sample. OFW, Approvals: Approve and sign.

A rent bill above her limit waits for her signature on that exact payment. She approves it on her device, and it's paid.

> OFW, Dashboard, then open a paid bill: FX rate, PayPal ids, signed receipt.

Her dashboard shows every peso: the bill photo, the exchange rate, PayPal's confirmation, a signed receipt, and every check the gateway ran.

> End card: repo URL.

The AI reads the bills. It never decides whether money moves. That's Padala: remittances with rules the sender signs, settled on PayPal.
