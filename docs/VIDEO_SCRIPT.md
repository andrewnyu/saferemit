# Demo video script (under 3 minutes)

Record in PayPal sandbox mode with real bill reading (no yellow "Mock PayPal" banner). Bill reading takes about 10 seconds, so cut the waits. `scripts/make_narration.py` turns the narration below into audio; lines starting with `>` are shot notes and are not read aloud.

## Narration

> Title card: Loop Remit, closed-loop remittances. Then the home page.

Last year, Filipinos working abroad sent home more than thirty-five billion dollars in cash. Once that cash lands, the sender can't see where it goes. In a BCG survey of overseas Filipino workers, fewer than half consistently tracked how the money was used, and family conflict over money and school rose after they left.

Loop Remit makes a remittance a closed loop. Instead of sending cash, the worker signs a plan, the plan pays the family's bills directly, and proof of every payment comes back.

> OFW, Setup: create the device key, link PayPal on PayPal's own sandbox page. Then OFW, Plan.

Meet Raphael Jude, an engineer from San Carlos, working abroad. Raphael links a PayPal wallet once, then sets the rules: who can be paid, a monthly budget, a cap for each category, and the amount above which Raphael decides personally. The browser signs those rules with a key that can't leave the device. That signed plan is an AP2 payment mandate.

> Family: tap the tuition sample, show the bill page. Then OFW, the bill's verification trace.

Back home in San Carlos City, Negros Occidental, Raphael's mother photographs a tuition statement. The AI model reads it into a strict schema. Plain code then checks it: is the payee registered, does the account match, do the items add up? The agent signs a payment, a deterministic gateway verifies the whole chain, and PayPal moves the money: dollars from Raphael's saved wallet, pesos to the school.

> Family: Negros Power sample, point at the +62% warning.

The power bill is up sixty-two percent on last October. Loop Remit flags it, but it's within the cap, so it's paid, and Raphael sees the warning.

> Family: upload hospital-doctored.png as Cousin Jun. Point at the tampering lines and "Stopped by gateway".

Now the hard cases. A cousin uploads a hospital bill from a clinic Raphael never approved. The AI model notices the total looks pasted over and the items don't add up. But that decision isn't the model's. The clinic isn't on the signed list, so the gateway refuses.

> Family: prompt-injection sample. Then OFW, Approvals: Decline. Then a quick cut of `python scripts/redteam.py` ending on 12/12.

This notice tells any AI reading it to send the money to a new account. The model doesn't obey. It reports the attempt, and the gateway holds the bill until Raphael decides. Raphael declines. And if a model were fooled? The red team tests that too: a payee outside the signed list is refused, whatever the AI says.

> Family: Casa Maria rent sample. OFW, Approvals: Approve and sign.

A rent bill above the limit waits for Raphael's signature on that exact payment. Raphael approves it on the device, and it's paid.

> OFW, Dashboard, then open a paid bill: FX rate, PayPal ids, signed receipt.

Raphael's dashboard shows every peso: the bill photo, the exchange rate, PayPal's confirmation, a signed receipt, and every check the gateway ran.

> End card: repo URL.

The AI reads the bills. It never decides whether money moves. That's Loop Remit: closed-loop remittances, with rules the sender signs, settled on PayPal.
