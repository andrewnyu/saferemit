// End-to-end browser check of the DESIGN.md demo script (mock mode).
//
//   PADALA_DATA_DIR=/tmp/padala-e2e PADALA_INTAKE_MODE=offline uvicorn padala.web.app:app --port 8765 &
//   mkdir -p /tmp/shots && BASE=http://127.0.0.1:8765 OUT=/tmp/shots SAMPLES=$PWD/samples node scripts/e2e_demo.js
//
// Needs Node and Playwright (npm i playwright; npx playwright install chromium).
// Real WebCrypto signing: the browser generates the device key, signs the plan
// and the step-up approval, and the server verifies both.
const { chromium } = require('playwright');
const BASE = process.env.BASE || 'http://localhost:8765';
const OUT = process.env.OUT;
(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();
  page.on('console', m => { if (m.type() === 'error') console.log('console error:', m.text()); });
  page.on('pageerror', e => console.log('page error:', e.message));
  const shot = async (n) => page.screenshot({ path: `${OUT}/${n}.png`, fullPage: true });

  // 1. OFW onboarding: device key + PayPal vault (mock approval page)
  await page.goto(BASE + '/ofw/onboarding');
  await page.click('#create-key');
  await page.waitForSelector('#key-status.ok');
  console.log('key status:', (await page.textContent('#key-status')).trim());
  await page.click('text=Link PayPal wallet');
  await page.waitForURL(/mock-approve/);
  await shot('02-mock-approve');
  await page.click('text=Agree and continue');
  await page.waitForURL(/vault=ok/);
  console.log('vault:', (await page.textContent('.callout.ok')).trim().slice(0, 80));
  await shot('01-onboarding');

  // 1b. Plan: review (browser verifies digests) and sign
  await page.goto(BASE + '/ofw/plan');
  await page.click('#review');
  await page.waitForSelector('#sheet:not([hidden])');
  console.log('disclosures verified in browser:', await page.textContent('#n-disc'));
  await shot('03-sign-sheet');
  await page.click('#sign');
  await page.waitForSelector('#signed:not([hidden])');
  console.log('signed:', (await page.textContent('#signed')).trim().slice(0, 60));

  // 2. Family uploads tuition + power bill (sample buttons)
  for (const key of ['tuition', 'negros-power']) {
    await page.goto(BASE + '/family');
    await page.click(`form[action="/family/samples/${key}"] button`);
    await page.waitForURL(/family\/bills\/\d+/);
    console.log(key, '->', (await page.textContent('.badge')).trim());
  }
  await shot('05-family-bill-power');

  // 3. Cousin uploads a doctored hospital bill through the real file input
  await page.goto(BASE + '/family');
  await page.fill('input[name=submitted_by]', 'Cousin Jun');
  await page.setInputFiles('input[type=file]', process.env.SAMPLES + '/hospital-doctored.png');
  await page.click('form[action="/family/bills"] button');
  await page.waitForURL(/family\/bills\/\d+/);
  console.log('hospital ->', (await page.textContent('.badge')).trim());

  // 4. Prompt-injection bill
  await page.goto(BASE + '/family');
  await page.click('form[action="/family/samples/prompt-injection"] button');
  await page.waitForURL(/family\/bills\/\d+/);
  console.log('injection ->', (await page.textContent('.badge')).trim());

  // Extra: rent over the step-up threshold
  await page.goto(BASE + '/family');
  await page.click('form[action="/family/samples/casa-maria-rent"] button');
  await page.waitForURL(/family\/bills\/\d+/);
  console.log('rent ->', (await page.textContent('.badge')).trim());
  await page.goto(BASE + '/family');
  await shot('04-family');

  // OFW: approvals: approve the rent (step-up), decline the injection held for review
  await page.goto(BASE + '/ofw/approvals');
  await shot('06-approvals');
  await page.click(`section:has-text("Casa Maria") button[data-decision=approve]`);
  await page.waitForURL(/ofw\/bills\/\d+/);
  console.log('rent after step-up ->', (await page.textContent('h1 ~ * .badge, .spread .badge')).trim());
  await page.goto(BASE + '/ofw/approvals');
  const declines = await page.$$('button.danger.decide');
  console.log('pending declinable items:', declines.length);
  await declines[0].click();
  await page.waitForURL(/ofw\/bills\/\d+/);
  await shot('07-bill-declined');

  // 5. Dashboard and a paid bill's trace
  await page.goto(BASE + '/ofw');
  await shot('08-dashboard');
  const rows = await page.$$eval('.bill-list li', lis => lis.map(li => li.innerText.replace(/\s+/g, ' ').slice(0, 150)));
  rows.forEach(r => console.log('  ', r));
  await page.click('.bill-list >> text=Negros Power');
  await page.waitForURL(/ofw\/bills\/\d+/);
  await shot('09-bill-detail-power');
  const passes = await page.$$eval('.trace li.pass', l => l.length);
  console.log('power bill trace steps passed:', passes);

  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(BASE + '/ofw');
  await shot('10-dashboard-desktop');
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
