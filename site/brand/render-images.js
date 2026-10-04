// Renders the site's raster images from the SVGs in this folder:
// favicon-32.png, apple-touch-icon.png, icon-192.png, icon-512.png and
// og.png (1200x630). The build only copies the results.
//
// Needs Playwright with Chromium, which is not a dependency of this
// repository: `npm install --no-save playwright && npx playwright install chromium`,
// then `node site/brand/render-images.js`.

'use strict';

/* global document */

const fs = require('node:fs');
const path = require('node:path');

const {chromium} = require('playwright');

const brand = __dirname;
const out = path.join(__dirname, '..');
const svg = file => fs.readFileSync(path.join(brand, file), 'utf8');
const TILE = '#1D3536';
const BG = '#FBF7EF';

const icon = (file, size, padding, background) => `<body style="margin:0;background:${background}">
<div style="width:${size}px;height:${size}px;display:grid;place-items:center">
<div style="width:${size - (2 * padding)}px;height:${size - (2 * padding)}px">${svg(file)}</div></div></body>`;

const og = `<head><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400&family=IBM+Plex+Mono:wght@500&display=block"></head>
<body style="margin:0;width:1200px;height:630px;background:${BG};display:flex;flex-direction:column;justify-content:center;padding:0 110px;box-sizing:border-box">
<div style="height:150px">${svg('logo.svg')}</div>
<p style="margin:44px 0 0;font:400 42px/1.3 'IBM Plex Sans',sans-serif;color:#425958;max-width:900px">Verify that production servers run exactly the code in a public repository.</p>
<p style="margin:36px 0 0;padding-top:28px;border-top:2px solid #E0D5C3;font:500 28px 'IBM Plex Mono',monospace;color:#236661">auditstatus.com</p>
</body>`;

(async () => {
  const browser = await chromium.launch();
  const shot = async (html, width, height, file, transparent = false) => {
    const page = await browser.newPage({viewport: {width, height}});
    await page.setContent(html.replaceAll('<svg ', '<svg width="100%" height="100%" preserveAspectRatio="xMinYMid meet" '), {waitUntil: 'networkidle'});
    await page.evaluate(() => document.fonts.ready);
    await page.screenshot({path: path.join(out, file), omitBackground: transparent});
    await page.close();
  };

  await shot(icon('favicon.svg', 32, 0, 'transparent'), 32, 32, 'favicon-32.png', true);
  await shot(icon('mark.svg', 180, 18, TILE), 180, 180, 'apple-touch-icon.png');
  await shot(icon('mark.svg', 192, 20, TILE), 192, 192, 'icon-192.png');
  await shot(icon('mark.svg', 512, 52, TILE), 512, 512, 'icon-512.png');
  await shot(og, 1200, 630, 'og.png');
  await browser.close();
})();
