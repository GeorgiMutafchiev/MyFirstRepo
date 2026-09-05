import http from "node:http";
import { randomUUID } from "node:crypto";
import { promises as dns } from "node:dns";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import puppeteer from "puppeteer-core";
import chromium from "@sparticuz/chromium";

const require = createRequire(import.meta.url);
const rrwebScriptPath = require.resolve("rrweb/dist/rrweb.min.js");
const rrwebScript = readFileSync(rrwebScriptPath, "utf8");
const PORT = Number(process.env.PORT || 10000);
const TOKEN = process.env.ORIGIN_CAPTURE_TOKEN || "";
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/$/, "");
const MAX_BODY_BYTES = 64_000;
const MAX_CAPTURE_MS = 120_000;
const ARTIFACT_TTL_MS = 30 * 60_000;
const artifacts = new Map();
let browserPromise;

function getBrowser() {
  if (!browserPromise) {
    browserPromise = (async () => {
      chromium.setGraphicsMode = false;
      const browser = await puppeteer.launch({
        args: await puppeteer.defaultArgs({ args: chromium.args, headless: "shell" }),
        defaultViewport: { width: 1440, height: 1000 },
        executablePath: await chromium.executablePath(),
        headless: "shell",
        timeout: 90_000,
      });
      browser.once("disconnected", () => { browserPromise = undefined; });
      return browser;
    })().catch((error) => {
      browserPromise = undefined;
      throw error;
    });
  }
  return browserPromise;
}

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  response.end(JSON.stringify(body));
}

function isPrivateAddress(address) {
  return /^(?:127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|::1$|fc|fd|fe80)/i.test(address);
}

async function validateTarget(rawUrl) {
  const url = new URL(rawUrl);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("Only HTTP and HTTPS URLs are supported.");
  if (url.username || url.password) throw new Error("URLs containing credentials are not supported.");
  const records = await dns.lookup(url.hostname, { all: true, verbatim: true });
  if (!records.length || records.some((record) => isPrivateAddress(record.address))) throw new Error("Private and local network targets are blocked.");
  return url;
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new Error("Capture request is too large.");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function withTimeout(promise, timeoutMs, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${timeoutMs} ms.`)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function autoScroll(page) {
  const session = await page.createCDPSession();
  try {
    const metrics = await session.send("Page.getLayoutMetrics");
    return Math.ceil(metrics.cssContentSize?.height || metrics.contentSize?.height || 0);
  } finally {
    await session.detach().catch(() => undefined);
  }
}

async function serializeDom(page) {
  const session = await page.createCDPSession();
  try {
    const { root } = await session.send("DOM.getDocument", { depth: 1, pierce: true });
    const { outerHTML } = await session.send("DOM.getOuterHTML", { nodeId: root.nodeId });
    return `<!doctype html>\n${outerHTML}`;
  } finally {
    await session.detach().catch(() => undefined);
  }
}

async function prepareMedia(page) {
  await page.evaluate(async () => {
    document.querySelectorAll("img[loading='lazy'],iframe[loading='lazy']").forEach((element) => element.setAttribute("loading", "eager"));
    document.querySelectorAll("video").forEach((video) => {
      video.muted = true;
      video.setAttribute("muted", "");
      video.setAttribute("playsinline", "");
      video.preload = "auto";
      video.play().catch(() => undefined);
    });
    document.querySelectorAll("[aria-expanded='false']").forEach((element) => {
      if (element instanceof HTMLElement && element.matches("summary,[data-accordion-trigger]")) element.click();
    });
    await new Promise((resolve) => setTimeout(resolve, 500));
  });
}

async function captureSite(sourceUrl, baseUrl) {
  const captureId = randomUUID();
  const startedAt = Date.now();
  const stage = (name) => console.log(JSON.stringify({ captureId, stage: name, elapsedMs: Date.now() - startedAt }));
  stage("browser");
  const browser = await getBrowser();
  const page = await browser.newPage();
  await page.setRequestInterception(true);
  page.on("request", async (request) => {
    if (!request.isNavigationRequest() || request.resourceType() !== "document") return request.continue();
    try {
      await validateTarget(request.url());
      return request.continue();
    } catch {
      return request.abort("blockedbyclient");
    }
  });
  const runtimeErrors = [];
  const criticalFailures = [];
  let networkRequests = 0;
  page.on("pageerror", (error) => runtimeErrors.push(String(error.message || error)));
  page.on("request", () => { networkRequests += 1; });
  page.on("requestfailed", (request) => {
    const type = request.resourceType();
    try {
      const requestUrl = new URL(request.url());
      if (["document", "stylesheet", "script"].includes(type) && requestUrl.origin === sourceUrl.origin) criticalFailures.push(`${type}: ${requestUrl.pathname}`);
    } catch { /* Non-HTTP browser-internal request. */ }
  });
  try {
    stage("instrument");
    await page.evaluateOnNewDocument(rrwebScript);
    await page.evaluateOnNewDocument(() => {
      window.__originRrwebEvents = [];
      window.addEventListener("DOMContentLoaded", () => {
        if (window.rrweb?.record) {
          window.__originStopRrweb = window.rrweb.record({
            emit(event) {
              if (window.__originRrwebEvents.length < 1200) window.__originRrwebEvents.push(event);
            },
            recordCanvas: false,
            collectFonts: false,
            checkoutEveryNms: 5000,
          });
        }
      }, { once: true });
    });
    stage("navigate");
    const response = await page.goto(sourceUrl.toString(), { waitUntil: "domcontentloaded", timeout: 30_000 });
    if (!response || response.status() >= 400) throw new Error(`The browser navigation returned HTTP ${response?.status() || "unknown"}.`);
    await new Promise((resolve) => setTimeout(resolve, 1800));
    stage("media");
    await withTimeout(prepareMedia(page), 8000, "Media preparation").catch(() => undefined);
    stage("scroll");
    const scrollHeight = await withTimeout(autoScroll(page), 20_000, "Page scrolling");
    await new Promise((resolve) => setTimeout(resolve, 800));
    stage("serialize");
    const renderedHtml = await withTimeout(serializeDom(page), 12_000, "DOM serialization");
    let events = [];
    try {
      events = await withTimeout(page.evaluate(() => {
        if (typeof window.__originStopRrweb === "function") window.__originStopRrweb();
        return window.__originRrwebEvents || [];
      }), 8000, "Replay serialization");
    } catch (error) {
      runtimeErrors.push(error instanceof Error ? error.message : "Replay serialization failed.");
    }
    const metrics = await page.evaluate(() => ({
      elements: document.querySelectorAll("*").length,
      stylesheets: document.styleSheets.length,
      scripts: document.scripts.length,
      images: document.images.length,
      videos: document.querySelectorAll("video,source[type^='video']").length,
      canvases: document.querySelectorAll("canvas,svg").length,
      customElements: [...document.querySelectorAll("*")].filter((element) => element.localName.includes("-")).length,
      interactiveSignals: document.querySelectorAll("button,a,input,select,textarea,[role='button'],[aria-expanded],[data-animation],[class*='carousel'],[class*='slider']").length,
    }));
    stage("screenshot");
    const screenshot = await withTimeout(page.screenshot({ fullPage: false, type: "jpeg", quality: 68 }), 12_000, "Screenshot capture");
    const viewports = [1440, 1024, 768, 390];
    stage("responsive");
    for (const width of viewports.slice(1)) {
      await page.setViewport({ width, height: width === 390 ? 844 : 900 });
      await new Promise((resolve) => setTimeout(resolve, 280));
      const session = await page.createCDPSession();
      try {
        await withTimeout(session.send("Page.getLayoutMetrics"), 5000, `${width}px layout validation`);
      } finally {
        await session.detach().catch(() => undefined);
      }
    }
    artifacts.set(captureId, { createdAt: Date.now(), screenshot, events, sourceUrl: sourceUrl.toString() });
    const checks = {
      loaded: true,
      scrolled: scrollHeight > 0,
      replayable: events.length > 1,
      responsive: viewports.length === 4,
      domCaptured: renderedHtml.length > 100,
    };
    const verified = Object.values(checks).every(Boolean) && criticalFailures.length === 0 && runtimeErrors.length === 0;
    return {
      schemaVersion: "origin.capture/2",
      provider: "origin-puppeteer-rrweb",
      state: verified ? "verified" : "partial",
      sourceUrl: sourceUrl.toString(),
      replayUrl: `${baseUrl}/captures/${captureId}/replay`,
      screenshotUrl: `${baseUrl}/captures/${captureId}/screenshot.jpg`,
      capturedAt: new Date().toISOString(),
      renderedHtml,
      checks,
      evidence: {
        htmlBytes: Buffer.byteLength(renderedHtml),
        ...metrics,
        viewports: viewports.length,
        scrollHeight,
        networkRequests,
        criticalNetworkFailures: criticalFailures.length,
        runtimeErrors: runtimeErrors.length,
      },
      blockers: [...runtimeErrors.slice(0, 5), ...criticalFailures.slice(0, 10)],
    };
  } finally {
    stage("cleanup");
    await page.close().catch(() => undefined);
  }
}

function replayDocument(artifact) {
  const events = JSON.stringify(artifact.events).replace(/</g, "\\u003c");
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/rrweb-player@1.0.0-alpha.4/dist/style.css"><style>html,body,#replay{height:100%;margin:0;background:#fff}.rr-player{width:100%!important;height:100%!important}.rr-player__frame{width:100%!important;height:calc(100% - 80px)!important}</style></head><body><div id="replay"></div><script src="https://cdn.jsdelivr.net/npm/rrweb-player@1.0.0-alpha.4/dist/index.js"></script><script>new rrwebPlayer({target:document.getElementById('replay'),props:{events:${events},autoPlay:true,showController:true,width:1440,height:900}})</script></body></html>`;
}

setInterval(() => {
  const cutoff = Date.now() - ARTIFACT_TTL_MS;
  for (const [id, artifact] of artifacts) if (artifact.createdAt < cutoff) artifacts.delete(id);
}, 60_000).unref();

const server = http.createServer(async (request, response) => {
  try {
    if (request.method === "GET" && request.url === "/health") return json(response, 200, { ok: true, schemaVersion: "origin.capture/2" });
    const match = request.url?.match(/^\/captures\/([a-f0-9-]+)\/(replay|screenshot\.jpg)$/i);
    if (request.method === "GET" && match) {
      const artifact = artifacts.get(match[1]);
      if (!artifact) return json(response, 404, { error: "Capture expired or was not found." });
      if (match[2] === "screenshot.jpg") {
        response.writeHead(200, { "content-type": "image/jpeg", "cache-control": "private, max-age=1800" });
        return response.end(artifact.screenshot);
      }
      response.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'self' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src * data: blob:; media-src * data: blob:; font-src * data:", "cache-control": "private, max-age=1800" });
      return response.end(replayDocument(artifact));
    }
    if (request.method !== "POST" || request.url !== "/capture") return json(response, 404, { error: "Not found." });
    if (TOKEN && request.headers.authorization !== `Bearer ${TOKEN}`) return json(response, 401, { error: "Unauthorized." });
    const body = await readJson(request);
    if (body.schemaVersion !== "origin.capture/2" || typeof body.url !== "string") return json(response, 400, { error: "Invalid capture request." });
    const sourceUrl = await validateTarget(body.url);
    const forwardedProto = String(request.headers["x-forwarded-proto"] || "https").split(",")[0];
    const host = String(request.headers["x-forwarded-host"] || request.headers.host || "");
    const baseUrl = PUBLIC_BASE_URL || `${forwardedProto}://${host}`;
    const result = await Promise.race([
      captureSite(sourceUrl, baseUrl),
      new Promise((_, reject) => setTimeout(() => reject(new Error("Browser capture timed out.")), MAX_CAPTURE_MS)),
    ]);
    return json(response, 200, result);
  } catch (error) {
    return json(response, 422, { error: error instanceof Error ? error.message : "Capture failed." });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Origin capture worker listening on ${PORT}`);
  getBrowser().then(() => console.log("Origin capture browser ready")).catch((error) => console.error("Origin capture browser failed", error));
});
