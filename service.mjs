import http from "node:http";
import { randomUUID } from "node:crypto";
import { promises as dns } from "node:dns";
import puppeteer from "puppeteer-core";
import chromium from "@sparticuz/chromium";

const PORT = Number(process.env.PORT || 10000);
const TOKEN = process.env.ORIGIN_CAPTURE_TOKEN || "";
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/$/, "");
const SMOKE_URL = process.env.ORIGIN_CAPTURE_SMOKE_URL?.trim() || "";
const MAX_BODY_BYTES = 64_000;
const MAX_CAPTURE_MS = 120_000;
const ARTIFACT_TTL_MS = 30 * 60_000;
const artifacts = new Map();
const jobs = new Map();
const dnsCache = new Map();
const MAX_RETAINED_CAPTURES = 3;
const JOB_TTL_MS = 10 * 60_000;
let browserPromise;
let captureQueue = Promise.resolve();

async function launchBrowser(graphicsMode) {
  chromium.setGraphicsMode = graphicsMode;
  return puppeteer.launch({
    args: await puppeteer.defaultArgs({ args: chromium.args, headless: "shell" }),
    defaultViewport: { width: 1440, height: 1000 },
    executablePath: await chromium.executablePath(),
    headless: "shell",
    timeout: 90_000,
  });
}

function getBrowser() {
  if (!browserPromise) {
    browserPromise = launchBrowser(false).then((browser) => {
      browser.once("disconnected", () => { browserPromise = undefined; });
      return browser;
    }).catch((error) => {
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
  const cached = dnsCache.get(url.hostname);
  const records = cached?.expiresAt > Date.now()
    ? cached.records
    : await dns.lookup(url.hostname, { all: true, verbatim: true });
  if (!cached || cached.expiresAt <= Date.now()) {
    dnsCache.set(url.hostname, { records, expiresAt: Date.now() + 5 * 60_000 });
    if (dnsCache.size > 256) dnsCache.delete(dnsCache.keys().next().value);
  }
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

async function waitForNetworkQuiet(activeRequests, timeoutMs = 12_000) {
  const startedAt = Date.now();
  let quietSince = 0;
  while (Date.now() - startedAt < timeoutMs) {
    if (activeRequests() <= 2) {
      if (!quietSince) quietSince = Date.now();
      if (Date.now() - quietSince >= 1_000) return true;
    } else {
      quietSince = 0;
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  return false;
}

async function autoScroll(page) {
  const session = await page.createCDPSession();
  const layout = async () => {
    try {
      const metrics = await withTimeout(session.send("Page.getLayoutMetrics"), 2_000, "Layout metrics");
      const viewport = metrics.cssVisualViewport || metrics.visualViewport || {};
      const content = metrics.cssContentSize || metrics.contentSize || {};
      return {
        pageY: Math.max(0, Number(viewport.pageY) || 0),
        viewportHeight: Math.max(1, Number(viewport.clientHeight) || 1000),
        contentHeight: Math.max(1, Number(content.height) || 1000),
      };
    } catch {
      return null;
    }
  };
  const wheel = async (deltaY) => withTimeout(session.send("Input.dispatchMouseEvent", {
    type: "mouseWheel",
    x: 720,
    y: 720,
    deltaX: 0,
    deltaY,
  }), 2_000, "Browser wheel scroll").then(() => true).catch(() => false);

  try {
    const initial = await layout();
    let current = initial;
    let maxScrollY = current?.pageY || 0;
    let steps = 0;
    for (let index = 0; index < 12; index += 1) {
      const remaining = current ? Math.max(0, current.contentHeight - current.viewportHeight - current.pageY) : 1_100;
      if (current && remaining <= 8) break;
      if (!await wheel(Math.max(700, Math.min(1_250, remaining)))) break;
      steps += 1;
      await new Promise((resolve) => setTimeout(resolve, 320));
      current = await layout() || current;
      maxScrollY = Math.max(maxScrollY, current?.pageY || 0);
    }
    const final = await layout() || current;
    const bottomReached = Boolean(final && final.contentHeight - final.viewportHeight - final.pageY <= 16);
    for (let index = 0; index < Math.max(1, steps); index += 1) {
      if (!await wheel(-1_250)) break;
      await new Promise((resolve) => setTimeout(resolve, 180));
    }
    await withTimeout(session.send("Input.dispatchKeyEvent", {
      type: "keyDown", key: "Home", code: "Home", windowsVirtualKeyCode: 36, nativeVirtualKeyCode: 36,
    }), 1_500, "Top-boundary key down").catch(() => undefined);
    await withTimeout(session.send("Input.dispatchKeyEvent", {
      type: "keyUp", key: "Home", code: "Home", windowsVirtualKeyCode: 36, nativeVirtualKeyCode: 36,
    }), 1_500, "Top-boundary key up").catch(() => undefined);
    await new Promise((resolve) => setTimeout(resolve, 350));
    const returned = await layout();
    const returnedToTop = Boolean(returned && returned.pageY <= 8);
    return {
      initialHeight: initial?.contentHeight || 0,
      finalHeight: final?.contentHeight || 0,
      viewportHeight: final?.viewportHeight || initial?.viewportHeight || 1000,
      maxScrollY,
      steps,
      moved: maxScrollY > 8,
      bottomReached,
      returnedToTop,
    };
  } finally {
    await session.detach().catch(() => undefined);
  }
}

async function startVisualRecorder(page) {
  const session = await page.createCDPSession();
  const frames = [];
  let firstFrameAt = 0;
  let lastFrameAt = 0;
  let lastAcceptedAt = 0;
  const onFrame = (event) => {
    session.send("Page.screencastFrameAck", { sessionId: event.sessionId }).catch(() => undefined);
    const now = Date.now();
    if (frames.length >= 18 || now - lastAcceptedAt < 650) return;
    const frame = Buffer.from(event.data || "", "base64");
    if (frame.length < 1_000) return;
    frames.push(frame);
    firstFrameAt ||= now;
    lastFrameAt = now;
    lastAcceptedAt = now;
  };
  session.on("Page.screencastFrame", onFrame);
  await withTimeout(session.send("Page.startScreencast", {
    format: "jpeg",
    quality: 48,
    maxWidth: 1440,
    maxHeight: 1000,
    everyNthFrame: 1,
  }), 3_000, "Visual recorder start");
  return {
    frames,
    async stop() {
      await new Promise((resolve) => setTimeout(resolve, 500));
      await withTimeout(session.send("Page.stopScreencast"), 2_000, "Visual recorder stop").catch(() => undefined);
      session.off("Page.screencastFrame", onFrame);
      await withTimeout(session.detach(), 1_000, "Visual recorder cleanup").catch(() => undefined);
      return { durationMs: firstFrameAt && lastFrameAt ? Math.max(0, lastFrameAt - firstFrameAt) : 0 };
    },
  };
}

async function captureVisualPass(sourceUrl) {
  const browser = await launchBrowser(true);
  const page = await browser.newPage();
  let recorder;
  try {
    await page.setRequestInterception(true);
    page.on("request", async (request) => {
      try {
        const target = new URL(request.url());
        if (target.protocol === "http:" || target.protocol === "https:") await validateTarget(target.toString());
        else if (!["data:", "blob:", "about:"].includes(target.protocol)) throw new Error("Blocked non-web request.");
        return request.continue();
      } catch {
        return request.abort("blockedbyclient");
      }
    });
    recorder = await startVisualRecorder(page);
    const response = await page.goto(sourceUrl.toString(), { waitUntil: "domcontentloaded", timeout: 30_000 });
    if (!response || response.status() >= 400) throw new Error(`The visual browser navigation returned HTTP ${response?.status() || "unknown"}.`);
    await new Promise((resolve) => setTimeout(resolve, 5_000));
    const result = await recorder.stop();
    const frames = recorder.frames.slice(-12);
    recorder = null;
    return { frames, durationMs: result.durationMs };
  } finally {
    if (recorder) await recorder.stop().catch(() => undefined);
    await page.close().catch(() => undefined);
    await withTimeout(browser.close(), 6_000, "Visual browser recycle").catch(() => undefined);
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

async function captureViewportScreenshot(page, timeoutMs, label, quality = 68) {
  const session = await page.createCDPSession();
  try {
    const result = await withTimeout(session.send("Page.captureScreenshot", {
      format: "jpeg",
      quality,
      fromSurface: true,
      captureBeyondViewport: false,
    }), timeoutMs, label);
    return Buffer.from(result.data, "base64");
  } finally {
    await withTimeout(session.detach(), 1_000, `${label} session cleanup`).catch(() => undefined);
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

function countMatches(value, expression) {
  return value.match(expression)?.length || 0;
}

function summarizeMarkup(renderedHtml) {
  return {
    elements: countMatches(renderedHtml, /<(?!\/|!|\?)[a-z][^>]*>/gi),
    stylesheets: countMatches(renderedHtml, /<style\b|<link\b[^>]*\brel=["']?stylesheet/gi),
    scripts: countMatches(renderedHtml, /<script\b/gi),
    images: countMatches(renderedHtml, /<img\b/gi),
    videos: countMatches(renderedHtml, /<(?:video|source)\b[^>]*(?:type=["']video|<video\b)/gi),
    canvases: countMatches(renderedHtml, /<(?:canvas|svg)\b/gi),
    customElements: countMatches(renderedHtml, /<[a-z][a-z0-9]*-[a-z0-9-]+\b/gi),
    interactiveSignals: countMatches(renderedHtml, /<(?:button|a|input|select|textarea)\b|\brole=["']button|\baria-expanded=|\bdata-animation=|\bclass=["'][^"']*(?:carousel|slider)/gi),
  };
}

function normalizeRuntimeUrl(value) {
  try {
    const url = new URL(value);
    url.hash = "";
    return url.toString();
  } catch {
    return value;
  }
}

function isOptionalRuntimeScriptPath(pathname) {
  return /(?:\/cdn-cgi\/|\/analytics?\/|\/beacon\/|\/[a-f0-9]{12,}\/script\.js$)/i.test(pathname);
}

function absolutizeCssUrls(source, sourceUrl) {
  return source.replace(/url\s*\(\s*(["']?)([^"')]+)\1\s*\)/gi, (match, quote, rawUrl) => {
    const value = rawUrl.trim();
    if (!value || /^(?:data:|blob:|#)/i.test(value)) return match;
    try {
      return `url("${new URL(value, sourceUrl).toString().replaceAll('"', "%22")}")`;
    } catch {
      return match;
    }
  });
}

async function captureLoadedCss(session, stylesheetHeaders, stylesheetBodies) {
  const headers = [...stylesheetHeaders.values()].filter((header) => header.sourceURL).slice(0, 48);
  const results = await Promise.all(headers.map(async (header) => {
    try {
      const result = await withTimeout(
        session.send("CSS.getStyleSheetText", { styleSheetId: header.styleSheetId }),
        2_500,
        "Stylesheet capture",
      );
      return { sourceUrl: header.sourceURL, text: result.text || "" };
    } catch {
      return null;
    }
  }));
  const stylesheetTexts = new Map(stylesheetBodies);
  for (const result of results) {
    if (result?.text && !stylesheetTexts.has(result.sourceUrl)) stylesheetTexts.set(result.sourceUrl, result.text);
  }
  let capturedCss = "";
  let stylesheetsCaptured = 0;
  for (const [sourceUrl, stylesheetText] of stylesheetTexts) {
    if (!stylesheetText) continue;
    const remaining = 1_500_000 - capturedCss.length;
    if (remaining <= 0) break;
    capturedCss += `${absolutizeCssUrls(stylesheetText, sourceUrl).slice(0, remaining)}\n`;
    stylesheetsCaptured += 1;
  }
  return { capturedCss, stylesheetsCaptured };
}

async function captureSite(sourceUrl, baseUrl) {
  const captureId = randomUUID();
  const startedAt = Date.now();
  const stage = (name) => console.log(JSON.stringify({ captureId, stage: name, elapsedMs: Date.now() - startedAt }));
  stage("visual-browser");
  const visualPass = await withTimeout(captureVisualPass(sourceUrl), 48_000, "Visual browser pass").catch((error) => ({
    frames: [],
    durationMs: 0,
    error: error instanceof Error ? error.message : "Visual browser pass failed.",
  }));
  console.log(JSON.stringify({
    captureId,
    stage: "visual-browser-complete",
    elapsedMs: Date.now() - startedAt,
    frames: visualPass.frames.length,
    durationMs: visualPass.durationMs,
    error: visualPass.error,
  }));
  stage("browser");
  const browser = await getBrowser();
  const page = await browser.newPage();
  const telemetrySession = await page.createCDPSession();
  const runtimeErrors = [];
  const criticalFailures = [];
  const scriptRequests = new Set();
  const executedScripts = new Set();
  const animations = new Map();
  const stylesheetHeaders = new Map();
  const stylesheetBodies = new Map();
  const stylesheetCaptures = new Set();
  let networkRequests = 0;
  let activeRequestCount = 0;
  const visualFrames = visualPass.frames;
  const visualReplay = { durationMs: visualPass.durationMs };
  if (visualPass.error) runtimeErrors.push(visualPass.error);

  telemetrySession.on("Debugger.scriptParsed", (event) => {
    if (event.url && executedScripts.size < 600) executedScripts.add(normalizeRuntimeUrl(event.url));
  });
  telemetrySession.on("Animation.animationStarted", ({ animation }) => {
    if (!animation?.id || animations.size >= 300) return;
    animations.set(animation.id, {
      name: animation.name || "",
      type: animation.type || "",
      playState: animation.playState || "",
      duration: animation.source?.duration || 0,
      delay: animation.source?.delay || 0,
      iterations: animation.source?.iterations || 0,
      direction: animation.source?.direction || "",
      easing: animation.source?.easing || "",
    });
  });
  telemetrySession.on("CSS.styleSheetAdded", ({ header }) => {
    if (header?.styleSheetId && stylesheetHeaders.size < 80) stylesheetHeaders.set(header.styleSheetId, header);
  });
  await withTimeout(telemetrySession.send("Debugger.enable"), 3000, "Script telemetry").catch((error) => {
    runtimeErrors.push(error instanceof Error ? error.message : "Script telemetry failed.");
  });
  await withTimeout(telemetrySession.send("Animation.enable"), 3000, "Animation telemetry").catch((error) => {
    runtimeErrors.push(error instanceof Error ? error.message : "Animation telemetry failed.");
  });
  await withTimeout(telemetrySession.send("DOM.enable"), 3000, "DOM telemetry").catch(() => undefined);
  await withTimeout(telemetrySession.send("CSS.enable"), 3000, "Stylesheet telemetry").catch(() => undefined);

  await page.setRequestInterception(true);
  page.on("request", async (request) => {
    networkRequests += 1;
    activeRequestCount += 1;
    if (request.resourceType() === "script" && scriptRequests.size < 600) scriptRequests.add(normalizeRuntimeUrl(request.url()));
    try {
      const target = new URL(request.url());
      if (target.protocol === "http:" || target.protocol === "https:") await validateTarget(target.toString());
      else if (!["data:", "blob:", "about:"].includes(target.protocol)) throw new Error("Blocked non-web request.");
      return request.continue();
    } catch {
      return request.abort("blockedbyclient");
    }
  });
  page.on("pageerror", (error) => {
    const message = String(error.message || error);
    if (!/webgl|gpu process|graphics context|error creating .*context/i.test(message)) runtimeErrors.push(message);
  });
  page.on("requestfinished", () => { activeRequestCount = Math.max(0, activeRequestCount - 1); });
  page.on("response", (response) => {
    if (response.request().resourceType() !== "stylesheet" || stylesheetBodies.size + stylesheetCaptures.size >= 48) return;
    const sourceUrl = response.url();
    const capture = withTimeout(response.text(), 4_000, "Stylesheet response capture")
      .then((text) => {
        if (text && !stylesheetBodies.has(sourceUrl)) stylesheetBodies.set(sourceUrl, text);
      })
      .catch(() => undefined)
      .finally(() => stylesheetCaptures.delete(capture));
    stylesheetCaptures.add(capture);
  });
  page.on("requestfailed", (request) => {
    activeRequestCount = Math.max(0, activeRequestCount - 1);
    const type = request.resourceType();
    try {
      const requestUrl = new URL(request.url());
      if (["document", "stylesheet", "script"].includes(type)
        && requestUrl.origin === sourceUrl.origin
        && !(type === "script" && isOptionalRuntimeScriptPath(requestUrl.pathname))) {
        criticalFailures.push(`${type}: ${requestUrl.pathname}`);
      }
    } catch { /* Non-HTTP browser-internal request. */ }
  });
  try {
    stage("instrument");
    stage("navigate");
    const response = await page.goto(sourceUrl.toString(), { waitUntil: "domcontentloaded", timeout: 30_000 });
    if (!response || response.status() >= 400) throw new Error(`The browser navigation returned HTTP ${response?.status() || "unknown"}.`);
    await new Promise((resolve) => setTimeout(resolve, 1800));
    stage("network-settle");
    await waitForNetworkQuiet(() => activeRequestCount, 12_000);
    stage("media");
    await withTimeout(prepareMedia(page), 8000, "Media preparation").catch(() => undefined);
    stage("styles");
    await withTimeout(Promise.allSettled([...stylesheetCaptures]), 6_000, "Stylesheet response drain").catch(() => undefined);
    const { capturedCss, stylesheetsCaptured } = await captureLoadedCss(telemetrySession, stylesheetHeaders, stylesheetBodies);
    console.log(JSON.stringify({
      captureId,
      stage: "styles-complete",
      elapsedMs: Date.now() - startedAt,
      headers: stylesheetHeaders.size,
      responses: stylesheetBodies.size,
      stylesheetsCaptured,
      cssBytes: Buffer.byteLength(capturedCss),
    }));
    stage("scroll");
    const scroll = await withTimeout(autoScroll(page), 18_000, "Page scrolling");
    await new Promise((resolve) => setTimeout(resolve, 600));
    const replayReady = visualFrames.length >= 3 && visualReplay.durationMs >= 500;
    console.log(JSON.stringify({
      captureId,
      stage: "visual-recording-complete",
      elapsedMs: Date.now() - startedAt,
      frames: visualFrames.length,
      durationMs: visualReplay.durationMs,
      scroll,
    }));
    stage("serialize");
    const renderedHtml = await withTimeout(serializeDom(page), 12_000, "DOM serialization");
    const metrics = summarizeMarkup(renderedHtml);
    const discoveredScriptUrls = [...scriptRequests];
    const executedScriptUrls = new Set(executedScripts);
    const unexecutedScriptUrls = discoveredScriptUrls.filter((url) => !executedScriptUrls.has(url));
    const requiredUnexecutedScriptUrls = unexecutedScriptUrls.filter((url) => {
      try {
        const parsed = new URL(url);
        return parsed.origin === sourceUrl.origin && !isOptionalRuntimeScriptPath(parsed.pathname);
      } catch {
        return false;
      }
    });
    stage("screenshot");
    const finalScreenshot = await captureViewportScreenshot(page, 8_000, "Final screenshot capture")
      .catch((error) => {
        console.warn(JSON.stringify({
          captureId,
          stage: "screenshot-final-skipped",
          elapsedMs: Date.now() - startedAt,
          error: error instanceof Error ? error.message : "Final screenshot capture failed.",
        }));
        return null;
      });
    const screenshot = visualFrames.at(-1) || finalScreenshot || null;
    const screenshotFallbackUsed = Boolean(visualFrames.length || (!finalScreenshot && screenshot));
    const viewports = [1440, 1024, 768, 390];
    let responsiveViewports = 1;
    stage("responsive");
    for (const width of viewports.slice(1)) {
      try {
        await withTimeout(page.setViewport({ width, height: width === 390 ? 844 : 900 }), 5000, `${width}px viewport setup`);
        await new Promise((resolve) => setTimeout(resolve, 280));
        const frame = await captureViewportScreenshot(page, 5_000, `${width}px viewport validation`, 24);
        if (frame.length > 1_000) responsiveViewports += 1;
      } catch (error) {
        runtimeErrors.push(error instanceof Error ? error.message : `${width}px layout validation failed.`);
      }
    }
    artifacts.set(captureId, { captureId, createdAt: Date.now(), screenshot, visualFrames, replayReady, renderedHtml, sourceUrl: sourceUrl.toString() });
    while (artifacts.size > MAX_RETAINED_CAPTURES) artifacts.delete(artifacts.keys().next().value);
    const checks = {
      loaded: true,
      scrolled: scroll.bottomReached,
      returnedToTop: scroll.returnedToTop,
      replayable: replayReady,
      responsive: responsiveViewports === viewports.length,
      domCaptured: renderedHtml.length > 100,
      screenshotCaptured: Boolean(screenshot),
      runtimeScriptsExecuted: requiredUnexecutedScriptUrls.length === 0 && !criticalFailures.some((failure) => failure.startsWith("script:")),
    };
    const verified = Object.values(checks).every(Boolean) && criticalFailures.length === 0 && runtimeErrors.length === 0;
    return {
      schemaVersion: "origin.capture/2",
      provider: "origin-cdp-visual-dom",
      captureId,
      state: verified ? "verified" : "partial",
      sourceUrl: sourceUrl.toString(),
      replayUrl: `${baseUrl}/captures/${captureId}/replay`,
      screenshotUrl: screenshot ? `${baseUrl}/captures/${captureId}/screenshot.jpg` : undefined,
      capturedAt: new Date().toISOString(),
      renderedHtml,
      capturedCss,
      checks,
      motion: [...animations.values()].slice(0, 120),
      evidence: {
        htmlBytes: Buffer.byteLength(renderedHtml),
        ...metrics,
        viewports: responsiveViewports,
        scrollHeight: scroll.finalHeight,
        initialScrollHeight: scroll.initialHeight,
        scrollSteps: scroll.steps,
        maxScrollY: scroll.maxScrollY,
        bottomReached: scroll.bottomReached,
        returnedToTop: scroll.returnedToTop,
        networkRequests,
        runtimeScriptsDiscovered: discoveredScriptUrls.length,
        runtimeScriptsExecuted: discoveredScriptUrls.length - unexecutedScriptUrls.length,
        runtimeScriptsUnexecuted: unexecutedScriptUrls.length,
        animationsStarted: animations.size,
        replayEvents: visualFrames.length,
        replayDurationMs: visualReplay.durationMs,
        replayMutations: 0,
        visualFrames: visualFrames.length,
        visualReplayDurationMs: visualReplay.durationMs,
        stylesheetsCaptured,
        cssBytes: Buffer.byteLength(capturedCss),
        screenshotFallbackUsed,
        criticalNetworkFailures: criticalFailures.length,
        runtimeErrors: runtimeErrors.length,
      },
      blockers: [
        ...runtimeErrors.slice(0, 5),
        ...(!screenshot ? ["Viewport screenshot could not be captured."] : []),
        ...criticalFailures.slice(0, 10),
        ...requiredUnexecutedScriptUrls.slice(0, 10).map((url) => `required script not executed: ${url}`),
      ],
    };
  } finally {
    stage("cleanup");
    await telemetrySession.detach().catch(() => undefined);
    await page.close().catch(() => undefined);
    browserPromise = undefined;
    await withTimeout(browser.close(), 6_000, "Browser recycle").catch(() => undefined);
    console.log(JSON.stringify({ captureId, stage: "browser-recycled", elapsedMs: Date.now() - startedAt }));
  }
}

function replayDocument(artifact) {
  if (artifact.replayReady && artifact.visualFrames?.length) {
    const frameUrls = artifact.visualFrames.map((_, index) => `/captures/${artifact.captureId}/frames/${index}.jpg`);
    const frames = JSON.stringify(frameUrls).replace(/</g, "\\u003c");
    return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>html,body{height:100%;margin:0;background:#111;overflow:hidden}body{display:grid;place-items:center}img{display:block;width:100%;height:100%;object-fit:contain;background:#111}.badge{position:fixed;z-index:2;right:12px;bottom:12px;padding:6px 9px;border-radius:999px;background:#111c;color:#fff;font:600 11px/1 system-ui,sans-serif;letter-spacing:.05em}</style></head><body><img id="frame" alt="Recorded browser rendering"><span class="badge">RECORDED BROWSER MOTION</span><script>(()=>{const frames=${frames};const image=document.getElementById('frame');let index=0;const show=()=>{image.src=frames[index];index=(index+1)%frames.length};show();setInterval(show,320)})()</script></body></html>`;
  }
  if (!artifact.replayReady) {
    const base = `<base href="${artifact.sourceUrl.replaceAll("&", "&amp;").replaceAll('"', "&quot;")}">`;
    return artifact.renderedHtml.replace(/<head([^>]*)>/i, `<head$1>${base}`);
  }
  return artifact.renderedHtml;
}

function requestBaseUrl(request) {
  const forwardedProto = String(request.headers["x-forwarded-proto"] || "https").split(",")[0];
  const host = String(request.headers["x-forwarded-host"] || request.headers.host || "");
  return PUBLIC_BASE_URL || `${forwardedProto}://${host}`;
}

function enqueueCapture(sourceUrl, baseUrl) {
  const jobId = randomUUID();
  jobs.set(jobId, { createdAt: Date.now(), state: "pending" });
  captureQueue = captureQueue.catch(() => undefined).then(async () => {
    const job = jobs.get(jobId);
    if (!job) return;
    jobs.set(jobId, { ...job, state: "running", startedAt: Date.now() });
    try {
      const artifact = await withTimeout(captureSite(sourceUrl, baseUrl), MAX_CAPTURE_MS, "Browser capture");
      jobs.set(jobId, { ...jobs.get(jobId), state: "complete", completedAt: Date.now(), artifact });
      console.log(JSON.stringify({
        jobId,
        stage: "job-complete",
        sourceUrl: sourceUrl.toString(),
        state: artifact.state,
        checks: artifact.checks,
        evidence: artifact.evidence,
        blockers: artifact.blockers,
      }));
    } catch (error) {
      const message = error instanceof Error ? error.message : "Capture failed.";
      jobs.set(jobId, {
        ...jobs.get(jobId),
        state: "failed",
        completedAt: Date.now(),
        error: message,
      });
      console.error(JSON.stringify({ jobId, stage: "job-failed", sourceUrl: sourceUrl.toString(), error: message }));
    }
  });
  return jobId;
}

async function runSmokeCapture(rawUrl) {
  const baseUrl = `http://127.0.0.1:${PORT}`;
  const headers = {
    "content-type": "application/json",
    ...(TOKEN ? { authorization: `Bearer ${TOKEN}` } : {}),
  };
  const startResponse = await fetch(`${baseUrl}/capture/jobs`, {
    method: "POST",
    headers,
    body: JSON.stringify({ schemaVersion: "origin.capture/2", url: rawUrl }),
  });
  const started = await startResponse.json();
  if (startResponse.status !== 202 || typeof started.jobId !== "string") {
    throw new Error(started.error || `Smoke capture start returned HTTP ${startResponse.status}.`);
  }
  console.log(JSON.stringify({ jobId: started.jobId, stage: "smoke-start", sourceUrl: rawUrl }));
  const deadline = Date.now() + MAX_CAPTURE_MS + 15_000;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 1_500));
    const pollResponse = await fetch(`${baseUrl}/capture/jobs/${encodeURIComponent(started.jobId)}`, { headers });
    const job = await pollResponse.json();
    if (pollResponse.status === 202) continue;
    if (!pollResponse.ok || job.state !== "complete") throw new Error(job.error || `Smoke capture returned HTTP ${pollResponse.status}.`);
    if (!job.artifact?.checks?.domCaptured || typeof job.artifact.renderedHtml !== "string") {
      throw new Error("Smoke capture completed without a rendered DOM artifact.");
    }
    if (!job.artifact?.checks?.screenshotCaptured || typeof job.artifact.screenshotUrl !== "string") {
      throw new Error("Smoke capture completed without a screenshot artifact.");
    }
    const screenshotBytes = artifacts.get(job.artifact.captureId)?.screenshot?.length || 0;
    if (screenshotBytes < 1_000) throw new Error(`Smoke screenshot verification produced only ${screenshotBytes} bytes.`);
    console.log(JSON.stringify({
      jobId: started.jobId,
      stage: "smoke-complete",
      sourceUrl: rawUrl,
      state: job.artifact?.state,
      checks: job.artifact?.checks,
      evidence: job.artifact?.evidence,
      renderedHtmlBytes: Buffer.byteLength(job.artifact.renderedHtml),
      screenshotBytes,
      blockers: job.artifact?.blockers,
    }));
    return;
  }
  throw new Error("Smoke capture timed out.");
}

setInterval(() => {
  const artifactCutoff = Date.now() - ARTIFACT_TTL_MS;
  const jobCutoff = Date.now() - JOB_TTL_MS;
  for (const [id, artifact] of artifacts) if (artifact.createdAt < artifactCutoff) artifacts.delete(id);
  for (const [id, job] of jobs) if (job.createdAt < jobCutoff) jobs.delete(id);
  while (jobs.size > 12) jobs.delete(jobs.keys().next().value);
}, 60_000).unref();

const server = http.createServer(async (request, response) => {
  try {
    if (request.method === "GET" && request.url === "/health") return json(response, 200, { ok: true, schemaVersion: "origin.capture/2" });
    const match = request.url?.match(/^\/captures\/([a-f0-9-]+)\/(replay|screenshot\.jpg)$/i);
    const frameMatch = request.url?.match(/^\/captures\/([a-f0-9-]+)\/frames\/(\d+)\.jpg$/i);
    if (request.method === "GET" && frameMatch) {
      const artifact = artifacts.get(frameMatch[1]);
      const frame = artifact?.visualFrames?.[Number(frameMatch[2])];
      if (!frame) return json(response, 404, { error: "Capture frame expired or was not found." });
      response.writeHead(200, { "content-type": "image/jpeg", "cache-control": "private, max-age=1800" });
      return response.end(frame);
    }
    if (request.method === "GET" && match) {
      const artifact = artifacts.get(match[1]);
      if (!artifact) return json(response, 404, { error: "Capture expired or was not found." });
      if (match[2] === "screenshot.jpg") {
        if (!artifact.screenshot) return json(response, 404, { error: "A screenshot was not produced for this capture." });
        response.writeHead(200, { "content-type": "image/jpeg", "cache-control": "private, max-age=1800" });
        return response.end(artifact.screenshot);
      }
      const contentSecurityPolicy = artifact.replayReady
        ? "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:"
        : "default-src 'none'; script-src 'none'; style-src 'unsafe-inline' https:; img-src data: blob: https:; media-src data: blob: https:; font-src data: https:; frame-src https:; form-action 'none'; base-uri https:";
      response.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": contentSecurityPolicy, "cache-control": "private, max-age=1800" });
      return response.end(replayDocument(artifact));
    }
    const jobMatch = request.url?.match(/^\/capture\/jobs\/([a-f0-9-]+)$/i);
    const isCaptureRequest = request.method === "POST" && request.url === "/capture";
    const isJobStart = request.method === "POST" && request.url === "/capture/jobs";
    const isJobPoll = request.method === "GET" && Boolean(jobMatch);
    if (!isCaptureRequest && !isJobStart && !isJobPoll) return json(response, 404, { error: "Not found." });
    if (TOKEN && request.headers.authorization !== `Bearer ${TOKEN}`) return json(response, 401, { error: "Unauthorized." });
    if (isJobPoll && jobMatch) {
      const job = jobs.get(jobMatch[1]);
      if (!job) return json(response, 404, { schemaVersion: "origin.capture-job/1", state: "failed", error: "Capture job expired or was not found." });
      if (job.state === "complete") return json(response, 200, { schemaVersion: "origin.capture-job/1", jobId: jobMatch[1], state: "complete", artifact: job.artifact });
      if (job.state === "failed") return json(response, 422, { schemaVersion: "origin.capture-job/1", jobId: jobMatch[1], state: "failed", error: job.error });
      return json(response, 202, { schemaVersion: "origin.capture-job/1", jobId: jobMatch[1], state: job.state, pollAfterMs: 1500 });
    }
    const body = await readJson(request);
    if (body.schemaVersion !== "origin.capture/2" || typeof body.url !== "string") return json(response, 400, { error: "Invalid capture request." });
    const sourceUrl = await validateTarget(body.url);
    const baseUrl = requestBaseUrl(request);
    if (isJobStart) {
      const jobId = enqueueCapture(sourceUrl, baseUrl);
      return json(response, 202, { schemaVersion: "origin.capture-job/1", jobId, state: "pending", pollAfterMs: 1500 });
    }
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
  getBrowser().then(() => {
    console.log("Origin capture browser ready");
    if (SMOKE_URL) runSmokeCapture(SMOKE_URL).catch((error) => {
      console.error(JSON.stringify({ stage: "smoke-failed", sourceUrl: SMOKE_URL, error: error instanceof Error ? error.message : "Smoke capture failed." }));
    });
  }).catch((error) => console.error("Origin capture browser failed", error));
});
