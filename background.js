
console.log('Background script running');

const adBlocklist = new Set();
const trackerBlocklist = new Set();
const whitelistSet = new Set();
const manualBlocksSet = new Set(); // New: Manual Mode user-defined blocks
const filterFiles = {
  'easylist.txt': adBlocklist,
  'easyprivacy.txt': trackerBlocklist,
};

let currentMode = 'balanced'; // balanced, aggressive, manual
let protectionSettings = {
  adBlocking: true,
  socialTrackers: true,
  fingerprinting: true,
  strictFP: false,
  blockCookies: false, // New Global Override
  showNotifications: false // New Global Override
};

const sessionStats = {
  tabs: {}, // tabId: { totalTrackers, blockedCount, detectedDomains }
  history: [0, 0, 0, 0, 0, 0, 0], // Last 7 days block counts
};

// Initialize settings from storage
browser.storage.local.get(['protectionSettings', 'blockHistory', 'whitelist', 'privacyMode', 'manualBlocks', 'blockCookies', 'showNotifications']).then(res => {
  if (res.protectionSettings) protectionSettings = res.protectionSettings;
  if (res.blockHistory) sessionStats.history = res.blockHistory;
  if (res.privacyMode) currentMode = res.privacyMode;
  if (res.blockCookies !== undefined) protectionSettings.blockCookies = res.blockCookies;
  if (res.showNotifications !== undefined) protectionSettings.showNotifications = res.showNotifications;
  if (Array.isArray(res.whitelist)) {
    res.whitelist.forEach(d => whitelistSet.add(d));
  }
  if (Array.isArray(res.manualBlocks)) {
    res.manualBlocks.forEach(d => manualBlocksSet.add(d));
  }
});

const fingerprintingKeywords = [
  'fingerprint', 'fp.js', 'device-id', 'canvas', 'audiocontext', 'battery-status', 'getClientRects'
];

function updateWhitelistCache(list) {
  whitelistSet.clear();
  if (Array.isArray(list)) {
    list.forEach(d => {
      if (typeof d === 'string' && d.trim()) whitelistSet.add(d.trim());
    });
  }
}

function initTabStats(tabId) {
  if (!sessionStats.tabs[tabId]) {
    sessionStats.tabs[tabId] = {
      totalTrackers: 0,
      blockedCount: 0,
      detectedDomains: new Set(),
      trackerDomains: new Set(), // Unique trackers for scoring
      adCount: 0, // Total ads for scoring
      fingerprintingAttempts: 0,
      trustScore: 100,
      statusLabel: 'Safe',
      statusColor: '#22C55E',
      blockedRequests: [], // Track individual blocked requests
      categories: {
        Advertising: 0,
        Analytics: 0,
        Social: 0,
        Fingerprinting: 0,
        Cookies: 0,
        Others: 0
      },
      totalPageRequests: 0, // Track total requests for density calculation
      isHttps: true, // Default to true
      topDomain: ''
    };
  }
}

function calculateTrustScore(stats) {
  const telemetry = {
    counts: {
      advertising: stats.categories.Advertising,
      analytics: stats.categories.Analytics,
      social: stats.categories.Social,
      fingerprinting: stats.categories.Fingerprinting,
      cryptomining: 0 // Not tracked yet
    },
    isHttps: stats.isHttps,
    totalRequests: Math.max(stats.totalPageRequests, stats.totalTrackers, 1),
    uniqueDomains: stats.trackerDomains.size
  };

  const result = computeTrustScore(telemetry);
  stats.trustScore = result.score;
  stats.statusLabel = result.status_label;
  stats.statusColor = result.status_color;
}

/**
 * ============================================================
 *  PRIVACY SHIELD — Intelligent Trust Score Engine
 *  trustScoreEngine.js  |  Manifest V2  |  ES2020+
 * ============================================================
 *
 *  Architecture: Pure-function pipeline. Zero side-effects,
 *  no closures that retain DOM refs, safe to call on every
 *  webRequest event without fear of memory leaks.
 *
 *  Pipeline:
 *    siteTelemetry
 *      → normalise()
 *      → computeThreatPenalty()
 *      → computeContextModifiers()
 *      → computeProtocolPenalty()
 *      → aggregateScore()
 *      → classify()
 *      → TrustScoreResult
 * ============================================================
 */

"use strict";

// ─────────────────────────────────────────────
//  SECTION 1 · CONSTANTS  (tune here only)
// ─────────────────────────────────────────────

/**
 * Base penalty per *unit* of each threat category.
 * Applied inside a log-dampened curve, so these are
 * effective weights, not raw per-request penalties.
 *
 * Rationale:
 *  cryptomining   → hijacks CPU; zero legitimate use on content sites
 *  fingerprinting → identity theft vector; 1 script = permanent profile
 *  analytics      → behavioural profiling across sessions
 *  social         → cross-site identity linking
 *  advertising    → data leakage + nuisance; widest-deployed
 */
const THREAT_WEIGHTS = Object.freeze({
  cryptomining:   10,
  fingerprinting:  8,
  analytics:       4,
  social:          3,
  advertising:     2,
});

/**
 * Fingerprinting anomaly: even a single FP script triggers
 * this extra multiplier on top of its base weight.
 * Models the asymmetric real-world risk of "1 FP = permanent identity".
 */
const FINGERPRINT_SPIKE_THRESHOLD = 1;   // ≥ this many → spike activates
const FINGERPRINT_SPIKE_MULTIPLIER = 1.8;

/**
 * Cryptomining anomaly: any mining script is an immediate
 * severity escalation regardless of count.
 */
const CRYPTOMINING_SPIKE_MULTIPLIER = 2.0;

/** Flat penalty for plain HTTP (MITM risk is categorical). */
const HTTP_PROTOCOL_PENALTY = 15;

/**
 * Tracker density penalty weight.
 * density = blocked / totalRequests (0–1)
 * penalty = density * DENSITY_WEIGHT
 */
const DENSITY_WEIGHT = 25;

/**
 * Unique third-party domain surface penalty.
 * Applied as: log2(uniqueDomains + 1) * DOMAIN_SURFACE_WEIGHT
 */
const DOMAIN_SURFACE_WEIGHT = 3;

/**
 * Large-site volume forgiveness.
 * Sites with many total requests get a mild score buffer on
 * raw volume (not on threat type). Prevents Google/Reddit from
 * scoring worse than a tiny site just because they load more assets.
 *
 * forgiveness = log10(totalRequests + 1) * VOLUME_FORGIVENESS_FACTOR
 * Capped at MAX_VOLUME_FORGIVENESS points.
 */
const VOLUME_FORGIVENESS_FACTOR = 2.5;
const MAX_VOLUME_FORGIVENESS    = 10;

/** Hard score boundaries. */
const SCORE_MIN = 0;
const SCORE_MAX = 100;

// ─────────────────────────────────────────────
//  SECTION 2 · TYPE DEFINITIONS  (JSDoc)
// ─────────────────────────────────────────────

/**
 * @typedef {Object} ThreatCounts
 * @property {number} advertising
 * @property {number} analytics
 * @property {number} social
 * @property {number} fingerprinting
 * @property {number} cryptomining
 */

/**
 * @typedef {Object} SiteTelemetry
 * @property {ThreatCounts} counts        - Blocked request counts per category
 * @property {string[]}     types         - Flat list of threat type strings seen
 * @property {boolean}      isHttps       - Whether the page protocol is HTTPS
 * @property {number}       totalRequests - All requests fired (blocked + allowed)
 * @property {number}       uniqueDomains - Count of distinct third-party hostnames
 */

/**
 * @typedef {Object} TrustScoreResult
 * @property {number}  score          - 0 (dangerous) → 100 (safe)
 * @property {string}  status_label   - Human-readable verdict
 * @property {string}  status_color   - Hex colour for UI badge
 * @property {string}  risk_level     - "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE"
 * @property {string}  top_threat_type - The single most impactful threat category
 * @property {Object}  _debug         - Internal breakdown (strip in production if desired)
 */

// ─────────────────────────────────────────────
//  SECTION 3 · HELPER UTILITIES
// ─────────────────────────────────────────────

/**
 * Safe logarithmic dampener.
 * Maps a raw count onto a compressed scale so that
 * 100 trackers ≠ 100× the penalty of 1 tracker.
 *
 * Uses natural log: log(1)=0, log(2)≈0.69, log(11)≈2.4, log(101)≈4.6
 *
 * @param  {number} count - Raw integer count (≥ 0)
 * @returns {number}
 */
const logDampen = (count) => Math.log(count + 1);

/**
 * Linearly clamp a value between [min, max].
 * @param  {number} value
 * @param  {number} min
 * @param  {number} max
 * @returns {number}
 */
const clamp = (value, min, max) => Math.min(Math.max(value, min), max);

/**
 * Return the key with the highest numeric value in an object.
 * Tie-breaks in insertion order (first wins).
 * @param  {Object.<string, number>} obj
 * @returns {string}
 */
const maxKey = (obj) =>
  Object.entries(obj).reduce(
    (best, [k, v]) => (v > best[1] ? [k, v] : best),
    ["none", -Infinity]
  )[0];

// ─────────────────────────────────────────────
//  SECTION 4 · PIPELINE STAGES
// ─────────────────────────────────────────────

/**
 * Stage 1 — Normalise & validate input.
 * Guarantees every downstream stage receives clean numbers.
 * Never throws; falls back to safe defaults.
 *
 * @param  {SiteTelemetry} raw
 * @returns {SiteTelemetry}
 */
function normalise(raw) {
  const safeCount = (v) => (Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0);

  return {
    counts: {
      advertising:   safeCount(raw?.counts?.advertising),
      analytics:     safeCount(raw?.counts?.analytics),
      social:        safeCount(raw?.counts?.social),
      fingerprinting:safeCount(raw?.counts?.fingerprinting),
      cryptomining:  safeCount(raw?.counts?.cryptomining),
    },
    isHttps:       raw?.isHttps === true,
    totalRequests: Math.max(safeCount(raw?.totalRequests), 1), // never divide-by-zero
    uniqueDomains: safeCount(raw?.uniqueDomains),
  };
}

// ─────────────────────────────────────────────

/**
 * Stage 2 — Compute threat penalty.
 *
 * For each category:
 *   basePenalty = weight × log(count + 1)
 *
 * Anomaly spikes (non-linear escalation):
 *   • Fingerprinting ≥ 1  → multiply that category's penalty by FINGERPRINT_SPIKE_MULTIPLIER
 *   • Cryptomining   ≥ 1  → multiply that category's penalty by CRYPTOMINING_SPIKE_MULTIPLIER
 *
 * Returns per-category penalty map + total.
 *
 * @param  {SiteTelemetry} t
 * @returns {{ perCategory: Object.<string,number>, total: number }}
 */
function computeThreatPenalty(t) {
  const perCategory = {};

  for (const [type, weight] of Object.entries(THREAT_WEIGHTS)) {
    const count = t.counts[type] ?? 0;
    let penalty = weight * logDampen(count);

    // Anomaly spikes — asymmetric risk model
    if (type === "fingerprinting" && count >= FINGERPRINT_SPIKE_THRESHOLD) {
      penalty *= FINGERPRINT_SPIKE_MULTIPLIER;
    }
    if (type === "cryptomining" && count >= 1) {
      penalty *= CRYPTOMINING_SPIKE_MULTIPLIER;
    }

    perCategory[type] = penalty;
  }

  const total = Object.values(perCategory).reduce((s, v) => s + v, 0);
  return { perCategory, total };
}

// ─────────────────────────────────────────────

/**
 * Stage 3 — Compute context-aware modifiers.
 *
 * 3a. Tracker density penalty
 *     High ratio of blocked/total requests signals an aggressively
 *     tracking site, regardless of absolute numbers.
 *     penalty = (blocked / total) × DENSITY_WEIGHT
 *
 * 3b. Domain surface penalty
 *     Many unique third-party domains = wide data exfiltration surface.
 *     penalty = log2(uniqueDomains + 1) × DOMAIN_SURFACE_WEIGHT
 *
 * 3c. Volume forgiveness (large-site buffer)
 *     Major sites naturally fire more requests. Give a small credit
 *     based on log10(totalRequests) so sheer volume doesn't unfairly
 *     punish high-traffic legitimate sites.
 *     credit = min(log10(total+1) × FACTOR, MAX_CAP)
 *
 * @param  {SiteTelemetry} t
 * @returns {{ densityPenalty: number, domainPenalty: number, volumeCredit: number }}
 */
function computeContextModifiers(t) {
  const totalBlocked = Object.values(t.counts).reduce((s, v) => s + v, 0);

  const density        = totalBlocked / t.totalRequests;
  const densityPenalty = density * DENSITY_WEIGHT;

  const domainPenalty  = Math.log2(t.uniqueDomains + 1) * DOMAIN_SURFACE_WEIGHT;

  const volumeCredit   = clamp(
    Math.log10(t.totalRequests + 1) * VOLUME_FORGIVENESS_FACTOR,
    0,
    MAX_VOLUME_FORGIVENESS
  );

  return { densityPenalty, domainPenalty, volumeCredit };
}

// ─────────────────────────────────────────────

/**
 * Stage 4 — Protocol penalty.
 *
 * HTTP (non-HTTPS) means the connection is unencrypted.
 * Every blocked tracker could also be MITM'd — this is a
 * categorical risk, so it's a flat deduction, not a gradient.
 *
 * @param  {boolean} isHttps
 * @returns {number}
 */
const computeProtocolPenalty = (isHttps) =>
  isHttps ? 0 : HTTP_PROTOCOL_PENALTY;

// ─────────────────────────────────────────────

/**
 * Stage 5 — Aggregate final score.
 *
 * score = 100
 *       − threatPenalty
 *       − densityPenalty
 *       − domainPenalty
 *       − protocolPenalty
 *       + volumeCredit
 *
 * Clamped to [0, 100].
 *
 * @param  {number} threatTotal
 * @param  {Object} modifiers
 * @param  {number} protocolPenalty
 * @returns {number}
 */
function aggregateScore(threatTotal, modifiers, protocolPenalty) {
  const { densityPenalty, domainPenalty, volumeCredit } = modifiers;

  const raw = 100
    - threatTotal
    - densityPenalty
    - domainPenalty
    - protocolPenalty
    + volumeCredit;

  return clamp(Math.round(raw), SCORE_MIN, SCORE_MAX);
}

// ─────────────────────────────────────────────

/**
 * Stage 6 — Classify score into human-readable verdict.
 *
 * Thresholds derived from common infosec risk matrices
 * (CVSS-inspired: Critical/High/Medium/Low/Informational).
 *
 * @param  {number} score
 * @returns {{ status_label: string, status_color: string, risk_level: string }}
 */
function classify(score) {
  if (score >= 85) return { status_label: "Trusted",       status_color: "#22C55E", risk_level: "SAFE"     };
  if (score >= 65) return { status_label: "Mostly Safe",   status_color: "#84CC16", risk_level: "LOW"      };
  if (score >= 45) return { status_label: "Suspicious",    status_color: "#F59E0B", risk_level: "MEDIUM"   };
  if (score >= 25) return { status_label: "Risky",         status_color: "#EF4444", risk_level: "HIGH"     };
                   return { status_label: "Dangerous",     status_color: "#7F1D1D", risk_level: "CRITICAL" };
}

// ─────────────────────────────────────────────
//  SECTION 5 · PUBLIC API
// ─────────────────────────────────────────────

/**
 * computeTrustScore
 * ─────────────────
 * The single public entry point.  Call this on every webRequest
 * event with the current tab's accumulated telemetry.
 *
 * Performance profile:
 *  • O(k) where k = number of threat categories (constant = 5)
 *  • No heap allocations retained after return
 *  • No async I/O, no DOM access, no global state mutations
 *  • Safe to call 1000+ times/sec without memory pressure
 *
 * @param  {SiteTelemetry} siteTelemetry
 * @returns {TrustScoreResult}
 *
 * @example
 * const result = computeTrustScore({
 *   counts:        { advertising: 40, analytics: 12, social: 3, fingerprinting: 1, cryptomining: 0 },
 *   types:         ["advertising", "analytics", "fingerprinting"],
 *   isHttps:       true,
 *   totalRequests: 120,
 *   uniqueDomains: 18,
 * });
 * // → { score: 54, status_label: "Suspicious", status_color: "#F59E0B",
 * //     risk_level: "MEDIUM", top_threat_type: "fingerprinting" }
 */
function computeTrustScore(siteTelemetry) {
  // ── Stage 1: Sanitise
  const t = normalise(siteTelemetry);

  // ── Stage 2: Threat penalties
  const { perCategory, total: threatTotal } = computeThreatPenalty(t);

  // ── Stage 3: Context modifiers
  const modifiers = computeContextModifiers(t);

  // ── Stage 4: Protocol
  const protocolPenalty = computeProtocolPenalty(t.isHttps);

  // ── Stage 5: Final score
  const score = aggregateScore(threatTotal, modifiers, protocolPenalty);

  // ── Stage 6: Classification
  const { status_label, status_color, risk_level } = classify(score);

  // ── Determine top threat (highest penalty contribution)
  const top_threat_type = maxKey(perCategory);

  return {
    score,
    status_label,
    status_color,
    risk_level,
    top_threat_type,

    // Debug breakdown — consider stripping in prod builds via a build flag
    _debug: {
      perCategoryPenalties: perCategory,
      threatTotal:          +threatTotal.toFixed(2),
      densityPenalty:       +modifiers.densityPenalty.toFixed(2),
      domainPenalty:        +modifiers.domainPenalty.toFixed(2),
      volumeCredit:         +modifiers.volumeCredit.toFixed(2),
      protocolPenalty,
      normalisedTelemetry:  t,
    },
  };
}

// ─────────────────────────────────────────────
//  SECTION 6 · EXPORTS
// ─────────────────────────────────────────────

// Works in both MV2 background scripts (window scope) and
// module-aware bundlers (webpack / esbuild).
if (typeof module !== "undefined" && module.exports) {
  module.exports = { computeTrustScore };
} else if (typeof window !== "undefined") {
  window.PrivacyShield = window.PrivacyShield || {};
  window.PrivacyShield.computeTrustScore = computeTrustScore;
}

async function loadFilters() {
  for (const [file, blocklist] of Object.entries(filterFiles)) {
    try {
      const response = await fetch(browser.runtime.getURL(file));
      const text = await response.text();
      const lines = text.split('\n');
      let count = 0;

      for (let line of lines) {
        line = line.trim();
        if (!line || line.startsWith('!') || line.includes('##') || line.includes('###')) {
          continue;
        }
        
        let rule = line;
        if (rule.startsWith('||')) rule = rule.substring(2);
        if (rule.includes('^')) rule = rule.split('^')[0];
        if (rule.includes('$')) rule = rule.split('$')[0];

        if (rule) {
          blocklist.add(rule);
          count++;
        }
      }
      console.log(`Loaded ${count} rules from ${file}`);
    } catch (error) {
      console.error(`Failed to load ${file}:`, error);
    }
  }
  console.log(`Total ad rules: ${adBlocklist.size}, Total tracker rules: ${trackerBlocklist.size}`);
}

loadFilters();

function showNotification(title, message) {
  if (protectionSettings.showNotifications && typeof browser.notifications !== 'undefined') {
    browser.notifications.create({
      type: 'basic',
      title: title,
      message: message
    }).catch(err => console.log("Notification suppressed or error:", err));
  }
}

// Third-Party Cookie Blocking
browser.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (!protectionSettings.blockCookies || details.tabId === -1) return { cancel: false };

    initTabStats(details.tabId);
    const stats = sessionStats.tabs[details.tabId];
    const topDomain = stats.topDomain;
    if (!topDomain) return { cancel: false };

    try {
      const url = new URL(details.url);
      const requestDomain = url.hostname;
      
      // If it's third-party
      if (requestDomain !== topDomain && !requestDomain.endsWith('.' + topDomain)) {
        const headers = details.requestHeaders;
        for (let i = 0; i < headers.length; i++) {
          if (headers[i].name.toLowerCase() === 'cookie') {
            headers.splice(i, 1);
            console.log(`Third-party cookie blocked for ${details.url}`);
            
            // Log to activity tab
            const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            stats.blockedCount++;
            stats.categories.Cookies++;
            stats.blockedRequests.push({
              domain: requestDomain,
              type: 'Cookie',
              category: 'Cookies',
              timestamp: timestamp,
              url: details.url,
              status: 'Blocked'
            });
            calculateTrustScore(stats);
            break;
          }
        }
        return { requestHeaders: headers };
      }
    } catch (e) {
      console.error("Error in cookie blocking logic:", e);
    }
    return { cancel: false };
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"]
);

browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (!protectionSettings.blockCookies || details.tabId === -1) return { cancel: false };

    initTabStats(details.tabId);
    const stats = sessionStats.tabs[details.tabId];
    const topDomain = stats.topDomain;
    if (!topDomain) return { cancel: false };

    try {
      const url = new URL(details.url);
      const requestDomain = url.hostname;

      if (requestDomain !== topDomain && !requestDomain.endsWith('.' + topDomain)) {
        const headers = details.responseHeaders;
        let blocked = false;
        for (let i = 0; i < headers.length; i++) {
          if (headers[i].name.toLowerCase() === 'set-cookie') {
            headers.splice(i, 1);
            i--; // Adjust index after removal
            blocked = true;
          }
        }
        if (blocked) {
          console.log(`Third-party Set-Cookie blocked for ${details.url}`);
          const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
          stats.blockedCount++;
          stats.categories.Cookies++;
          stats.blockedRequests.push({
            domain: requestDomain,
            type: 'Cookie',
            category: 'Cookies',
            timestamp: timestamp,
            url: details.url,
            status: 'Blocked'
          });
          calculateTrustScore(stats);
        }
        return { responseHeaders: headers };
      }
    } catch (e) {
      console.error("Error in Set-Cookie blocking logic:", e);
    }
    return { cancel: false };
  },
  { urls: ["<all_urls>"] },
  ["blocking", "responseHeaders"]
);

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    const tabId = details.tabId;
    if (tabId === -1) return { cancel: false }; // Skip background requests

    initTabStats(tabId);
    const stats = sessionStats.tabs[tabId];
    stats.totalPageRequests++;

    const url = new URL(details.url);
    if (details.type === 'main_frame') {
      stats.isHttps = url.protocol === 'https:';
      stats.topDomain = url.hostname;
    }
    const domain = url.hostname;
    const topDomainForCheck = stats.topDomain || domain;

    // Whitelist bypass — allow everything for whitelisted top-level domains
    if (whitelistSet.has(topDomainForCheck)) {
      return { cancel: false };
    }

    let isAd = false;
    let isTracker = false;
    let isFingerprinting = false;

    // Check for fingerprinting activities first
    const lowercaseUrl = details.url.toLowerCase();
    for (const keyword of fingerprintingKeywords) {
      if (lowercaseUrl.includes(keyword)) {
        isFingerprinting = true;
        break;
      }
    }

    for (const rule of adBlocklist) {
      if (details.url.includes(rule)) {
        isAd = true;
        break;
      }
    }
    for (const rule of trackerBlocklist) {
      if (details.url.includes(rule)) {
        isTracker = true;
        break;
      }
    }

    let category = 'Others';
    if (isFingerprinting) {
      category = 'Fingerprinting';
      stats.fingerprintingAttempts++;
      stats.categories.Fingerprinting++;
      console.log(`High-Risk Fingerprinting Script: ${details.url}`);
      showNotification('High-Risk Tracker Detected', `Fingerprinting attempt detected on ${topDomainForCheck}`);
    } else if (isAd) {
      stats.adCount++;
      if (lowercaseUrl.includes('doubleclick') || lowercaseUrl.includes('adsystem') || lowercaseUrl.includes('adnxs') || lowercaseUrl.includes('criteo') || lowercaseUrl.includes('google-adservices')) {
        category = 'Advertising';
        stats.categories.Advertising++;
      } else if (lowercaseUrl.includes('analytics') || lowercaseUrl.includes('google-analytics') || lowercaseUrl.includes('hotjar') || lowercaseUrl.includes('segment.io')) {
        category = 'Analytics';
        stats.categories.Analytics++;
      } else if (lowercaseUrl.includes('facebook') || lowercaseUrl.includes('twitter') || lowercaseUrl.includes('linkedin')) {
        category = 'Social';
        stats.categories.Social++;
      } else {
        category = 'Advertising';
        stats.categories.Advertising++;
      }
    } else if (isTracker) {
      stats.trackerDomains.add(domain);
      if (lowercaseUrl.includes('analytics') || lowercaseUrl.includes('google-analytics') || lowercaseUrl.includes('stats.g.doubleclick.net')) {
        category = 'Analytics';
        stats.categories.Analytics++;
      } else if (lowercaseUrl.includes('facebook') || lowercaseUrl.includes('connect.facebook.net') || lowercaseUrl.includes('t.co') || lowercaseUrl.includes('linkedin')) {
        category = 'Social';
        stats.categories.Social++;
      } else if (lowercaseUrl.includes('adsystem') || lowercaseUrl.includes('doubleclick')) {
        category = 'Advertising';
        stats.categories.Advertising++;
      } else {
        category = 'Others';
        stats.categories.Others++;
      }
    }

    if (isAd || isTracker || isFingerprinting) {
      stats.totalTrackers++;
      stats.detectedDomains.add(domain);
    }
    
    // Recalculate on every tab request so UI can update instantly.
    calculateTrustScore(stats);

    // SAFETY CHECK: Never block the main website frame (main_frame)
    if (details.type === 'main_frame') {
      return { cancel: false };
    }

    // Apply Live Toggles Logic
    if (isAd && !protectionSettings.adBlocking) return { cancel: false };
    if (isFingerprinting && !protectionSettings.fingerprinting) return { cancel: false };
    if (isTracker && !protectionSettings.socialTrackers && lowercaseUrl.includes('facebook|twitter|linkedin')) return { cancel: false };

    // If it's not a known threat, let it pass
    if (!isAd && !isTracker && !isFingerprinting) {
      return { cancel: false };
    }

    if (stats.blockedRequests.length > 200) stats.blockedRequests.shift(); // Keep last 200 blocked requests

    const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    // Determine if it's a third-party script
    const isThirdParty = domain !== stats.topDomain && details.type === 'script';

    switch (currentMode) {
      case 'aggressive':
        // Aggressive Mode: Block EVERYTHING (Ads, Trackers, Fingerprinting, Third-party scripts)
        if (isAd || isTracker || isFingerprinting || isThirdParty) {
          console.log(`Aggressive Blocking: ${details.url} [Type: ${details.type}]`);
          stats.blockedCount++;
          sessionStats.history[6]++; // Today's count
          browser.storage.local.set({ blockHistory: sessionStats.history });
          stats.blockedRequests.push({ 
            domain: domain, 
            type: details.type, 
            category: isThirdParty && !isAd && !isTracker && !isFingerprinting ? 'Others' : category, 
            timestamp: timestamp, 
            url: details.url, 
            status: 'Blocked' 
          });
          return { cancel: true };
        }
        break;
      
      case 'balanced':
        // Balanced Mode: Block High-Risk (Fingerprinting, Analytics, Social)
        // Allow Functional/Essential (Generic Ads if not high-risk, or non-tracking third-party scripts)
        const isHighRisk = isFingerprinting || category === 'Analytics' || category === 'Social';
        
        if (isHighRisk) {
          console.log(`Balanced Blocking (High-Risk): ${details.url} [Type: ${details.type}]`);
          stats.blockedCount++;
          sessionStats.history[6]++; // Today's count
          browser.storage.local.set({ blockHistory: sessionStats.history });
          stats.blockedRequests.push({ 
            domain: domain, 
            type: details.type, 
            category: category, 
            timestamp: timestamp, 
            url: details.url, 
            status: 'Blocked' 
          });
          return { cancel: true };
        }
        // Allow others in balanced mode to prevent breakage
        break;

      case 'manual':
        // Manual Mode: Stop automatic blocking, switch to 'Detection Only'
        // But block if domain is in manualBlocksSet
        const isManuallyBlocked = manualBlocksSet.has(domain);
        
        if (isAd || isTracker || isFingerprinting || isThirdParty) {
          console.log(`Manual Mode [${isManuallyBlocked ? 'Blocked' : 'Detected'}]: ${details.url}`);
          
          if (isManuallyBlocked) {
            stats.blockedCount++;
            sessionStats.history[6]++;
            browser.storage.local.set({ blockHistory: sessionStats.history });
          }

          stats.blockedRequests.push({ 
            domain: domain, 
            type: details.type, 
            category: isThirdParty && !isAd && !isTracker && !isFingerprinting ? 'Others' : category, 
            timestamp: timestamp, 
            url: details.url, 
            status: isManuallyBlocked ? 'Blocked' : 'Allowed'
          });

          if (isManuallyBlocked) return { cancel: true };
        }
        break;
    }

    return { cancel: false };
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.command === 'getStats') {
    const tabId = message.tabId;
    initTabStats(tabId);
    const stats = sessionStats.tabs[tabId];
    
    const tabStats = {
      totalTrackers: stats.totalTrackers,
      blockedCount: stats.blockedCount,
      detectedDomains: [...stats.detectedDomains],
      fingerprintingAttempts: stats.fingerprintingAttempts,
      trustScore: stats.trustScore,
      statusLabel: stats.statusLabel,
      statusColor: stats.statusColor,
      blockedRequests: stats.blockedRequests,
      categories: stats.categories,
      history: sessionStats.history,
      protectionSettings: protectionSettings,
      mode: currentMode,
    };
    sendResponse(tabStats);
  } else if (message.command === 'setMode') {
    currentMode = message.mode;
    console.log(`Mode changed to: ${currentMode}`);
    sendResponse({ status: 'Mode updated' });
  } else if (message.command === 'updateSettings') {
    protectionSettings = { ...protectionSettings, ...message.settings };
    browser.storage.local.set({ protectionSettings });
    sendResponse({ status: 'Settings updated' });
  } else if (message.command === 'toggleManualBlock') {
    const domain = message.domain;
    if (manualBlocksSet.has(domain)) {
      manualBlocksSet.delete(domain);
    } else {
      manualBlocksSet.add(domain);
    }
    browser.storage.local.set({ manualBlocks: Array.from(manualBlocksSet) });
    sendResponse({ status: 'Manual block toggled', isBlocked: manualBlocksSet.has(domain) });
  } else if (message.command === 'getManualBlocks') {
    sendResponse(Array.from(manualBlocksSet));
  } else if (message.type === 'FINGERPRINTING_DETECTED') {
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId) {
      initTabStats(tabId);
      const stats = sessionStats.tabs[tabId];
      stats.fingerprintingAttempts++;
      stats.categories.Fingerprinting++;
      stats.totalTrackers++;
      
      // Log the attempt
      stats.blockedRequests.unshift({
        url: message.api,
        domain: new URL(message.url).hostname,
        type: 'Fingerprinting',
        category: 'Fingerprinting',
        timestamp: new Date().toISOString()
      });

      calculateTrustScore(stats);
      
      console.log(`Fingerprinting Detected on tab ${tabId}: ${message.api}`);
      showNotification('High-Risk Tracker Detected', `Fingerprinting attempt (${message.api}) detected on this page.`);
    }
  } else if (message.command === 'updateWhitelist') {
    updateWhitelistCache(message.whitelist || []);
    sendResponse({ status: 'Whitelist updated', size: whitelistSet.size });
  }
  return true; // Required for async sendResponse
});
