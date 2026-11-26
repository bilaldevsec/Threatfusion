"""Node ``vm`` virtual-DOM execution harness and Wave 2 frontend invariant tests."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from threatfusion.advisory.telemetry_shield import draft_detection_rule

REPO_ROOT = Path(__file__).resolve().parents[3]
SOC_DASHBOARD_JS = REPO_ROOT / "frontend" / "js" / "soc_dashboard.js"

# Lightweight virtual DOM + browser API shim executed inside Node's ``vm`` context.
# Avoids jsdom/external npm deps while faithfully modeling element queries, classes,
# dataset, attributes, bubbling events, innerHTML parsing/serialization, Headers, and fetch.
_HARNESS_PRELUDE_JS = r"""
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

let pageerrors = 0;
const pageErrorMessages = [];
process.on('unhandledRejection', (reason) => {
  pageerrors += 1;
  pageErrorMessages.push('unhandledRejection: ' + String(reason && reason.stack ? reason.stack : reason));
});
process.on('uncaughtException', (err) => {
  pageerrors += 1;
  pageErrorMessages.push('uncaughtException: ' + String(err && err.stack ? err.stack : err));
});

function createDeferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function decodeHtmlEntities(str) {
  return String(str)
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0*39;/g, "'")
    .replace(/&amp;/g, '&');
}

function escapeAttr(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function escapeText(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

const VOID_TAGS = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr']);

class VirtualText {
  constructor(text) {
    this.nodeType = 3;
    this._text = String(text == null ? '' : text);
    this.parentNode = null;
  }
  get textContent() {
    return this._text;
  }
  set textContent(val) {
    this._text = String(val == null ? '' : val);
    if (this.parentNode) this.parentNode._invalidateHtmlCache();
  }
  toHtml() {
    return escapeText(this._text);
  }
}

function parseAttributes(attrText, el) {
  const re = /([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let match;
  while ((match = re.exec(attrText)) !== null) {
    const name = match[1].toLowerCase();
    const rawVal = match[2] !== undefined ? match[2] : (match[3] !== undefined ? match[3] : (match[4] !== undefined ? match[4] : ''));
    el.setAttribute(name, decodeHtmlEntities(rawVal));
  }
}

function parseHtmlFragment(html, doc) {
  const input = String(html == null ? '' : html);
  const rootNodes = [];
  const stack = [];
  const pushNode = (node) => {
    const parent = stack.length ? stack[stack.length - 1] : null;
    if (parent) {
      node.parentNode = parent;
      parent.childNodes.push(node);
    } else {
      node.parentNode = null;
      rootNodes.push(node);
    }
  };

  let idx = 0;
  const len = input.length;
  while (idx < len) {
    const lt = input.indexOf('<', idx);
    if (lt === -1) {
      const tail = input.slice(idx);
      if (tail) pushNode(new VirtualText(decodeHtmlEntities(tail)));
      break;
    }
    if (lt > idx) {
      pushNode(new VirtualText(decodeHtmlEntities(input.slice(idx, lt))));
    }
    if (input.startsWith('<!--', lt)) {
      const endComment = input.indexOf('-->', lt + 4);
      idx = endComment === -1 ? len : endComment + 3;
      continue;
    }
    const gt = input.indexOf('>', lt + 1);
    if (gt === -1) {
      pushNode(new VirtualText(decodeHtmlEntities(input.slice(lt))));
      break;
    }
    const tagBody = input.slice(lt + 1, gt).trim();
    idx = gt + 1;
    if (!tagBody) continue;
    if (tagBody[0] === '/') {
      const closeName = tagBody.slice(1).trim().toLowerCase();
      for (let i = stack.length - 1; i >= 0; i -= 1) {
        if (stack[i].tagName.toLowerCase() === closeName) {
          stack.length = i;
          break;
        }
      }
      continue;
    }
    const selfClosing = tagBody.endsWith('/');
    const cleanBody = selfClosing ? tagBody.slice(0, -1).trim() : tagBody;
    const spaceIdx = cleanBody.search(/\s/);
    const tagName = (spaceIdx === -1 ? cleanBody : cleanBody.slice(0, spaceIdx)).toLowerCase();
    const attrText = spaceIdx === -1 ? '' : cleanBody.slice(spaceIdx + 1);
    if (!/^[a-z][a-z0-9:-]*$/i.test(tagName)) {
      pushNode(new VirtualText('<' + tagBody + '>'));
      continue;
    }
    const el = new VirtualElement(tagName, doc);
    if (attrText) parseAttributes(attrText, el);
    pushNode(el);
    if (tagName === 'script' || tagName === 'style') {
      const closeTag = '</' + tagName + '>';
      const closeIdx = input.toLowerCase().indexOf(closeTag, idx);
      if (closeIdx !== -1) {
        const inner = input.slice(idx, closeIdx);
        if (inner) {
          const textNode = new VirtualText(inner);
          textNode.parentNode = el;
          el.childNodes.push(textNode);
        }
        idx = closeIdx + closeTag.length;
      }
      continue;
    }
    if (!selfClosing && !VOID_TAGS.has(tagName)) {
      stack.push(el);
    }
  }
  return rootNodes;
}

function splitSelectorList(selector) {
  const out = [];
  let cur = '';
  let quote = null;
  for (let i = 0; i < selector.length; i += 1) {
    const ch = selector[i];
    if (quote) {
      cur += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === ',') {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function parseCompoundSelector(part) {
  const cond = { tag: null, id: null, classes: [], attrs: [] };
  let rest = part.trim();
  const tagMatch = rest.match(/^([a-zA-Z*][a-zA-Z0-9_-]*)/);
  if (tagMatch) {
    if (tagMatch[1] !== '*') cond.tag = tagMatch[1].toLowerCase();
    rest = rest.slice(tagMatch[0].length);
  }
  while (rest.length > 0) {
    if (rest[0] === '#') {
      const m = rest.match(/^#([A-Za-z0-9_:-]+)/);
      if (!m) break;
      cond.id = m[1];
      rest = rest.slice(m[0].length);
    } else if (rest[0] === '.') {
      const m = rest.match(/^\.([A-Za-z0-9_-]+)/);
      if (!m) break;
      cond.classes.push(m[1]);
      rest = rest.slice(m[0].length);
    } else if (rest[0] === '[') {
      const m = rest.match(/^\[([A-Za-z0-9_:-]+)(?:=(?:"([^"]*)"|'([^']*)'|([^\]]*)))?\]/);
      if (!m) break;
      const hasValue = m[2] !== undefined || m[3] !== undefined || m[4] !== undefined;
      const value = m[2] !== undefined ? m[2] : (m[3] !== undefined ? m[3] : m[4]);
      cond.attrs.push({ name: m[1].toLowerCase(), hasValue, value });
      rest = rest.slice(m[0].length);
    } else {
      break;
    }
  }
  return cond;
}

function matchesCompound(el, cond) {
  if (!el || el.nodeType !== 1) return false;
  if (cond.tag && el.tagName.toLowerCase() !== cond.tag) return false;
  if (cond.id && el.id !== cond.id) return false;
  for (const cls of cond.classes) {
    if (!el.classList.contains(cls)) return false;
  }
  for (const attr of cond.attrs) {
    if (!el.hasAttribute(attr.name)) return false;
    if (attr.hasValue && String(el.getAttribute(attr.name)) !== String(attr.value)) return false;
  }
  return true;
}

function matchesSingleSelector(el, selector) {
  const parts = selector.trim().split(/\s+/).filter(Boolean).map(parseCompoundSelector);
  if (!parts.length) return false;
  if (!matchesCompound(el, parts[parts.length - 1])) return false;
  let cur = el.parentNode;
  for (let i = parts.length - 2; i >= 0; i -= 1) {
    while (cur && !matchesCompound(cur, parts[i])) {
      cur = cur.parentNode;
    }
    if (!cur) return false;
    cur = cur.parentNode;
  }
  return true;
}

function matchesSelector(el, selector) {
  const options = splitSelectorList(String(selector || ''));
  return options.some((opt) => matchesSingleSelector(el, opt));
}

class VirtualClassList {
  constructor(el) {
    this._el = el;
  }
  _list() {
    const raw = this._el._attrs.get('class') || '';
    return raw.trim() ? raw.trim().split(/\s+/) : [];
  }
  _save(items) {
    if (items.length === 0) {
      this._el._attrs.delete('class');
    } else {
      this._el._attrs.set('class', items.join(' '));
    }
    this._el._invalidateHtmlCache();
  }
  contains(token) {
    return this._list().includes(String(token));
  }
  add(...tokens) {
    const items = this._list();
    for (const token of tokens) {
      const t = String(token);
      if (t && !items.includes(t)) items.push(t);
    }
    this._save(items);
  }
  remove(...tokens) {
    const removeSet = new Set(tokens.map(String));
    this._save(this._list().filter((item) => !removeSet.has(item)));
  }
  toggle(token, force) {
    const t = String(token);
    const has = this.contains(t);
    const shouldAdd = force === undefined ? !has : Boolean(force);
    if (shouldAdd && !has) this.add(t);
    else if (!shouldAdd && has) this.remove(t);
    return shouldAdd;
  }
}

class VirtualElement {
  constructor(tagName, ownerDocument) {
    this.nodeType = 1;
    this.tagName = String(tagName || 'div').toUpperCase();
    this.ownerDocument = ownerDocument || null;
    this._attrs = new Map();
    this.childNodes = [];
    this.parentNode = null;
    this.style = {};
    this._listeners = new Map();
    this._cachedInnerHtml = null;
    this._value = '';
    this._disabled = false;
    this._tabIndex = undefined;
    this.href = '';
    this.download = '';
    this.type = '';
    this.classList = new VirtualClassList(this);
    const self = this;
    this.dataset = new Proxy({}, {
      get(_target, prop) {
        if (typeof prop !== 'string') return undefined;
        const attrName = 'data-' + prop.replace(/[A-Z]/g, (m) => '-' + m.toLowerCase());
        return self.getAttribute(attrName) ?? undefined;
      },
      set(_target, prop, value) {
        if (typeof prop !== 'string') return false;
        const attrName = 'data-' + prop.replace(/[A-Z]/g, (m) => '-' + m.toLowerCase());
        self.setAttribute(attrName, String(value));
        return true;
      },
      deleteProperty(_target, prop) {
        if (typeof prop !== 'string') return false;
        const attrName = 'data-' + prop.replace(/[A-Z]/g, (m) => '-' + m.toLowerCase());
        self.removeAttribute(attrName);
        return true;
      }
    });
  }

  _invalidateHtmlCache() {
    let cur = this;
    while (cur) {
      cur._cachedInnerHtml = null;
      cur = cur.parentNode;
    }
  }

  get children() {
    return this.childNodes.filter((n) => n.nodeType === 1);
  }

  get id() {
    return this._attrs.get('id') || '';
  }
  set id(val) {
    this.setAttribute('id', String(val));
  }

  get className() {
    return this._attrs.get('class') || '';
  }
  set className(val) {
    this.setAttribute('class', String(val));
  }

  get hidden() {
    return this._attrs.has('hidden');
  }
  set hidden(val) {
    if (val) this._attrs.set('hidden', '');
    else this._attrs.delete('hidden');
    this._invalidateHtmlCache();
  }

  get disabled() {
    return this._disabled;
  }
  set disabled(val) {
    this._disabled = Boolean(val);
    if (this._disabled) this._attrs.set('disabled', '');
    else this._attrs.delete('disabled');
  }

  get tabIndex() {
    return this._tabIndex;
  }
  set tabIndex(val) {
    this._tabIndex = Number(val);
    this._attrs.set('tabindex', String(this._tabIndex));
  }

  get title() {
    return this._attrs.get('title') || '';
  }
  set title(val) {
    this.setAttribute('title', String(val));
  }

  get value() {
    return this._value;
  }
  set value(val) {
    this._value = String(val == null ? '' : val);
  }

  getAttribute(name) {
    const key = String(name).toLowerCase();
    return this._attrs.has(key) ? this._attrs.get(key) : null;
  }

  hasAttribute(name) {
    return this._attrs.has(String(name).toLowerCase());
  }

  setAttribute(name, value) {
    const key = String(name).toLowerCase();
    const val = String(value == null ? '' : value);
    this._attrs.set(key, val);
    if (key === 'id' && this.ownerDocument) {
      this.ownerDocument._byId.set(val, this);
    } else if (key === 'disabled') {
      this._disabled = true;
    } else if (key === 'tabindex') {
      this._tabIndex = Number(val);
    } else if (key === 'value') {
      this._value = val;
    }
    this._invalidateHtmlCache();
  }

  removeAttribute(name) {
    const key = String(name).toLowerCase();
    this._attrs.delete(key);
    if (key === 'disabled') this._disabled = false;
    this._invalidateHtmlCache();
  }

  get textContent() {
    return this.childNodes.map((child) => child.textContent).join('');
  }

  set textContent(val) {
    this.childNodes = [];
    const str = String(val == null ? '' : val);
    if (str !== '') {
      const text = new VirtualText(str);
      text.parentNode = this;
      this.childNodes.push(text);
    }
    this._invalidateHtmlCache();
  }

  get innerHTML() {
    if (this._cachedInnerHtml !== null) return this._cachedInnerHtml;
    return this.childNodes.map((child) => child.toHtml()).join('');
  }

  set innerHTML(html) {
    const raw = String(html == null ? '' : html);
    const parsed = parseHtmlFragment(raw, this.ownerDocument);
    this.childNodes = [];
    for (const node of parsed) {
      node.parentNode = this;
      this.childNodes.push(node);
    }
    this._invalidateHtmlCache();
    this._cachedInnerHtml = raw;
  }

  toHtml() {
    const tag = this.tagName.toLowerCase();
    const attrParts = [];
    for (const [k, v] of this._attrs.entries()) {
      attrParts.push(v === '' && (k === 'hidden' || k === 'disabled' || k === 'readonly')
        ? k
        : k + '="' + escapeAttr(v) + '"');
    }
    const open = '<' + tag + (attrParts.length ? ' ' + attrParts.join(' ') : '') + '>';
    if (VOID_TAGS.has(tag)) return open;
    return open + this.innerHTML + '</' + tag + '>';
  }

  appendChild(node) {
    if (!node) return node;
    if (node.parentNode) node.parentNode.removeChild(node);
    node.parentNode = this;
    this.childNodes.push(node);
    this._invalidateHtmlCache();
    return node;
  }

  removeChild(node) {
    const idx = this.childNodes.indexOf(node);
    if (idx !== -1) {
      this.childNodes.splice(idx, 1);
      node.parentNode = null;
      this._invalidateHtmlCache();
    }
    return node;
  }

  remove() {
    if (this.parentNode) this.parentNode.removeChild(this);
  }

  insertAdjacentHTML(position, html) {
    const nodes = parseHtmlFragment(html, this.ownerDocument);
    if (String(position).toLowerCase() === 'beforeend') {
      for (const node of nodes) {
        this.appendChild(node);
      }
      return;
    }
    throw new Error('Unsupported insertAdjacentHTML position: ' + position);
  }

  _collectDescendants(out) {
    for (const child of this.childNodes) {
      if (child.nodeType === 1) {
        out.push(child);
        child._collectDescendants(out);
      }
    }
  }

  querySelectorAll(selector) {
    const nodes = [];
    this._collectDescendants(nodes);
    return nodes.filter((node) => matchesSelector(node, selector));
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }

  closest(selector) {
    let cur = this;
    while (cur && cur.nodeType === 1) {
      if (matchesSelector(cur, selector)) return cur;
      cur = cur.parentNode;
    }
    return null;
  }

  addEventListener(type, fn) {
    if (typeof fn !== 'function') return;
    const key = String(type);
    if (!this._listeners.has(key)) this._listeners.set(key, []);
    this._listeners.get(key).push(fn);
  }

  removeEventListener(type, fn) {
    const key = String(type);
    const list = this._listeners.get(key);
    if (!list) return;
    const idx = list.indexOf(fn);
    if (idx !== -1) list.splice(idx, 1);
  }

  dispatchEvent(event) {
    const evt = event || { type: '' };
    if (!evt.target) evt.target = this;
    let cur = this;
    while (cur && !evt._stopped) {
      evt.currentTarget = cur;
      const listeners = cur._listeners ? cur._listeners.get(String(evt.type)) : null;
      if (listeners) {
        for (const fn of listeners.slice()) {
          fn.call(cur, evt);
        }
      }
      if (evt.bubbles === false) break;
      cur = cur.parentNode;
    }
    return !evt.defaultPrevented;
  }

  click() {
    this.dispatchEvent(new MockEvent('click', { bubbles: true, cancelable: true }));
  }

  select() {}
  scrollIntoView() {}
}

class MockEvent {
  constructor(type, init) {
    const opts = init || {};
    this.type = String(type);
    this.key = opts.key || '';
    this.bubbles = opts.bubbles !== undefined ? Boolean(opts.bubbles) : false;
    this.cancelable = opts.cancelable !== undefined ? Boolean(opts.cancelable) : true;
    this.defaultPrevented = false;
    this._stopped = false;
    this.target = opts.target || null;
    this.currentTarget = null;
  }
  preventDefault() {
    if (this.cancelable) this.defaultPrevented = true;
  }
  stopPropagation() {
    this._stopped = true;
  }
}

class MockHeaders {
  constructor(init) {
    this._map = new Map();
    if (!init) return;
    if (init instanceof MockHeaders || (typeof init.forEach === 'function' && typeof init.get === 'function')) {
      init.forEach((v, k) => this.set(k, v));
    } else if (Array.isArray(init)) {
      for (const pair of init) {
        if (Array.isArray(pair) && pair.length >= 2) this.set(pair[0], pair[1]);
      }
    } else if (typeof init === 'object') {
      for (const k of Object.keys(init)) {
        this.set(k, init[k]);
      }
    }
  }
  set(name, value) {
    this._map.set(String(name).toLowerCase(), String(value));
  }
  get(name) {
    const k = String(name).toLowerCase();
    return this._map.has(k) ? this._map.get(k) : null;
  }
  has(name) {
    return this._map.has(String(name).toLowerCase());
  }
  delete(name) {
    this._map.delete(String(name).toLowerCase());
  }
  forEach(cb) {
    for (const [k, v] of this._map.entries()) cb(v, k, this);
  }
  entries() {
    return this._map.entries();
  }
}

class VirtualDocument {
  constructor() {
    this.readyState = 'loading';
    this._byId = new Map();
    this._listeners = new Map();
    this.documentElement = new VirtualElement('html', this);
    this.head = new VirtualElement('head', this);
    this.body = new VirtualElement('body', this);
    this.documentElement.appendChild(this.head);
    this.documentElement.appendChild(this.body);
  }
  createElement(tag) {
    return new VirtualElement(tag, this);
  }
  registerElement(tag, id, attrs) {
    const el = this.createElement(tag);
    if (id) el.id = id;
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (k === 'hidden' && v) el.hidden = true;
        else if (k === 'disabled' && v) el.disabled = true;
        else if (k === 'textContent') el.textContent = v;
        else if (k === 'value') el.value = v;
        else el.setAttribute(k, v);
      }
    }
    this.body.appendChild(el);
    return el;
  }
  getElementById(id) {
    const key = String(id);
    if (this._byId.has(key)) return this._byId.get(key);
    return this.documentElement.querySelector('#' + key);
  }
  querySelector(selector) {
    return this.documentElement.querySelector(selector);
  }
  querySelectorAll(selector) {
    return this.documentElement.querySelectorAll(selector);
  }
  addEventListener(type, fn) {
    const key = String(type);
    if (!this._listeners.has(key)) this._listeners.set(key, []);
    this._listeners.get(key).push(fn);
  }
  dispatchEvent(event) {
    const list = this._listeners.get(String(event.type)) || [];
    for (const fn of list.slice()) fn.call(this, event);
    return !event.defaultPrevented;
  }
  execCommand() {
    return false;
  }
}

function makeJsonResponse(status, payload) {
  const bodyText = typeof payload === 'string' ? payload : JSON.stringify(payload || {});
  return {
    status: Number(status),
    ok: Number(status) >= 200 && Number(status) < 300,
    text: async () => bodyText,
    json: async () => (typeof payload === 'string' ? JSON.parse(payload) : (payload || {}))
  };
}

function buildConsoleSandbox(options) {
  const opts = options || {};
  const doc = new VirtualDocument();

  // Optional CSRF meta tag
  if (opts.csrfMetaToken) {
    const meta = doc.createElement('meta');
    meta.setAttribute('name', 'threatfusion-csrf-token');
    meta.setAttribute('content', opts.csrfMetaToken);
    doc.head.appendChild(meta);
  }

  // Register standard console DOM elements used by soc_dashboard.js
  const elementSpecs = [
    ['div', 'identityModal', { class: 'identity-modal zt-login-gate', hidden: true }],
    ['div', 'identityModalStatus', { 'data-evidence-state': 'unavailable' }],
    ['button', 'btnReturnToConsole', { hidden: true }],
    ['button', 'btnCloseIdentityModal', { hidden: true }],
    ['div', 'consoleApp', {}],
    ['div', 'forensicDrawer', {}],
    ['span', 'activeSessionName', {}],
    ['span', 'activeSessionActor', {}],
    ['span', 'activeSessionRole', {}],
    ['span', 'activeSessionState', {}],
    ['span', 'operatorAuthBadge', { 'data-evidence-state': 'unavailable' }],
    ['span', 'operatorProfileName', {}],
    ['input', 'operatorActor', { value: 'analyst_a' }],
    ['select', 'operatorRoleSelect', {}],
    ['input', 'rbacUsername', { value: 'approver@threatfusion.local' }],
    ['input', 'rbacAccessCode', { value: 'secret-code' }],
    ['input', 'rbacEntraToken', { value: '' }],
    ['input', 'rbacRegisterName', { value: '' }],
    ['select', 'rbacRegisterRole', { value: 'tier1_triage' }],
    ['tbody', 'incidentQueueList', {}],
    ['span', 'queueCountBadge', {}],
    ['div', 'campaignQueueStatus', { 'data-evidence-state': 'unavailable' }],
    ['p', 'liveQueueStatus', { 'data-evidence-state': 'unavailable' }],
    ['div', 'actionStatusBanner', { 'data-evidence-state': 'unavailable', textContent: 'No analyst action recorded yet.' }],
    ['div', 'socToast', { hidden: true }],
    ['span', 'pillCountAll', {}],
    ['span', 'pillCountUrgent', {}],
    ['span', 'pillCountNotable', {}],
    ['span', 'pillCountInfo', {}],
    ['span', 'liveHeroFlowCount', {}],
    ['span', 'liveHeroCampaignCount', {}],
    ['span', 'liveHeroIncidentCount', {}],
    ['span', 'liveHeroBridgeCount', {}],
    ['h2', 'inspectorCaseTitle', {}],
    ['span', 'groundedBadge', {}],
    ['div', 'conclusionCard', {}],
    ['span', 'inspectorDecision', {}],
    ['span', 'inspectorScore', {}],
    ['span', 'inspectorSensorLine', {}],
    ['span', 'inspectorForestLine', {}],
    ['span', 'inspectorScenarioLabel', {}],
    ['span', 'inspectorAssets', {}],
    ['span', 'inspectorPlaybook', {}],
    ['span', 'inspectorChain', {}],
    ['span', 'inspectorCallback', {}],
    ['span', 'inspectorExecutionPath', {}],
    ['span', 'headerChainBadge', {}],
    ['div', 'soarChangelog', {}],
    ['span', 'flowRfBadge', {}],
    ['span', 'flowAeBadge', {}],
    ['span', 'flowDnnBadge', { textContent: 'PyTorch DNN (9-Class): waiting' }],
    ['span', 'rangeConnectivityBadge', { 'data-evidence-state': 'unavailable' }],
    ['div', 'rangeFirewallStatus', { 'data-evidence-state': 'unavailable' }],
    ['button', 'approvePlaybookBtn', { disabled: true }],
    ['button', 'soarApproveBtn', { disabled: true }],
    ['button', 'evidenceApproveBtn', { disabled: true }],
    ['button', 'btnDispatchCallback', { disabled: true }],
    ['button', 'btnIsolateAttacker', { disabled: true }],
    ['button', 'btnContainRange', { disabled: true }],
    ['button', 'btnRollbackRange', { disabled: true }],
    ['span', 'advisoryCompletenessPill', { 'data-completeness': 'PENDING ADVISORY' }],
    ['span', 'ledgerFencePill', { 'data-ledger-status': 'pending' }],
    ['div', 'advisoryAuthorityBar', {}],
    ['tbody', 'advisoryTraceBody', {}],
    ['div', 'advisoryTraceGaps', {}],
    ['details', 'advisoryTraceGapsDetails', { hidden: true }],
    ['pre', 'aiReasoningEvidence', {}],
    ['div', 'aiGovernancePills', {}],
    ['div', 'liveCopilotAnswer', { 'data-evidence-state': 'unavailable' }],
    ['input', 'liveCopilotQuestion', { value: '' }],
    ['div', 'advisoryProgress', { hidden: true }],
    ['span', 'copilotProviderBadge', {}],
    ['input', 'analystNoteText', { value: '' }],
    ['button', 'btnSaveAnalystNote', {}],
    ['tbody', 'huntingGuidesBody', {}],
    ['input', 'hunterDraftRuleQuery', { value: '' }],
    ['pre', 'hunterDraftRulePreview', {}],
    ['span', 'hunterVerifyBadge', {}],
    ['div', 'hunterRuleBadges', {}],
    ['pre', 'hunterRuleSuricata', {}],
    ['pre', 'hunterRuleSigma', {}],
    ['pre', 'hunterRuleSpl', {}],
    ['pre', 'hunterRuleYara', {}],
    ['div', 'huntAiSummaryCard', { hidden: true }],
    ['p', 'huntSummaryOverview', {}],
    ['ul', 'huntSummaryIndicators', {}],
    ['ol', 'huntSummaryProgression', {}],
    ['ol', 'huntSummaryActions', {}],
    ['div', 'huntSummaryLedger', {}],
    ['div', 'gaugeRfFill', {}],
    ['div', 'gaugeRfThreshold', {}],
    ['div', 'gaugeRfValue', {}],
    ['div', 'gaugeAeFill', {}],
    ['div', 'gaugeAeThreshold', {}],
    ['div', 'gaugeAeValue', {}],
    ['div', 'gaugeDnnFill', {}],
    ['div', 'gaugeDnnThreshold', {}],
    ['div', 'gaugeDnnValue', {}],
    ['div', 'dnnSoftmaxChart', {}],
    ['div', 'aeFeatureErrorChart', {}],
    ['pre', 'modelProofResults', {}],
    ['div', 'modelProofFeatureGrid', {}],
    ['select', 'workspaceSelect', {}],
    ['div', 'sensorRegistryList', {}],
    ['span', 'entraUpn', {}],
    ['span', 'entraObjectId', {}],
    ['span', 'entraAppRole', {}],
    ['span', 'entraMtlsStatus', {}],
    ['span', 'entraTenantId', {}],
    ['span', 'entraSubscriptionTier', {}],
    ['div', 'workspaceStatus', {}],
    ['div', 'sampleBanner', { 'data-sample-only': 'true' }]
  ];
  for (const [tag, id, attrs] of elementSpecs) {
    doc.registerElement(tag, id, attrs);
  }

  const fetchCalls = [];
  let timerIdSeq = 0;
  let fetchHandler = opts.fetchHandler || (async () => makeJsonResponse(200, {}));

  const storageStore = new Map();
  const mockStorage = {
    getItem(k) { return storageStore.has(k) ? storageStore.get(k) : null; },
    setItem(k, v) { storageStore.set(String(k), String(v)); },
    removeItem(k) { storageStore.delete(String(k)); }
  };

  const sandbox = {
    console,
    document: doc,
    location: { hash: '' },
    navigator: { clipboard: { writeText: async () => {} } },
    sessionStorage: mockStorage,
    localStorage: mockStorage,
    Headers: MockHeaders,
    Event: MockEvent,
    Blob: class MockBlob { constructor(parts) { this.parts = parts; } },
    URL: { createObjectURL: () => 'blob:mock', revokeObjectURL: () => {} },
    setTimeout: () => { timerIdSeq += 1; return timerIdSeq; },
    clearTimeout: () => {},
    setInterval: () => { timerIdSeq += 1; return timerIdSeq; },
    clearInterval: () => {},
    fetch: async function (url, init) {
      const record = {
        url: String(url),
        method: String((init && init.method) || 'GET').toUpperCase(),
        credentials: init ? init.credentials : undefined,
        headers: init && init.headers ? new MockHeaders(init.headers) : new MockHeaders(),
        body: init && init.body !== undefined ? init.body : undefined
      };
      fetchCalls.push(record);
      return fetchHandler(record.url, init || {}, record);
    }
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;

  const jsPath = process.argv[1];
  let source = fs.readFileSync(jsPath, 'utf8');
  if (opts.exportPatchCopilotSectionFive) {
    source = source.replace(
      '    renderHuntingGuideRow,\n    initApp',
      '    renderHuntingGuideRow,\n    patchCopilotSectionFive,\n    initApp'
    );
  }

  vm.runInNewContext(source, sandbox, { filename: jsPath });

  return {
    context: sandbox,
    doc,
    sandbox,
    api: sandbox.ThreatFusionDashboard,
    fetchCalls,
    setFetchHandler(fn) { fetchHandler = fn; }
  };
}

async function flushMicrotasks(rounds = 12) {
  for (let i = 0; i < rounds; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

function finalizeNodeTest() {
  if (pageerrors !== 0) {
    console.error('Page errors encountered:', pageErrorMessages.join('\n'));
    process.exit(2);
  }
  process.exit(0);
}
"""


def _run_node_harness(test_js: str) -> None:
    """Execute a Node ``vm`` test script against ``frontend/js/soc_dashboard.js``."""
    assert shutil.which("node"), "node binary is required for JS DOM harness tests"
    full_script = (
        _HARNESS_PRELUDE_JS
        + "\n(async () => {\n"
        + test_js
        + "\n})().then(() => finalizeNodeTest()).catch((err) => { console.error(err && err.stack ? err.stack : err); process.exit(1); });\n"
    )
    completed = subprocess.run(
        ["node", "-e", full_script, str(SOC_DASHBOARD_JS)],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, (
        f"Node VM harness failed (rc={completed.returncode})\n"
        f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
    )


def test_js_harness_xss_sanitization_across_sinks() -> None:
    """Verify XSS payloads are HTML-escaped across all dashboard DOM rendering sinks."""
    _run_node_harness(r"""
const { doc, api } = buildConsoleSandbox();
const payloads = [
  '<img src=x onerror=alert(1)>',
  '<script>evil()</script>',
  '" onmouseover="alert(1)'
];
const combined = payloads.join(' | ');

for (const payload of payloads) {
  const escaped = api.escapeHtml(payload);
  assert(!escaped.includes('<script'), 'escapeHtml leaked raw <script');
  assert(!escaped.includes('<img'), 'escapeHtml leaked raw <img');
  if (payload.includes('<img')) assert(escaped.includes('&lt;img'));
  if (payload.includes('<script')) assert(escaped.includes('&lt;script'));
  if (payload.includes('"')) assert(escaped.includes('&quot;'));
}

// 1. formatCopilotAnswer
const copilotBox = doc.getElementById('liveCopilotAnswer');
copilotBox.innerHTML = api.formatCopilotAnswer('[1] VERDICT\n**' + combined + '** `' + combined + '`');
assert(copilotBox.innerHTML.includes('&lt;img'));
assert(copilotBox.innerHTML.includes('&lt;script'));
assert(copilotBox.innerHTML.includes('&quot;'));
assert(!copilotBox.innerHTML.toLowerCase().includes('<script'));
assert(!copilotBox.innerHTML.toLowerCase().includes('<img'));
assert.strictEqual(copilotBox.querySelectorAll('script, img').length, 0);

// 2. appendIncidentItem
const tbody = doc.getElementById('incidentQueueList');
api.appendIncidentItem(tbody, {
  id: 'inc-' + combined,
  flowId: 77,
  observedAt: '2026-11-26T10:00:00Z ' + combined,
  decision: 'Attack',
  uncalibratedScore: 0.94,
  sourceLabel: 'suricata_bridge',
  triageState: combined,
  analystVerdict: combined,
  simhashSignature: combined,
  burstCount: 3,
  provenance: {
    srcIp: '<img src=x onerror=alert(1)>',
    dstIp: '<script>evil()</script>',
    dstPort: 443,
    proto: '" onmouseover="alert(1)'
  },
  advisory: { summaryHeadline: combined }
});
const tr = tbody.children[0];
assert(tr, 'appendIncidentItem must append a <tr>');
assert(tr.innerHTML.includes('&lt;img'), 'appendIncidentItem missing &lt;img');
assert(tr.innerHTML.includes('&lt;script'), 'appendIncidentItem missing &lt;script');
assert(tr.innerHTML.includes('&quot;'), 'appendIncidentItem missing &quot;');
assert(!tr.innerHTML.toLowerCase().includes('<script'), 'appendIncidentItem leaked raw <script');
assert(!tr.innerHTML.toLowerCase().includes('<img'), 'appendIncidentItem leaked raw <img');
assert.strictEqual(tr.querySelectorAll('script, img').length, 0);

// 3. renderAdvisoryTrace
api.renderAdvisoryTrace({
  completeness_badge: 'COMPLETE',
  authority: { decision_writes_by_advisory_components: 0, frozen_rf_verdict: 'Attack', gate_g9: 'PASS' },
  components: [{
    component_id: 'custom_xss',
    display_name: combined,
    assigned_scope: combined,
    actual_output: combined,
    evidence_ids_read: [combined],
    measurement_integrity: combined
  }]
});
const traceBody = doc.getElementById('advisoryTraceBody');
assert(traceBody.innerHTML.includes('&lt;img'), 'renderAdvisoryTrace missing &lt;img');
assert(traceBody.innerHTML.includes('&lt;script'), 'renderAdvisoryTrace missing &lt;script');
assert(traceBody.innerHTML.includes('&quot;'), 'renderAdvisoryTrace missing &quot;');
assert(!traceBody.innerHTML.toLowerCase().includes('<script'), 'renderAdvisoryTrace leaked raw <script');
assert(!traceBody.innerHTML.toLowerCase().includes('<img'), 'renderAdvisoryTrace leaked raw <img');
assert.strictEqual(traceBody.querySelectorAll('script, img').length, 0);

// 4. renderHuntingGuideRow
const guidesBody = doc.getElementById('huntingGuidesBody');
guidesBody.innerHTML = api.renderHuntingGuideRow({
  guide_id: 'guide-' + combined,
  title: combined,
  adversary_profile: combined,
  hypothesis: combined,
  mitre_technique: combined,
  active_match_pct: 80,
  results_found_count: 2,
  max_sbytes_zscore: combined,
  badges: [combined]
});
assert(guidesBody.innerHTML.includes('&lt;img'), 'renderHuntingGuideRow missing &lt;img');
assert(guidesBody.innerHTML.includes('&lt;script'), 'renderHuntingGuideRow missing &lt;script');
assert(guidesBody.innerHTML.includes('&quot;'), 'renderHuntingGuideRow missing &quot;');
assert(!guidesBody.innerHTML.toLowerCase().includes('<script'), 'renderHuntingGuideRow leaked raw <script');
assert(!guidesBody.innerHTML.toLowerCase().includes('<img'), 'renderHuntingGuideRow leaked raw <img');
assert.strictEqual(guidesBody.querySelectorAll('script, img').length, 0);
""")


def test_js_harness_fetch_csrf_logout_wipe_and_401_production_gating() -> None:
    """Verify window.fetch CSRF header injection, logout token wipe, and 401 production re-gating."""
    _run_node_harness(r"""
let healthCalls = 0;
let currentCsrf = 'csrf-initial-1';
let return401OnLive = false;

const { doc, sandbox, api, fetchCalls, setFetchHandler } = buildConsoleSandbox({
  csrfMetaToken: 'csrf-initial-1',
  fetchHandler: async (url) => {
    if (url.startsWith('/api/v1/live/health')) {
      healthCalls += 1;
      return makeJsonResponse(200, { csrf_token: currentCsrf, checks: [] });
    }
    if (url === '/api/v1/live/posture') {
      return makeJsonResponse(200, {
        environment: 'production',
        posture_label: 'POSTURE: PRODUCTION',
        demo_quickfill_enabled: false
      });
    }
    if (url === '/api/rbac/login') {
      return makeJsonResponse(200, {
        authenticated: true,
        actor_id: 'lab_operator',
        role: 'soc_approver',
        display_name: 'Tier-3 SOC Approver',
        csrf_token: 'csrf-session-1'
      });
    }
    if (url === '/api/rbac/logout') {
      return makeJsonResponse(200, { authenticated: false });
    }
    if (return401OnLive && url.startsWith('/api/v1/live/')) {
      return makeJsonResponse(401, { error: 'session_expired' });
    }
    if (url === '/api/v1/live/notes') {
      return makeJsonResponse(200, { evidence_state: 'verified' });
    }
    if (url === '/api/v1/live/campaigns') {
      return makeJsonResponse(200, {
        flow_count: 1,
        campaign_count: 1,
        incident_count: 0,
        bridge_flow_count: 0,
        campaigns: [{
          campaign_id: 'cmp-1',
          member_count: 1,
          flows: [{
            flow_id: 1,
            decision: 'Attack',
            score: 0.91,
            src_entity_id: '172.29.0.10',
            dst_entity_id: '172.29.0.20',
            service_or_port: '80',
            flow_protocol: 'tcp',
            case_title: 'T1046 Probe'
          }]
        }],
        incidents: []
      });
    }
    return makeJsonResponse(200, {});
  }
});

// 1. POST /api/v1/live/notes injects X-ThreatFusion-CSRF and credentials: 'same-origin'
await sandbox.fetch('/api/v1/live/notes', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ flow_id: 1, note_text: 'check csrf' })
});
const noteCall1 = fetchCalls.filter((c) => c.url === '/api/v1/live/notes')[0];
assert(noteCall1, 'expected POST /api/v1/live/notes call');
assert.strictEqual(noteCall1.headers.get('X-ThreatFusion-CSRF'), 'csrf-initial-1');
assert.strictEqual(noteCall1.credentials, 'same-origin');

// 2. submitRbacLogout() wipes liveCsrfToken so subsequent live POST re-fetches /api/v1/live/health
currentCsrf = 'csrf-rotated-2';
const healthBeforeLogout = healthCalls;
await api.submitRbacLogout();
await sandbox.fetch('/api/v1/live/notes', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ flow_id: 1, note_text: 'after logout' })
});
assert.strictEqual(healthCalls, healthBeforeLogout + 1, 'logout must wipe liveCsrfToken and force re-fetch');
const noteCall2 = fetchCalls.filter((c) => c.url === '/api/v1/live/notes')[1];
assert.strictEqual(noteCall2.headers.get('X-ThreatFusion-CSRF'), 'csrf-rotated-2');
assert.notStrictEqual(noteCall2.headers.get('X-ThreatFusion-CSRF'), 'csrf-initial-1');

// 3. Authenticated 401 in production opens #identityModal, adds console-locked, clears session, never loads SAMPLE_INCIDENTS
await api.submitRbacLogin(false);
await flushMicrotasks();
assert.strictEqual(doc.body.classList.contains('console-locked'), false, 'login should unlock body');
assert.strictEqual(doc.getElementById('identityModal').hidden, true, 'login should hide #identityModal');
assert.strictEqual(doc.getElementById('activeSessionState').textContent, 'authenticated');

return401OnLive = true;
await api.refreshLiveCampaigns({ force: true });
await flushMicrotasks();

const modal = doc.getElementById('identityModal');
assert.strictEqual(modal.hidden, false, '401 must open #identityModal');
assert.strictEqual(modal.style.display, 'flex');
assert.strictEqual(doc.body.classList.contains('console-locked'), true, '401 must add console-locked to body');
assert.strictEqual(doc.getElementById('activeSessionState').textContent, 'unauthenticated');
assert.strictEqual(doc.getElementById('activeSessionActor').textContent, 'none');
assert.strictEqual(doc.getElementById('operatorAuthBadge').textContent, 'unverified local label');
assert.strictEqual(doc.getElementById('pillCountAll').textContent, '0', 'activeIncidents() must stay [] in production after 401');
assert.strictEqual(doc.getElementById('sampleBanner').hidden, true, 'sample-only surfaces must stay hidden');
const queueHtml = doc.getElementById('incidentQueueList').innerHTML;
assert(queueHtml.includes('No incidents match the active filter criteria.'), 'queue must stay empty on 401');
for (const sample of api.SAMPLE_INCIDENTS) {
  assert(!queueHtml.includes(sample.id), 'production 401 must never fall back to SAMPLE_INCIDENTS');
}

// Verify another /api/v1/live/* 401 route triggers the exact same re-gating behavior
setFetchHandler(async () => makeJsonResponse(401, { error: 'expired' }));
await sandbox.fetch('/api/v1/live/queue');
assert.strictEqual(doc.body.classList.contains('console-locked'), true);
assert.strictEqual(doc.getElementById('identityModal').hidden, false);
""")


def test_js_harness_selected_live_flow_id_isolation_across_inspect_hunt_guide() -> None:
    """Verify inspectHuntGuide preserves selectedLiveFlowId() and avoids duplicate T1046 prefix."""
    _run_node_harness(r"""
const { doc, api, fetchCalls } = buildConsoleSandbox({
  fetchHandler: async (url) => {
    if (url === '/api/v1/live/campaigns') {
      return makeJsonResponse(200, {
        flow_count: 2,
        campaign_count: 1,
        incident_count: 0,
        bridge_flow_count: 0,
        campaigns: [{
          campaign_id: 'cmp-hunt',
          member_count: 2,
          flows: [
            { flow_id: 1, decision: 'Attack', score: 0.91, src_entity_id: '172.29.0.10', dst_entity_id: '172.29.0.20', service_or_port: '80', flow_protocol: 'tcp', case_title: 'Flow 1 Attack' },
            { flow_id: 4, decision: 'Attack', score: 0.88, src_entity_id: '172.29.0.10', dst_entity_id: '172.29.0.20', service_or_port: '445', flow_protocol: 'tcp', case_title: 'Flow 4 Discovery' }
          ]
        }],
        incidents: []
      });
    }
    if (url === '/api/v1/live/hunter/guides') {
      return makeJsonResponse(200, {
        guides: [{
          guide_id: 'hunt-t1046',
          title: 'T1046 Network Service Discovery',
          adversary_profile: 'Lateral discovery',
          hypothesis: 'Port sweep across internal hosts',
          mitre_technique: 'T1046',
          active_match_pct: 75,
          results_found_count: 1,
          matching_flow_ids: [4],
          badges: ['Suricata', 'Sigma']
        }]
      });
    }
    if (url === '/api/v1/live/hunter/draft-rule') {
      return makeJsonResponse(200, {
        deployment_mode: 'REVIEW_ONLY_HUMAN_APPROVAL_REQUIRED',
        rule_syntax_verified: true,
        rules: {
          suricata: 'alert tcp any any -> $HOME_NET 445 (msg:"THREATFUSION T1046 Network Service Discovery"; sid:9000001; rev:1;)',
          sigma_yaml: 'title: ThreatFusion Hunt\ndetection:\n  selection:\n    dst_port: 445\n  condition: selection\n'
        }
      });
    }
    return makeJsonResponse(200, {});
  }
});

await api.refreshLiveCampaigns({ force: true });
await api.refreshHuntingGuides();
assert.strictEqual(api.selectedLiveFlowId(), 1, 'Flow #1 should be selected initially');

await api.inspectHuntGuide('hunt-t1046');

assert.strictEqual(api.selectedLiveFlowId(), 1, 'inspectHuntGuide must NOT overwrite selectedLiveFlowId() to Flow #4');
assert.strictEqual(
  doc.getElementById('hunterDraftRuleQuery').value,
  'Hunt T1046 Network Service Discovery',
  'query must strip duplicate T1046 prefix'
);
const draftCall = fetchCalls.find((c) => c.url === '/api/v1/live/hunter/draft-rule');
assert(draftCall, 'expected POST /api/v1/live/hunter/draft-rule');
const draftPayload = JSON.parse(draftCall.body);
assert.strictEqual(draftPayload.flow_id, 4);
assert.strictEqual(draftPayload.query, 'Hunt T1046 Network Service Discovery');
""")


def test_js_harness_save_live_analyst_note_payload_and_action_banner() -> None:
    """Verify saveLiveAnalystNote sends flow_id/author_id/note_text and updates banners."""
    _run_node_harness(r"""
let failNextNote = false;
const { doc, api, fetchCalls } = buildConsoleSandbox({
  csrfMetaToken: 'csrf-notes-1',
  fetchHandler: async (url) => {
    if (url === '/api/v1/live/campaigns') {
      return makeJsonResponse(200, {
        flow_count: 1,
        campaign_count: 1,
        incident_count: 0,
        bridge_flow_count: 0,
        campaigns: [{
          campaign_id: 'cmp-note',
          member_count: 1,
          flows: [{
            flow_id: 1,
            decision: 'Attack',
            score: 0.93,
            src_entity_id: '172.29.0.10',
            dst_entity_id: '172.29.0.20',
            service_or_port: '80',
            flow_protocol: 'tcp',
            case_title: 'T1046 Probe'
          }]
        }],
        incidents: []
      });
    }
    if (url === '/api/v1/live/notes') {
      if (failNextNote) {
        return makeJsonResponse(400, { evidence_state: 'unavailable', error: 'note_rejected' });
      }
      return makeJsonResponse(200, { evidence_state: 'verified', flow_id: 1 });
    }
    return makeJsonResponse(200, {});
  }
});

await api.refreshLiveCampaigns({ force: true });
assert.strictEqual(api.selectedLiveFlowId(), 1);
doc.getElementById('operatorActor').value = 'soc_approver_1';
doc.getElementById('analystNoteText').value = 'Confirmed SYN burst from 172.29.0.10';

await api.saveLiveAnalystNote();

const postCall = fetchCalls.find((c) => c.url === '/api/v1/live/notes');
assert(postCall && postCall.method === 'POST', 'expected POST /api/v1/live/notes');
const sent = JSON.parse(postCall.body);
assert.strictEqual(sent.flow_id, 1);
assert.strictEqual(sent.author_id, 'soc_approver_1');
assert.strictEqual(sent.note_text, 'Confirmed SYN burst from 172.29.0.10');

const banner = doc.getElementById('actionStatusBanner');
const liveStatus = doc.getElementById('liveQueueStatus');
assert.strictEqual(banner.textContent, 'Analyst note saved for flow 1.');
assert.strictEqual(banner.getAttribute('data-evidence-state'), 'verified');
assert.strictEqual(liveStatus.textContent, 'Analyst note saved for flow 1.');
assert.strictEqual(liveStatus.getAttribute('data-evidence-state'), 'verified');

failNextNote = true;
await api.saveLiveAnalystNote();
assert.strictEqual(banner.textContent, 'note_rejected');
assert.strictEqual(banner.getAttribute('data-evidence-state'), 'unavailable');
assert.strictEqual(liveStatus.textContent, 'note_rejected');
assert.strictEqual(liveStatus.getAttribute('data-evidence-state'), 'unavailable');
""")


def test_js_harness_set_dnn_badge_benign_probability_math() -> None:
    """Verify setDnnBadge formats Benign (1 - p) * 100 and Attack top class correctly."""
    _run_node_harness(r"""
const { doc, api } = buildConsoleSandbox();
const badge = doc.getElementById('flowDnnBadge');

api.setDnnBadge({ decision: 'Benign', dnnAttackProbability: 0.002 });
assert.strictEqual(badge.textContent, 'PyTorch DNN (9-Class): Normal (99.8%)');

api.setDnnBadge({
  decision: 'Attack',
  dnnAttackProbability: 0.912,
  topAttackClass: 'Reconnaissance',
  topAttackProbability: 0.85
});
assert.strictEqual(
  badge.textContent,
  'PyTorch DNN (9-Class): Attack 91.2% · Top: Reconnaissance (85.0%)'
);
""")


def test_js_harness_what_if_perturbed_isolation() -> None:
    """Verify renderVisualObservatory(perturbed) never overwrites live incident topAttackClass or #flowDnnBadge."""
    _run_node_harness(r"""
const { doc, api } = buildConsoleSandbox({
  fetchHandler: async (url) => {
    if (url === '/api/v1/live/campaigns') {
      return makeJsonResponse(200, {
        flow_count: 1,
        campaign_count: 1,
        incident_count: 0,
        bridge_flow_count: 0,
        campaigns: [{
          campaign_id: 'cmp-whatif',
          member_count: 1,
          flows: [{
            flow_id: 1,
            decision: 'Attack',
            score: 0.91,
            dnn_attack_probability: 0.88,
            top_attack_class: 'Reconnaissance',
            top_attack_probability: 0.81,
            src_entity_id: '172.29.0.10',
            dst_entity_id: '172.29.0.20',
            service_or_port: '80',
            flow_protocol: 'tcp',
            case_title: 'T1046 Reconnaissance'
          }]
        }],
        incidents: []
      });
    }
    return makeJsonResponse(200, {});
  }
});

await api.refreshLiveCampaigns({ force: true });
const badge = doc.getElementById('flowDnnBadge');
assert(badge.textContent.includes('Reconnaissance'), 'initial badge should show Reconnaissance');

api.renderVisualObservatory({
  flow_id: 1,
  perturbed: {
    top_attack_class: 'Worms',
    top_attack_probability: 0.99,
    rf_attack_probability: 0.99,
    ae_loss: 0.5,
    dnn_attack_probability: 0.99
  }
});

assert(badge.textContent.includes('Reconnaissance'), 'perturbed payload must not overwrite #flowDnnBadge');
assert(!badge.textContent.includes('Worms'), 'perturbed class Worms must not leak into #flowDnnBadge');

// Re-select Flow #1 row via DOM click to confirm stored incident.topAttackClass stayed 'Reconnaissance'
const firstRow = doc.getElementById('incidentQueueList').children[0];
assert(firstRow, 'expected Flow #1 row in #incidentQueueList');
firstRow.click();
await flushMicrotasks();
assert(badge.textContent.includes('Reconnaissance'), 'stored live incident topAttackClass must remain Reconnaissance');
assert(!badge.textContent.includes('Worms'));
""")


def test_js_harness_async_sequence_race_guard() -> None:
    """Verify out-of-order advisoryTrace/copilot responses and patchCopilotSectionFive guard stale flow IDs."""
    # Part A: Out-of-order async responses on verbatim unmodified soc_dashboard.js
    _run_node_harness(r"""
const trace1 = createDeferred();
const trace2 = createDeferred();
const copilot1 = createDeferred();
const copilot2 = createDeferred();

const flow1Raw = {
  flow_id: 1,
  decision: 'Attack',
  score: 0.91,
  src_entity_id: '172.29.0.10',
  dst_entity_id: '172.29.0.20',
  service_or_port: '80',
  flow_protocol: 'tcp',
  case_title: 'Flow1 Alpha',
  scenario_label: 'T1046'
};
const flow2Raw = {
  flow_id: 2,
  decision: 'Attack',
  score: 0.95,
  src_entity_id: '172.29.0.11',
  dst_entity_id: '172.29.0.20',
  service_or_port: '443',
  flow_protocol: 'tcp',
  case_title: 'Flow2 Beta',
  scenario_label: 'T1190'
};

const { doc, api } = buildConsoleSandbox({
  fetchHandler: async (url, init) => {
    if (url === '/api/v1/live/campaigns') {
      return makeJsonResponse(200, {
        flow_count: 2,
        campaign_count: 1,
        incident_count: 0,
        bridge_flow_count: 0,
        campaigns: [{ campaign_id: 'cmp-race', member_count: 2, flows: [flow1Raw, flow2Raw] }],
        incidents: []
      });
    }
    if (url.includes('/api/v1/live/advisory-trace?flow_id=1')) return trace1.promise;
    if (url.includes('/api/v1/live/advisory-trace?flow_id=2')) return trace2.promise;
    if (url === '/api/v1/live/copilot') {
      const payload = JSON.parse((init && init.body) || '{}');
      return payload.flow_id === 1 ? copilot1.promise : copilot2.promise;
    }
    return makeJsonResponse(200, {});
  }
});

await api.refreshLiveCampaigns({ force: true });
const inc1 = {
  id: 'live_flow:1',
  live: true,
  flowId: 1,
  flow_id: 1,
  decision: 'Attack',
  uncalibratedScore: 0.91,
  scenarioLabel: 'T1046',
  provenance: { srcIp: '172.29.0.10', dstIp: '172.29.0.20', dstPort: 80, proto: 'tcp' },
  advisory: { summaryHeadline: 'Flow1 Alpha' }
};
const inc2 = {
  id: 'live_flow:2',
  live: true,
  flowId: 2,
  flow_id: 2,
  decision: 'Attack',
  uncalibratedScore: 0.95,
  scenarioLabel: 'T1190',
  provenance: { srcIp: '172.29.0.11', dstIp: '172.29.0.20', dstPort: 443, proto: 'tcp' },
  advisory: { summaryHeadline: 'Flow2 Beta' }
};

api.selectInvestigation(inc1);
api.selectInvestigation(inc2);
assert.strictEqual(api.selectedLiveFlowId(), 2);

// Resolve Flow #2 first
trace2.resolve(makeJsonResponse(200, {
  completeness_badge: 'COMPLETE',
  authority: { decision_writes_by_advisory_components: 0, frozen_rf_verdict: 'Attack', gate_g9: 'PASS' },
  components: [{ component_id: 'cmp2', display_name: 'Flow2Component', assigned_scope: 'advisory', actual_output: 'ok', evidence_ids_read: ['flow:2'], measurement_integrity: 'verified' }]
}));
copilot2.resolve(makeJsonResponse(200, {
  flow_id: 2,
  provider: 'local_air_gapped',
  evidence_state: 'verified',
  narrative: '[1] VERDICT\nFlow2 Beta T1190 on 172.29.0.11 Attack\n\n[5] GOVERNED SOAR PLAYBOOK & CONTAINMENT GUIDANCE\n**Containment stays unauthorized.**'
}));
await flushMicrotasks();

assert(doc.getElementById('advisoryTraceBody').innerHTML.includes('Flow2Component'));
assert(doc.getElementById('liveCopilotAnswer').innerHTML.includes('Flow2 Beta'));

// Resolve stale Flow #1 late
trace1.resolve(makeJsonResponse(200, {
  completeness_badge: 'PARTIAL',
  authority: { decision_writes_by_advisory_components: 0, frozen_rf_verdict: 'Attack', gate_g9: 'PASS' },
  components: [{ component_id: 'cmp1', display_name: 'StaleFlow1Component', assigned_scope: 'advisory', actual_output: 'stale', evidence_ids_read: ['flow:1'], measurement_integrity: 'stale' }]
}));
copilot1.resolve(makeJsonResponse(200, {
  flow_id: 1,
  provider: 'local_air_gapped',
  evidence_state: 'verified',
  narrative: '[1] VERDICT\nStaleFlow1 Alpha T1046 on 172.29.0.10 Attack'
}));
await flushMicrotasks();

const traceHtml = doc.getElementById('advisoryTraceBody').innerHTML;
assert(traceHtml.includes('Flow2Component'), 'Flow #2 advisory trace must stay active');
assert(!traceHtml.includes('StaleFlow1Component'), 'stale Flow #1 trace must be dropped');
assert.strictEqual(doc.getElementById('advisoryCompletenessPill').textContent, 'COMPLETE');

const copilotHtml = doc.getElementById('liveCopilotAnswer').innerHTML;
assert(copilotHtml.includes('Flow2 Beta'), 'Flow #2 copilot brief must stay active');
assert(!copilotHtml.includes('StaleFlow1'), 'stale Flow #1 copilot brief must be dropped');
""")

    # Part B: Explicit patchCopilotSectionFive(999, 'approved') guard when Flow #1 is active
    _run_node_harness(r"""
const { doc, api } = buildConsoleSandbox({
  exportPatchCopilotSectionFive: true,
  fetchHandler: async (url) => {
    if (url === '/api/v1/live/campaigns') {
      return makeJsonResponse(200, {
        flow_count: 1,
        campaign_count: 1,
        incident_count: 0,
        bridge_flow_count: 0,
        campaigns: [{
          campaign_id: 'cmp-patch',
          member_count: 1,
          flows: [{
            flow_id: 1,
            decision: 'Attack',
            score: 0.91,
            src_entity_id: '172.29.0.10',
            dst_entity_id: '172.29.0.20',
            service_or_port: '80',
            flow_protocol: 'tcp',
            case_title: 'Flow1 Guarded',
            scenario_label: 'T1046'
          }]
        }],
        incidents: []
      });
    }
    if (url === '/api/v1/live/copilot') {
      return makeJsonResponse(200, {
        flow_id: 1,
        provider: 'local_air_gapped',
        evidence_state: 'verified',
        narrative: '[1] VERDICT\nFlow1 Guarded T1046 on 172.29.0.10 Attack\n\n[5] GOVERNED SOAR PLAYBOOK & CONTAINMENT GUIDANCE\n**Containment stays unauthorized.**'
      });
    }
    return makeJsonResponse(200, {});
  }
});

await api.refreshLiveCampaigns({ force: true });
api.selectInvestigation({
  id: 'live_flow:1',
  live: true,
  flowId: 1,
  flow_id: 1,
  decision: 'Attack',
  uncalibratedScore: 0.91,
  scenarioLabel: 'T1046',
  provenance: { srcIp: '172.29.0.10', dstIp: '172.29.0.20', dstPort: 80, proto: 'tcp' },
  advisory: { summaryHeadline: 'Flow1 Guarded' }
});
await flushMicrotasks();

const answer = doc.getElementById('liveCopilotAnswer');
const beforeHtml = answer.innerHTML;
const beforeText = answer.textContent;
assert(beforeText.includes('Containment stays unauthorized.'), 'baseline section 5 should be present');
assert.strictEqual(api.selectedLiveFlowId(), 1);

api.patchCopilotSectionFive(999, 'approved');
assert.strictEqual(answer.innerHTML, beforeHtml, 'patchCopilotSectionFive(999) must NOT mutate #liveCopilotAnswer');
assert.strictEqual(answer.textContent, beforeText);

api.patchCopilotSectionFive(1, 'approved');
assert(answer.innerHTML.includes('Playbook approved.'), 'matching flowId=1 should update section 5');
""")


def test_js_harness_endpoint_scoping_firewall_rbac_guard_403_and_ledger_fence_pill() -> None:
    """Verify isMissingEndpoint, 172.29.0.10 scoping, paintSessionIdentity guard, 403 telemetry, and ledger pill."""
    _run_node_harness(r"""
let telemetryStatus = 200;
let loginRole = 'tier1_triage';

const benignRow = {
  flow_id: 10,
  decision: 'Benign',
  score: 0.05,
  src_entity_id: '172.29.0.10',
  dst_entity_id: '172.29.0.20',
  service_or_port: '80',
  flow_protocol: 'tcp',
  source_label: 'suricata_bridge',
  case_title: 'Benign healthcheck'
};
const unswRow = {
  flow_id: 11,
  decision: 'Attack',
  score: 0.89,
  src_entity_id: 'dataset_flow:11',
  dst_entity_id: 'dataset_flow:11',
  service_or_port: '80',
  flow_protocol: 'tcp',
  source_label: 'recorded_unsw_nb15',
  case_title: 'UNSW Recorded Flow 11'
};
const attackNotDispatched = {
  flow_id: 12,
  decision: 'Attack',
  score: 0.93,
  src_entity_id: '172.29.0.10',
  dst_entity_id: '172.29.0.20',
  service_or_port: '80',
  flow_protocol: 'tcp',
  source_label: 'suricata_bridge',
  execution_path: 'not dispatched',
  callback_recorded: false,
  audit_chain_verified: false,
  case_title: 'Live Attack Undispatched'
};
const attackDispatched = {
  flow_id: 13,
  decision: 'Attack',
  score: 0.96,
  src_entity_id: '172.29.0.10',
  dst_entity_id: '172.29.0.20',
  service_or_port: '80',
  flow_protocol: 'tcp',
  source_label: 'suricata_bridge',
  execution_path: 'n8n_live_container',
  callback_recorded: true,
  audit_chain_verified: true,
  entry_sha256: 'a'.repeat(64),
  evidence_locker: {
    evidence_state: 'verified',
    queries: [{ query_id: 'correlated_campaign_soar_ledger', stitched_flow_count: 1, soar_receipt_status: 'verified' }]
  },
  case_title: 'Live Attack Dispatched'
};

const { doc, api } = buildConsoleSandbox({
  csrfMetaToken: 'csrf-ent-1',
  fetchHandler: async (url) => {
    if (url === '/api/v1/live/campaigns') {
      return makeJsonResponse(200, {
        flow_count: 4,
        campaign_count: 1,
        incident_count: 0,
        bridge_flow_count: 3,
        campaigns: [{
          campaign_id: 'cmp-ent',
          member_count: 4,
          flows: [benignRow, unswRow, attackNotDispatched, attackDispatched]
        }],
        incidents: []
      });
    }
    if (url === '/api/v1/live/range/telemetry') {
      if (telemetryStatus === 403) {
        return makeJsonResponse(403, { error: 'forbidden', reason: 'role_insufficient' });
      }
      return makeJsonResponse(200, { evidence_state: 'verified', containment_state: 'clear' });
    }
    if (url === '/api/rbac/login') {
      return makeJsonResponse(200, {
        authenticated: true,
        actor_id: loginRole === 'tier1_triage' ? 'tier1_analyst' : 'lab_operator',
        role: loginRole,
        display_name: loginRole === 'tier1_triage' ? 'Tier-1 Analyst' : 'Tier-3 SOC Approver',
        csrf_token: 'csrf-' + loginRole
      });
    }
    return makeJsonResponse(200, {});
  }
});

// 1. isMissingEndpoint
assert.strictEqual(api.isMissingEndpoint('stored-incident'), true);
assert.strictEqual(api.isMissingEndpoint('172.29.0.10'), false);

// 2. showStoredContainment and renderRangeFirewall do NOT leak 172.29.0.10 blocked badge onto Benign or UNSW rows
await api.refreshLiveCampaigns({ force: true });
const applied172Views = [{ containmentState: 'applied', provenance: { srcIp: '172.29.0.10' } }];
const probe172Blocked = {
  evidence_state: 'verified',
  reachability_probe: {
    local_drop_active: true,
    azure_drop_active: true,
    badge: 'CONTAINMENT APPLIED — Source 172.29.0.10 blocked at Azure & Local firewall (iptables DROP active).'
  }
};

// Benign row selected
api.selectInvestigation({
  id: 'live_flow:10',
  live: true,
  flowId: 10,
  decision: 'Benign',
  uncalibratedScore: 0.05,
  sourceLabel: 'suricata_bridge',
  provenance: { srcIp: '172.29.0.10', dstIp: '172.29.0.20', dstPort: 80, proto: 'tcp' }
});
api.showStoredContainment(applied172Views);
api.renderRangeFirewall(probe172Blocked);
const rangeBadge = doc.getElementById('rangeConnectivityBadge');
assert(!rangeBadge.textContent.includes('172.29.0.10 blocked'), 'Benign row must not show 172.29.0.10 blocked badge');
assert(!rangeBadge.textContent.includes('BLOCKED'), 'Benign row must stay disabled, not BLOCKED');

// UNSW row selected
api.selectInvestigation({
  id: 'live_flow:11',
  live: true,
  flowId: 11,
  decision: 'Attack',
  uncalibratedScore: 0.89,
  sourceLabel: 'recorded_unsw_nb15',
  provenance: { srcIp: '', dstIp: '', dstPort: 80, proto: 'tcp' }
});
api.showStoredContainment(applied172Views);
api.renderRangeFirewall(probe172Blocked);
assert(!rangeBadge.textContent.includes('172.29.0.10'), 'UNSW row must not show 172.29.0.10 badge');
assert(!rangeBadge.textContent.includes('BLOCKED'), 'UNSW row must not show BLOCKED');

// Attack 172.29.0.10 row selected -> should display blocked badge
api.selectInvestigation({
  id: 'live_flow:12',
  live: true,
  flowId: 12,
  decision: 'Attack',
  uncalibratedScore: 0.93,
  sourceLabel: 'suricata_bridge',
  executionPath: 'not dispatched',
  callbackRecorded: false,
  soarAuditChainVerified: false,
  provenance: { srcIp: '172.29.0.10', dstIp: '172.29.0.20', dstPort: 80, proto: 'tcp' }
});
api.renderRangeFirewall(probe172Blocked);
assert(rangeBadge.textContent.includes('172.29.0.10 blocked'), 'Attack 172.29.0.10 row should reflect blocked probe');

// 3. paintSessionIdentity calls applyContainmentGuard so switching back to soc_approver re-disables unapproved Step 3/4 buttons
loginRole = 'tier1_triage';
await api.submitRbacLogin(false);
await flushMicrotasks();
assert.strictEqual(doc.getElementById('btnContainRange').disabled, false, 'tier1 enables affordance button');
assert.strictEqual(doc.getElementById('btnRollbackRange').disabled, false);

loginRole = 'soc_approver';
await api.submitRbacLogin(false);
await flushMicrotasks();
assert.strictEqual(doc.getElementById('approvePlaybookBtn').disabled, false, 'Step 1 stays enabled on Attack row');
assert.strictEqual(doc.getElementById('btnIsolateAttacker').disabled, true, 'Step 3 must be re-disabled for unapproved flow');
assert.strictEqual(doc.getElementById('btnContainRange').disabled, true, 'Step 3 contain must be re-disabled for unapproved flow');
assert.strictEqual(doc.getElementById('btnRollbackRange').disabled, true, 'Step 4 rollback must be re-disabled for unapproved flow');

// Also verify direct paintSessionIdentity() call enforces applyContainmentGuard
doc.getElementById('btnContainRange').disabled = false;
doc.getElementById('btnRollbackRange').disabled = false;
api.paintSessionIdentity({ authenticated: true, actor_id: 'lab_operator', role: 'soc_approver', display_name: 'Tier-3 SOC Approver' });
assert.strictEqual(doc.getElementById('btnContainRange').disabled, true);
assert.strictEqual(doc.getElementById('btnRollbackRange').disabled, true);

// 4. loadEnterpriseControls with HTTP 403 on /api/v1/live/range/telemetry sets data-evidence-state === 'unavailable'
telemetryStatus = 403;
await api.loadEnterpriseControls();
const fwStatus = doc.getElementById('rangeFirewallStatus');
assert.strictEqual(fwStatus.getAttribute('data-evidence-state'), 'unavailable', 'HTTP 403 must mark #rangeFirewallStatus unavailable');

// 5. renderLedgerFencePill: Telemetry Grounded vs Ledger Verified
const traceEnvelope = {
  ledger_verification: { status: 'VERIFIED' },
  evidence_envelope: { envelope_sha256: 'b'.repeat(64) }
};
const rowForFlow12 = doc.getElementById('incidentQueueList').children.find((r) => r.dataset.id === 'live_flow:12');
const rowForFlow13 = doc.getElementById('incidentQueueList').children.find((r) => r.dataset.id === 'live_flow:13');
assert(rowForFlow12 && rowForFlow13, 'expected rows for flow 12 and flow 13');
// Select flow 12 (execution_path: 'not dispatched', callback_recorded: false)
rowForFlow12.click();
await flushMicrotasks();
assert.strictEqual(api.selectedLiveFlowId(), 12);
api.renderLedgerFencePill(traceEnvelope);
const pill = doc.getElementById('ledgerFencePill');
assert.strictEqual(pill.textContent, 'Telemetry Grounded · Fence Active');
assert.strictEqual(pill.getAttribute('data-ledger-status'), 'verified');

// Select flow 13 (callback_recorded: true, execution_path: 'n8n_live_container', verified chain)
rowForFlow13.click();
await flushMicrotasks();
assert.strictEqual(api.selectedLiveFlowId(), 13);
api.renderLedgerFencePill(traceEnvelope);
assert.strictEqual(pill.textContent, 'Ledger Verified · Fence Active');
assert.strictEqual(pill.getAttribute('data-ledger-status'), 'verified');
""")


def test_js_harness_keyboard_accessibility_tr_enter_and_copy_button() -> None:
    """Verify appendIncidentItem sets tabIndex=0 and triggers selection on Enter except inside .copy-incident-id."""
    _run_node_harness(r"""
const { doc, sandbox, api } = buildConsoleSandbox({
  fetchHandler: async (url) => {
    if (url === '/api/v1/live/campaigns') {
      return makeJsonResponse(200, {
        flow_count: 2,
        campaign_count: 1,
        incident_count: 0,
        bridge_flow_count: 0,
        campaigns: [{
          campaign_id: 'cmp-a11y',
          member_count: 2,
          flows: [
            { flow_id: 1, decision: 'Attack', score: 0.91, src_entity_id: '172.29.0.10', dst_entity_id: '172.29.0.20', service_or_port: '80', flow_protocol: 'tcp', case_title: 'Flow 1 Selected' },
            { flow_id: 2, decision: 'Attack', score: 0.92, src_entity_id: '172.29.0.11', dst_entity_id: '172.29.0.20', service_or_port: '443', flow_protocol: 'tcp', case_title: 'Flow 2 Target' }
          ]
        }],
        incidents: []
      });
    }
    return makeJsonResponse(200, {});
  }
});

await api.refreshLiveCampaigns({ force: true });
assert.strictEqual(api.selectedLiveFlowId(), 1);

const tbody = doc.createElement('tbody');
const flow2 = {
  id: 'live_flow:2',
  live: true,
  flowId: 2,
  flow_id: 2,
  observedAt: '2026-11-26T12:00:00Z',
  decision: 'Attack',
  uncalibratedScore: 0.92,
  sourceLabel: 'suricata_bridge',
  provenance: { srcIp: '172.29.0.11', dstIp: '172.29.0.20', dstPort: 443, proto: 'tcp' },
  advisory: { summaryHeadline: 'Flow 2 Target' }
};
api.appendIncidentItem(tbody, flow2);
const tr = tbody.children[0];
assert(tr, 'appendIncidentItem must create a <tr>');
assert.strictEqual(tr.tabIndex, 0, 'incident row must have tabIndex = 0');

// Enter inside .copy-incident-id must NOT trigger row selection
const copyBtn = tr.querySelector('.copy-incident-id');
assert(copyBtn, 'expected .copy-incident-id button inside row');
const copyEnterEvt = new sandbox.Event('keydown', { key: 'Enter', bubbles: true, cancelable: true });
copyBtn.dispatchEvent(copyEnterEvt);
assert.strictEqual(api.selectedLiveFlowId(), 1, 'Enter on .copy-incident-id must be ignored by row selection');

// Enter directly on <tr> MUST call preventDefault() and select Flow #2
const rowEnterEvt = new sandbox.Event('keydown', { key: 'Enter', bubbles: true, cancelable: true });
tr.dispatchEvent(rowEnterEvt);
assert.strictEqual(rowEnterEvt.defaultPrevented, true, 'Enter on row must preventDefault');
assert.strictEqual(api.selectedLiveFlowId(), 2, 'Enter on row must select Flow #2');
assert.strictEqual(doc.getElementById('inspectorCaseTitle').textContent, 'Flow 2 Target');
""")


def test_js_harness_init_app_dom_content_loaded_and_pageerrors_zero() -> None:
    """Verify full DOMContentLoaded -> initApp() boot and listener wiring with zero pageerrors."""
    _run_node_harness(r"""
const { doc, sandbox, api, fetchCalls } = buildConsoleSandbox({
  csrfMetaToken: 'csrf-boot-1',
  fetchHandler: async (url) => {
    if (url === '/api/rbac/session') {
      return makeJsonResponse(200, {
        authenticated: true,
        actor_id: 'lab_operator',
        role: 'soc_approver',
        display_name: 'Tier-3 SOC Approver',
        csrf_token: 'csrf-boot-1'
      });
    }
    if (url === '/api/v1/live/posture') {
      return makeJsonResponse(200, { environment: 'lab', posture_label: 'POSTURE: LAB DEMO' });
    }
    if (url === '/api/v1/live/campaigns') {
      return makeJsonResponse(200, {
        flow_count: 1,
        campaign_count: 1,
        incident_count: 0,
        bridge_flow_count: 0,
        campaigns: [{
          campaign_id: 'cmp-boot',
          member_count: 1,
          flows: [{
            flow_id: 1,
            decision: 'Attack',
            score: 0.91,
            src_entity_id: '172.29.0.10',
            dst_entity_id: '172.29.0.20',
            service_or_port: '80',
            flow_protocol: 'tcp',
            case_title: 'Boot Flow 1'
          }]
        }],
        incidents: []
      });
    }
    if (url === '/api/v1/live/notes') {
      return makeJsonResponse(200, { evidence_state: 'verified', flow_id: 1 });
    }
    return makeJsonResponse(200, {});
  }
});

doc.dispatchEvent(new sandbox.Event('DOMContentLoaded'));
await flushMicrotasks(20);
assert.strictEqual(api.selectedLiveFlowId(), 1);
assert.strictEqual(doc.body.classList.contains('console-locked'), false);

doc.getElementById('analystNoteText').value = 'Boot listener check';
doc.getElementById('btnSaveAnalystNote').click();
await flushMicrotasks(10);
const notePost = fetchCalls.find((c) => c.url === '/api/v1/live/notes' && c.method === 'POST');
assert(notePost, 'click on #btnSaveAnalystNote wired by initApp must post /api/v1/live/notes');
assert.strictEqual(JSON.parse(notePost.body).flow_id, 1);
assert.strictEqual(doc.getElementById('actionStatusBanner').getAttribute('data-evidence-state'), 'verified');
""")


def test_draft_detection_rule_deduplicates_t1046_prefix_in_suricata_msg() -> None:
    """Verify telemetry_shield.draft_detection_rule deduplicates T1046 T1046 in Suricata msg:."""
    draft_from_query = draft_detection_rule(
        query="T1046 Network Service Discovery",
        flow_record={"technique_id": "T1046", "proto": "tcp", "dst_port": 80},
        rule_format="both",
    )
    suricata_query = draft_from_query["suricata"]
    assert 'msg:"THREATFUSION T1046 Network Service Discovery"' in suricata_query
    assert "T1046 T1046" not in suricata_query

    draft_from_vector = draft_detection_rule(
        query="Hunt T1046",
        flow_record={
            "technique_id": "T1046",
            "vector": "T1046 - T1046: Network Service Discovery",
            "proto": "tcp",
            "dst_port": 80,
        },
        rule_format="both",
    )
    suricata_vector = draft_from_vector["suricata"]
    assert 'msg:"THREATFUSION T1046 Network Service Discovery"' in suricata_vector
    assert "T1046 T1046" not in suricata_vector
