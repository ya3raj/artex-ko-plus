import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { parse } from '@formatjs/icu-messageformat-parser';
import { DEFAULT_LOCALE, LOCALES, resolveLocale } from '../src/i18n/config.ts';
const read = (locale) => JSON.parse(readFileSync(new URL(`../messages/${locale}.json`, import.meta.url), 'utf8'));
function flatten(value, prefix = '', result = {}) {
  for (const [key, child] of Object.entries(value)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (typeof child === 'string') result[path] = child;
    else flatten(child, path, result);
  }
  return result;
}
function contract(nodes, result = []) {
  for (const node of nodes) {
    if (node.type > 0) result.push([node.type, node.value, node.offset, node.pluralType, node.options && Object.keys(node.options).sort()]);
    if (node.options) for (const key of Object.keys(node.options).sort()) contract(node.options[key].value, result);
    if (node.children) contract(node.children, result);
  }
  return result.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}
const korean = flatten(read('ko'));
const english = flatten(read('en'));
test('English includes every UI message without untranslated Korean or Chinese', () => {
  assert.deepEqual(Object.keys(english).sort(), Object.keys(korean).sort());
  for (const [key, value] of Object.entries(english)) {
    assert.ok(!/[\uac00-\ud7af\u4e00-\u9fff]/u.test(value), `${key}: untranslated text`);
    assert.ok(!/TOKEN\d+/.test(value), `${key}: translation marker`);
  }
});
test('English retains interpolation arguments, rich-text tags, and ICU branches', () => {
  for (const [key, value] of Object.entries(korean)) {
    let original;
    try { original = parse(value); } catch { continue; } // Some original messages are literal JSON templates.
    assert.deepEqual(contract(parse(english[key])), contract(original), key);
  }
});

test('English is the default and all explicit build locales resolve correctly', () => {
  const previous = process.env.NEXT_PUBLIC_LOCALE;
  try {
    delete process.env.NEXT_PUBLIC_LOCALE;
    assert.equal(DEFAULT_LOCALE, 'en');
    assert.equal(resolveLocale(), 'en');
    for (const locale of LOCALES) {
      process.env.NEXT_PUBLIC_LOCALE = locale;
      assert.equal(resolveLocale(), locale);
    }
    process.env.NEXT_PUBLIC_LOCALE = 'unsupported';
    assert.equal(resolveLocale(), 'en');
  } finally {
    if (previous === undefined) delete process.env.NEXT_PUBLIC_LOCALE;
    else process.env.NEXT_PUBLIC_LOCALE = previous;
  }
});
