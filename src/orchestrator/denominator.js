import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/**
 * src/orchestrator/denominator.js — feature: Denominator counter / zero-dropped-cases retention
 *
 * Per spec/spec.md §Task feature [S12]:
 *   Loaded ACVP/Wycheproof JSON corpus + per-case classification from [feature]
 *   -> reports denominator == cases present in the corpus, a processed count,
 *      and retention (must be 100%, 0 dropped); empty corpus reports `Denominator=0`.
 *
 * Contract:
 *   - countCases(corpus)         -> number of test cases across all testGroups
 *   - computeDenominator(corpus) -> { denominator, processed, dropped, retention }
 *   - computeDenominator(corpus, classified) -> same with per-case labels
 *   - repeatableRead(filePath)   -> same count reading a JSON file twice
 *
 * Rules:
 *   - Every case in the corpus counts toward the denominator.
 *   - A case is "processed" if it appears in the classified list.
 *   - A case is "dropped" if it is absent from the classified list.
 *   - retention = (processed / denominator) * 100, or 100 when denominator === 0.
 *   - Zero cases may be silently dropped: retained must be 100% (0 dropped).
 *   - Empty corpus: denominator=0, processed=0, dropped=0, retention=100.
 *   - Duplicate tcIds across groups are rejected with a loud error.
 *   - tcId must exist on each test case; absent tcId triggers a loud error.
 */

export function countCases(corpus) {
  if (!corpus || typeof corpus !== 'object' || Array.isArray(corpus)) {
    throw new Error('corpus must be a JSON object');
  }
  if (!corpus.testGroups || !Array.isArray(corpus.testGroups)) {
    throw new Error('corpus must have a testGroups array');
  }
  let total = 0;
  const seenIds = new Set();
  for (const tg of corpus.testGroups) {
    if (!tg || typeof tg !== 'object' || Array.isArray(tg)) {
      throw new Error('each testGroup must be an object');
    }
    if (!tg.tests || !Array.isArray(tg.tests)) {
      throw new Error('each testGroup must have a tests array');
    }
    for (const tc of tg.tests) {
      if (!tc || typeof tc !== 'object' || Array.isArray(tc)) {
        throw new Error('each test case must be an object');
      }
      if (tc.tcId === undefined) {
        throw new Error('each test case must have a tcId');
      }
      if (seenIds.has(tc.tcId)) {
        throw new Error(`duplicate tcId found: ${tc.tcId}`);
      }
      seenIds.add(tc.tcId);
      total += 1;
    }
  }
  return total;
}

export function computeDenominator(corpus, classified) {
  if (!corpus || typeof corpus !== 'object' || Array.isArray(corpus)) {
    throw new Error('corpus must be a JSON object');
  }

  const totalCases = countCases(corpus);
  let processed = 0;
  let dropped = 0;
  const droppedTcIds = [];

  if (classified && Array.isArray(classified)) {
    const classifiedIds = new Set();
    for (const c of classified) {
      if (!c || typeof c !== 'object' || Array.isArray(c) || c.tcId === undefined) {
        continue;
      }
      classifiedIds.add(c.tcId);
      processed += 1;
    }

    // Identify dropped tcIds (in corpus but not in classified)
    const corpusTcIds = new Set();
    for (const tg of corpus.testGroups) {
      for (const tc of tg.tests) {
        corpusTcIds.add(tc.tcId);
      }
    }
    for (const tcId of corpusTcIds) {
      if (!classifiedIds.has(tcId)) {
        droppedTcIds.push(tcId);
        dropped += 1;
      }
    }
  } else {
    dropped = totalCases;
    processed = 0;
  }

  const retention = totalCases === 0 ? 100 : (processed / totalCases) * 100;

  return {
    denominator: totalCases,
    processed,
    dropped,
    retention,
    droppedTcIds,
    labels: _computeLabels(corpus, classified),
  };
}

function _computeLabels(corpus, classified) {
  const labels = {
    pass: 0,
    'documented-validation-rejection': 0,
    'unsupported-operation': 0,
    'adapter-invocation-error': 0,
  };

  if (!classified || !Array.isArray(classified)) {
    return labels;
  }

  for (const c of classified) {
    if (!c || typeof c !== 'object' || Array.isArray(c) || c.tcId === undefined) continue;
    const label = c.label;
    if (label && labels.hasOwnProperty(label)) {
      labels[label] += 1;
    }
  }

  return labels;
}

export function repeatableRead(filePath) {
  if (typeof filePath === 'string') {
    // accepted: plain string path
  } else if (filePath instanceof URL && filePath.protocol === 'file:') {
    filePath = fileURLToPath(filePath);
  } else {
    throw new Error('filePath must be a string or a file: URL');
  }

  try {
    const content = readFileSync(filePath, 'utf8');
    const data = JSON.parse(content);
    return countCases(data);
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(`ENOENT: no such file or directory: ${filePath}`);
    }
    if (err instanceof SyntaxError) {
      throw new Error(`JSON parse error in ${filePath}: ${err.message}`);
    }
    throw new Error(`cannot read ${filePath}: ${err.message}`);
  }
}