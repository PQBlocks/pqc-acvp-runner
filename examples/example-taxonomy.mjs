import { classifyResult, TAXONOMY_LABELS, summarizeTaxonomy } from '@pqblocks/pqc-acvp-runner';

const sampleCase = { tcId: 1 };
const sampleResult = {
  matches: true,
  error: null
};

const classification = classifyResult(sampleCase, sampleResult);
const summary = summarizeTaxonomy([classification]);

if (!summary[TAXONOMY_LABELS.PASS]) {
  throw new Error('Expected PASS in taxonomy summary');
}

console.log('Taxonomy classification verified successfully');
console.log('OK');
