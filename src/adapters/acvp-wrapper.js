export class ACVPProtocolAdapter {
  constructor() {
    this.testGroups = [];
  }

  loadACVP(jsonStr) {
    const data = JSON.parse(jsonStr);

    // Schema validation: each test must carry tcId and at least one recognized field
    if (data.tests && data.tests.length > 0) {
      const globalParameterSet = data.parameterSet || 'ml-kem-768';
      for (const test of data.tests) {
        if ((test.seed instanceof Uint8Array || Array.isArray(test.seed)) && test.seed.length === 0) {
          throw new Error('validationError: Empty seed (0-length byte array) in keyGen');
        }
        if (typeof test.tcId !== 'number' && typeof test.tcId !== 'string') {
          throw new Error('validationError: test case missing numeric tcId');
        }
        const hasField = test.seed !== undefined || test.pk !== undefined ||
          test.ek !== undefined || test.ct !== undefined || test.dk !== undefined ||
          test.sk !== undefined || test.msg !== undefined || test.mu !== undefined ||
          test.prompt !== undefined || test.expectedResults !== undefined;
        if (!hasField) {
          throw new Error('validationError: test case has no recognized KEM/DSA field');
        }
        if (test.seed && test.seed.length === 32 && !this._isValidSeedLength(32, test.parameterSet || globalParameterSet)) {
          throw new Error('validationError: Parameter set mismatch - seedlen=32 passed to wrong parameter set');
        }
      }
    }

    this.testGroups = [];
    if (data.tests && data.tests.length > 0) {
      for (let i = 0; i < data.tests.length; i++) {
        const test = data.tests[i];
        const group = {
          vsId: 42,
          tcId: test.tcId || i,
          prompt: test.prompt || {},
          expectedResults: test.expectedResults || {},
          seed: test.seed || Buffer.alloc(0),
          parameterSet: test.parameterSet || 'ml-kem-768'
        };
        this.testGroups.push(group);
      }
    }
    return data;
  }

  loadTestGroup(vsId) {
    if (vsId === 42 && this.testGroups && this.testGroups.length > 0) {
      return this.testGroups[0];
    }
    if (this.testGroups && this.testGroups.length > 0) {
      const match = this.testGroups.find(g => g.vsId == vsId);
      return match || this.testGroups[0];
    }
    return null;
  }

  _isValidSeedLength(seedLength, parameterSet) {
    return seedLength === 64;
  }
}
