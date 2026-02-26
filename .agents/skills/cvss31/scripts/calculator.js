/**
 * CVSS v3.1 Calculator
 * Based on FIRST.org specification: https://www.first.org/cvss/v3.1/specification-document
 * 
 * Usage: calculateCVSS(metrics) where metrics is an object with metric abbreviations as keys.
 * Returns: { baseScore, temporalScore, environmentalScore, baseSeverity, vector }
 */

// Metric numerical values
const WEIGHTS = {
  AV:  { N: 0.85, A: 0.62, L: 0.55, P: 0.20 },
  AC:  { L: 0.77, H: 0.44 },
  PR:  { 
    N: { U: 0.85, C: 0.85 }, 
    L: { U: 0.62, C: 0.68 }, 
    H: { U: 0.27, C: 0.50 } 
  },
  UI:  { N: 0.85, R: 0.62 },
  C:   { N: 0.00, L: 0.22, H: 0.56 },
  I:   { N: 0.00, L: 0.22, H: 0.56 },
  A:   { N: 0.00, L: 0.22, H: 0.56 },
  E:   { X: 1.00, U: 0.91, P: 0.94, F: 0.97, H: 1.00 },
  RL:  { X: 1.00, O: 0.95, T: 0.96, W: 0.97, U: 1.00 },
  RC:  { X: 1.00, U: 0.92, R: 0.96, C: 1.00 },
  CR:  { X: 1.00, L: 0.50, M: 1.00, H: 1.50 },
  IR:  { X: 1.00, L: 0.50, M: 1.00, H: 1.50 },
  AR:  { X: 1.00, L: 0.50, M: 1.00, H: 1.50 },
};

// Roundup function (floating-point safe per spec Appendix A)
function Roundup(input) {
  const int_input = Math.round(input * 100000);
  if (int_input % 10000 === 0) {
    return int_input / 100000.0;
  } else {
    return (Math.floor(int_input / 10000) + 1) / 10.0;
  }
}

function severityRating(score) {
  if (score === 0.0) return 'None';
  if (score < 4.0) return 'Low';
  if (score < 7.0) return 'Medium';
  if (score < 9.0) return 'High';
  return 'Critical';
}

function calculateCVSS(m) {
  // Required base metrics
  const scope = m.S;
  
  // PR depends on Scope
  const PR = WEIGHTS.PR[m.PR][scope];
  const AV = WEIGHTS.AV[m.AV];
  const AC = WEIGHTS.AC[m.AC];
  const UI = WEIGHTS.UI[m.UI];
  const C = WEIGHTS.C[m.C];
  const I = WEIGHTS.I[m.I];
  const A = WEIGHTS.A[m.A];

  // Base Score calculation
  const ISS = 1 - (1 - C) * (1 - I) * (1 - A);
  
  let impact;
  if (scope === 'U') {
    impact = 6.42 * ISS;
  } else {
    impact = 7.52 * (ISS - 0.029) - 3.25 * Math.pow(ISS - 0.02, 15);
  }

  const exploitability = 8.22 * AV * AC * PR * UI;

  let baseScore;
  if (impact <= 0) {
    baseScore = 0.0;
  } else if (scope === 'U') {
    baseScore = Roundup(Math.min(impact + exploitability, 10));
  } else {
    baseScore = Roundup(Math.min(1.08 * (impact + exploitability), 10));
  }

  // Temporal Score
  const E = WEIGHTS.E[m.E || 'X'];
  const RL = WEIGHTS.RL[m.RL || 'X'];
  const RC = WEIGHTS.RC[m.RC || 'X'];
  const temporalScore = Roundup(baseScore * E * RL * RC);

  // Environmental Score
  const CR = WEIGHTS.CR[m.CR || 'X'];
  const IR = WEIGHTS.IR[m.IR || 'X'];
  const AR = WEIGHTS.AR[m.AR || 'X'];

  // Modified metrics fall back to Base metric values
  const modScope = m.MS !== undefined && m.MS !== 'X' ? m.MS : scope;
  const MAV = m.MAV !== undefined && m.MAV !== 'X' ? WEIGHTS.AV[m.MAV] : AV;
  const MAC = m.MAC !== undefined && m.MAC !== 'X' ? WEIGHTS.AC[m.MAC] : AC;
  const MPR = m.MPR !== undefined && m.MPR !== 'X' ? WEIGHTS.PR[m.MPR][modScope] : WEIGHTS.PR[m.PR][modScope];
  const MUI = m.MUI !== undefined && m.MUI !== 'X' ? WEIGHTS.UI[m.MUI] : UI;
  const MC = m.MC !== undefined && m.MC !== 'X' ? WEIGHTS.C[m.MC] : C;
  const MI = m.MI !== undefined && m.MI !== 'X' ? WEIGHTS.I[m.MI] : I;
  const MA = m.MA !== undefined && m.MA !== 'X' ? WEIGHTS.A[m.MA] : A;

  const MISS = Math.min(
    1 - (1 - CR * MC) * (1 - IR * MI) * (1 - AR * MA),
    0.915
  );

  let modifiedImpact;
  if (modScope === 'U') {
    modifiedImpact = 6.42 * MISS;
  } else {
    modifiedImpact = 7.52 * (MISS - 0.029) - 3.25 * Math.pow(MISS * 0.9731 - 0.02, 13);
  }

  const modifiedExploitability = 8.22 * MAV * MAC * MPR * MUI;

  let environmentalScore;
  if (modifiedImpact <= 0) {
    environmentalScore = 0.0;
  } else if (modScope === 'U') {
    environmentalScore = Roundup(
      Roundup(Math.min(modifiedImpact + modifiedExploitability, 10)) * E * RL * RC
    );
  } else {
    environmentalScore = Roundup(
      Roundup(Math.min(1.08 * (modifiedImpact + modifiedExploitability), 10)) * E * RL * RC
    );
  }

  // Build vector string
  const baseVec = `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
  const temporalParts = [];
  if (m.E && m.E !== 'X') temporalParts.push(`E:${m.E}`);
  if (m.RL && m.RL !== 'X') temporalParts.push(`RL:${m.RL}`);
  if (m.RC && m.RC !== 'X') temporalParts.push(`RC:${m.RC}`);
  const envParts = [];
  ['CR','IR','AR','MAV','MAC','MPR','MUI','MS','MC','MI','MA'].forEach(k => {
    if (m[k] && m[k] !== 'X') envParts.push(`${k}:${m[k]}`);
  });
  
  const vector = [baseVec, ...temporalParts, ...envParts].join('/');

  return {
    baseScore,
    temporalScore,
    environmentalScore,
    baseSeverity: severityRating(baseScore),
    temporalSeverity: severityRating(temporalScore),
    environmentalSeverity: severityRating(environmentalScore),
    vector,
    // Sub-scores for debugging
    debug: { ISS, impact, exploitability, MISS, modifiedImpact, modifiedExploitability }
  };
}

// Parse a CVSS vector string into metrics object
function parseVector(vectorString) {
  const parts = vectorString.replace('CVSS:3.1/', '').split('/');
  const metrics = {};
  parts.forEach(part => {
    const [key, value] = part.split(':');
    metrics[key] = value;
  });
  return metrics;
}

// Example usage:
const example = calculateCVSS({
  AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H'
});
console.log(`Base Score: ${example.baseScore} ${example.baseSeverity}`);
console.log(`Vector: ${example.vector}`);
// Expected: 9.8 Critical

module.exports = { calculateCVSS, parseVector, Roundup, severityRating };
