/**
 * CSV Prompt Signature Loader
 *
 * Parses malicious_prompts.csv and converts each prompt row into a
 * precise regex-based rule signature compatible with the RULE_SIGNATURES array
 * in guardrailService.js.
 *
 * CSV Schema: id, prompt, label, attack_type, context, response
 */

const fs   = require('fs');
const path = require('path');

// ── Attack type → severity mapping ──────────────────────────────────────────
const ATTACK_SEVERITY_MAP = {
  jailbreaking:   'CRITICAL',
  role_playing:   'CRITICAL',
  code_execution: 'CRITICAL',
  data_leakage:   'CRITICAL',
  obfuscation:    'HIGH',
  sql_injection:  'CRITICAL',
};

// ── Words/Tokens common in legitimate programming code — NEVER match these alone ──
const PROGRAMMING_KEYWORDS = new Set([
  'import','class','public','private','protected','static','void','int','double','float',
  'boolean','string','char','long','short','byte','return','if','else','for','while','do',
  'new','try','catch','finally','throw','throws','package','extends','implements','super',
  'this','final','const','let','var','def','function','struct','auto','using','namespace',
  'include','std','vector','map','set','list','hashmap','arraylist','queue','stack','deque',
  'len','range','print','cout','cin','console','log','null','nil','true','false','none'
]);

const REGEX_SPECIAL = /[.*+?^${}()|[\]\\]/g;

function escapeRegex(str) {
  return str.replace(REGEX_SPECIAL, '\\$&');
}

/**
 * Clean prompt wrapper prefixes like "Execute: `...`", "Run: `...`", "Bypass: `...`"
 */
function extractCorePayload(promptText) {
  let cleaned = promptText.trim();

  // Strip prefixes like "Execute: ", "Run: ", "Bypass: ", "Decode and run: ", "As a pentester... "
  cleaned = cleaned.replace(/^(execute|run|bypass|decode and run|as a \w+[^:]*:)\s*/i, '');

  // Strip surrounding quotes / backticks
  cleaned = cleaned.replace(/^[`"']+|[`"']+$/g, '').trim();

  return cleaned;
}

/**
 * Build a precise regex from a malicious prompt text.
 */
function buildRuleFromPrompt(promptText, attackType, id) {
  const core = extractCorePayload(promptText);
  if (!core || core.length < 3) return null;

  // 1. Non-ASCII characters (Chinese, Arabic, Russian, Japanese, etc.)
  if (/[^\x00-\x7F]/.test(core)) {
    return {
      regex: new RegExp(escapeRegex(core), 'i'),
      label: `CSV:${id}:${attackType}`,
      severity: ATTACK_SEVERITY_MAP[attackType] || 'CRITICAL'
    };
  }

  // 2. Check if core payload is purely a single standard programming keyword or code fragment (e.g. "import java...")
  const words = core.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter(Boolean);
  if (words.length === 1 && PROGRAMMING_KEYWORDS.has(words[0])) {
    return null; // Skip single programming keywords
  }

  // 3. For obfuscations like "whoami | gzip", "atob(...)", "echo 'whoami' | rot13", "rot13", "hex: 726d20..."
  // If prompt has distinct attack terms or command patterns, build an exact core regex:
  const escaped = escapeRegex(core);

  return {
    regex: new RegExp(escaped, 'i'),
    label: `CSV:${id}:${attackType}`,
    severity: ATTACK_SEVERITY_MAP[attackType] || 'CRITICAL'
  };
}

/**
 * Load and parse the malicious_prompts.csv.
 */
function loadCSVSignatures(csvPath) {
  const resolved = csvPath || path.join(__dirname, 'malicious_prompts.csv');

  if (!fs.existsSync(resolved)) {
    console.warn(`[CSVSignatureLoader] File not found: ${resolved}. Skipping CSV rules.`);
    return [];
  }

  const raw   = fs.readFileSync(resolved, 'utf-8');
  const lines = raw.split(/\r?\n/);

  if (lines.length < 2) return [];

  const header = lines[0].split(',');
  const colIdx = {
    id:          header.indexOf('id'),
    prompt:      header.indexOf('prompt'),
    label:       header.indexOf('label'),
    attack_type: header.indexOf('attack_type'),
  };

  const rules = [];
  const seenLabels = new Set();

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    const cols = parseCsvLine(line);
    if (cols.length < 4) continue;

    const label      = (cols[colIdx.label]       || '').trim().toLowerCase();
    const attackType = (cols[colIdx.attack_type]  || '').trim().toLowerCase();
    const promptText = (cols[colIdx.prompt]       || '').trim();
    const id         = (cols[colIdx.id]           || `csv-${i}`).trim();

    if (label !== 'malicious' || !promptText) continue;

    // Build rule for original full prompt AND core payload
    const ruleObjCore = buildRuleFromPrompt(promptText, attackType, id);
    if (ruleObjCore && !seenLabels.has(ruleObjCore.label)) {
      seenLabels.add(ruleObjCore.label);
      rules.push(ruleObjCore);
    }

    // Also add full raw prompt as literal regex match
    const rawEscaped = escapeRegex(promptText.trim());
    const rawLabel = `CSV-RAW:${id}:${attackType}`;
    if (!seenLabels.has(rawLabel)) {
      seenLabels.add(rawLabel);
      rules.push({
        regex: new RegExp(rawEscaped, 'i'),
        label: rawLabel,
        severity: ATTACK_SEVERITY_MAP[attackType] || 'CRITICAL'
      });
    }
  }

  console.log(`[CSVSignatureLoader] Loaded ${rules.length} rules from ${path.basename(resolved)}`);
  return rules;
}

/**
 * Minimal RFC-4180-compatible CSV line parser.
 */
function parseCsvLine(line) {
  const result  = [];
  let current   = '';
  let inQuotes  = false;

  for (let ci = 0; ci < line.length; ci++) {
    const ch = line[ci];

    if (ch === '"') {
      if (inQuotes && line[ci + 1] === '"') {
        current += '"';
        ci++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += ch;
    }
  }

  result.push(current);
  return result;
}

module.exports = { loadCSVSignatures };
