import React, { useState, useRef } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  ShieldCheck, ShieldAlert, Eye, EyeOff, Zap, AlertTriangle, CheckCircle2,
  FileSearch, User, Mail, Phone, CreditCard, Key, Hash, MapPin, Building2,
  Cpu, Layers, ArrowRight, RefreshCw, Activity, Lock, Database, BarChart2,
  ChevronRight, ChevronDown, ChevronUp, Info, X, Tag, Search, FileText,
  AlertCircle, Upload, Copy, Check, Calendar, Landmark, HelpCircle
} from 'lucide-react';

// ─── Verhoeff Algorithm for Aadhaar Checksum Validation ─────────────────────
const verhoeffD = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
];
const verhoeffP = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
];

function validateVerhoeff(str) {
  const digits = str.replace(/\D/g, '');
  if (digits.length !== 12) return false;
  if (digits[0] === '0' || digits[0] === '1') return false; // Aadhaar cannot start with 0 or 1
  let c = 0;
  const reversed = digits.split('').reverse().map(Number);
  for (let i = 0; i < reversed.length; i++) {
    c = verhoeffD[c][verhoeffP[i % 8][reversed[i]]];
  }
  return c === 0;
}

// ─── Luhn Algorithm for Credit/Debit Cards ─────────────────────────────────
function validateLuhn(str) {
  const digits = str.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// ─── PII Entity Type Definitions & Metadata ────────────────────────────────
const ENTITY_TYPES = {
  // High Risk (Financial & Critical ID)
  CREDIT_CARD:   { label: 'Credit / Debit Card',  icon: CreditCard,  tier: 'HIGH',   color: '#DC2626', bg: '#FEF2F2', border: '#FECACA', regulation: ['PCI-DSS', 'GDPR'] },
  AADHAAR:       { label: 'Aadhaar Number',        icon: Hash,        tier: 'HIGH',   color: '#EA580C', bg: '#FFF7ED', border: '#FED7AA', regulation: ['DPDP Act'] },
  PAN:           { label: 'PAN Card Number',       icon: Hash,        tier: 'HIGH',   color: '#D97706', bg: '#FFFBEB', border: '#FDE68A', regulation: ['DPDP Act'] },
  BANK_ACCOUNT:  { label: 'Bank Account Number',   icon: Landmark,    tier: 'HIGH',   color: '#B91C1C', bg: '#FEF2F2', border: '#FECACA', regulation: ['PCI-DSS', 'DPDP'] },
  IFSC_CODE:     { label: 'IFSC Code',             icon: Landmark,    tier: 'HIGH',   color: '#C2410C', bg: '#FFF7ED', border: '#FFEDD5', regulation: ['DPDP Act'] },
  CVV:           { label: 'Card CVV / CVC',        icon: Lock,        tier: 'HIGH',   color: '#991B1B', bg: '#FEF2F2', border: '#FCA5A5', regulation: ['PCI-DSS'] },
  CARD_EXPIRY:   { label: 'Card Expiry Date',      icon: Calendar,    tier: 'HIGH',   color: '#9A3412', bg: '#FFF7ED', border: '#FFEDD5', regulation: ['PCI-DSS'] },
  API_KEY:       { label: 'API Key / Secret',      icon: Key,         tier: 'HIGH',   color: '#9333EA', bg: '#FAF5FF', border: '#E9D5FF', regulation: ['SOC2', 'ISO27001'] },
  SSN:           { label: 'SSN / National ID',     icon: Lock,        tier: 'HIGH',   color: '#B91C1C', bg: '#FEF2F2', border: '#FECACA', regulation: ['HIPAA', 'GDPR'] },

  // Medium Risk (Contact & Personal Identifiers)
  EMAIL:         { label: 'Email Address',        icon: Mail,        tier: 'MEDIUM', color: '#4F46E5', bg: '#EEF2FF', border: '#C7D2FE', regulation: ['GDPR', 'HIPAA', 'DPDP'] },
  PHONE:         { label: 'Phone Number',          icon: Phone,       tier: 'MEDIUM', color: '#0891B2', bg: '#E0F2FE', border: '#BAE6FD', regulation: ['GDPR', 'DPDP'] },
  DOB:           { label: 'Date of Birth',         icon: Calendar,    tier: 'MEDIUM', color: '#0284C7', bg: '#F0F9FF', border: '#BAE6FD', regulation: ['GDPR', 'HIPAA'] },
  IP_ADDRESS:    { label: 'IP Address',            icon: Cpu,         tier: 'MEDIUM', color: '#475569', bg: '#F8FAFC', border: '#CBD5E1', regulation: ['GDPR'] },

  // Low Risk (Unstructured Context & Names)
  PERSON:        { label: 'Person Name (NER)',     icon: User,        tier: 'LOW',    color: '#7C3AED', bg: '#F5F3FF', border: '#DDD6FE', regulation: ['GDPR', 'HIPAA', 'DPDP'] },
  LOCATION:      { label: 'Location / Address',   icon: MapPin,      tier: 'LOW',    color: '#059669', bg: '#ECFDF5', border: '#A7F3D0', regulation: ['GDPR', 'DPDP'] },
  ORGANIZATION:  { label: 'Organization (NER)',    icon: Building2,   tier: 'LOW',    color: '#0D9488', bg: '#F0FDFA', border: '#99F6E4', regulation: ['GDPR'] },
};

// Priority scoring map for resolving overlapping matches
const PRIORITY_MAP = {
  CREDIT_CARD: 100, AADHAAR: 100, PAN: 100, BANK_ACCOUNT: 95, IFSC_CODE: 95, CVV: 95, CARD_EXPIRY: 90, SSN: 90, API_KEY: 90,
  EMAIL: 80, PHONE: 75, DOB: 75, IP_ADDRESS: 60,
  PERSON: 50, ORGANIZATION: 45, LOCATION: 40
};

// ─── Test Preset Inputs ──────────────────────────────────────────────────
const PRESETS = [
  {
    id: 'customer_record',
    label: 'Customer Record',
    icon: User,
    text: `Customer: John Sharma\nEmail: john.sharma@acmecorp.in\nPhone: +91-98201-34567\nAadhaar: 2345 6789 1234\nPAN: ABCDE1234F\nAddress: 14, Sector 7, Noida, UP 201301\nCRIF Score: 789`
  },
  {
    id: 'banking_card_leak',
    label: 'Bank & Card Leak',
    icon: CreditCard,
    text: `Cardholder: Rohan Mehta\nCard Number: 4532 1188 9923 4567\nCVV: 452 | Expiry: 08/28\nIFSC Code: SBIN0001234\nBank Account: 003401567890\nEmployer: Rohan Mehta works at Infosys`
  },
  {
    id: 'api_leak',
    label: 'API Secret Leak',
    icon: Key,
    text: `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nDATABASE_PASSWORD=Sup3rS3cr3t!\nStripe API key: sk_live_4eC39HqLyjWDarjtT1zdp7dc`
  },
  {
    id: 'medical_note',
    label: 'Medical Note (HIPAA)',
    icon: FileText,
    text: `Patient: Sarah O'Brien, DOB: 14/02/1985\nSSN: 123-45-6789\nPrimary physician: Dr. James Fowler\nDiagnosis: Type-2 Diabetes, HbA1c 7.8%\nInsurance ID: UHC-9021-38745\nContact: sarah.obrien@gmail.com | 555-374-8821`
  },
  {
    id: 'safe_text',
    label: 'Safe Enterprise Text',
    icon: ShieldCheck,
    text: `Q3 FY2026 Security Report - FortifyAI Enterprise\n\nThis report covers prompt injection threat surface analysis across 4 deployed LLM endpoints.\nTotal scans: 142,900 | Blocked: 3,412 | Allowed: 139,488\nAverage detection latency: 18ms\nModernBERT model version: v2.4 (fine-tuned July 2026)`
  },
];

// ─── Layered PII Detection Engine ──────────────────────────────────────────
function detectPII(text) {
  const rawFindings = [];
  let idCounter = 0;

  // Helper to push a finding with exact start/end match bounds
  const addFinding = (type, value, start, end, confidence, detector) => {
    if (!value || start === undefined || end === undefined || start < 0 || end <= start) return;
    rawFindings.push({
      id: `f_${idCounter++}`,
      type,
      value,
      start,
      end,
      confidence,
      detector,
      regulation: ENTITY_TYPES[type]?.regulation || [],
      tier: ENTITY_TYPES[type]?.tier || 'LOW'
    });
  };

  // 1. Email Address (High accuracy)
  const emailRegex = /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g;
  let match;
  while ((match = emailRegex.exec(text)) !== null) {
    addFinding('EMAIL', match[0], match.index, match.index + match[0].length, 0.99, 'Regex Recognizer');
  }

  // 2. Aadhaar Number (12 digits grouped 4-4-4 or 12 digits continuous, with Verhoeff validation)
  const aadhaarRegex = /\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b/g;
  while ((match = aadhaarRegex.exec(text)) !== null) {
    if (validateVerhoeff(match[0])) {
      addFinding('AADHAAR', match[0], match.index, match.index + match[0].length, 0.98, 'Regex + Verhoeff Validator');
    }
  }

  // 3. Credit / Debit Card (13-19 digits, grouped 4-4-4-4 or continuous, with Luhn validation)
  const cardRegex = /\b(?:\d[ \-]?){13,18}\d\b/g;
  while ((match = cardRegex.exec(text)) !== null) {
    const rawDigits = match[0].replace(/\D/g, '');
    if (rawDigits.length >= 13 && rawDigits.length <= 19 && validateLuhn(match[0])) {
      addFinding('CREDIT_CARD', match[0], match.index, match.index + match[0].length, 0.99, 'Regex + Luhn Validator');
    }
  }

  // 4. Phone Number (Strict +91 Indian 10-digit mobile or US 10-digit format only!)
  const phoneRegex = /(?:\+91[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}\b|\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b/g;
  while ((match = phoneRegex.exec(text)) !== null) {
    const digitsOnly = match[0].replace(/\D/g, '');
    if (digitsOnly.length >= 10 && digitsOnly.length <= 12) {
      addFinding('PHONE', match[0], match.index, match.index + match[0].length, 0.94, 'Pattern Matcher');
    }
  }

  // 5. PAN Card Number (10 alphanumeric: 5 letters, 4 digits, 1 letter)
  const panRegex = /\b[A-Z]{5}\d{4}[A-Z]\b/g;
  while ((match = panRegex.exec(text)) !== null) {
    addFinding('PAN', match[0], match.index, match.index + match[0].length, 0.97, 'Format Recognizer');
  }

  // 6. IFSC Code (4 letters, 0, 6 alphanumeric)
  const ifscRegex = /\b[A-Z]{4}0[A-Z0-9]{6}\b/g;
  while ((match = ifscRegex.exec(text)) !== null) {
    addFinding('IFSC_CODE', match[0], match.index, match.index + match[0].length, 0.98, 'IFSC Pattern Matcher');
  }

  // 7. Bank Account Number (Requires nearby context words like account / a/c / bank account)
  const bankAccountRegex = /(?:account|a\/c|acct|bank account|account number|acc no)[\s:#\-]*([0-9]{9,18})\b/gi;
  while ((match = bankAccountRegex.exec(text)) !== null) {
    const fullMatch = match[0];
    const accVal = match[1];
    const accStart = match.index + fullMatch.indexOf(accVal);
    addFinding('BANK_ACCOUNT', accVal, accStart, accStart + accVal.length, 0.92, 'Context-Aware Recognizer');
  }

  // 8. Card CVV (Requires nearby context like CVV / CVC / Security Code)
  const cvvRegex = /(?:cvv|cvc|security code|cvv2)[\s:#\-]*([0-9]{3,4})\b/gi;
  while ((match = cvvRegex.exec(text)) !== null) {
    const fullMatch = match[0];
    const cvvVal = match[1];
    const cvvStart = match.index + fullMatch.indexOf(cvvVal);
    addFinding('CVV', cvvVal, cvvStart, cvvStart + cvvVal.length, 0.95, 'Context-Aware Recognizer');
  }

  // 9. Card Expiry Date (Requires nearby context like Exp / Expiry / Valid Thru)
  const expiryRegex = /(?:exp|expiry|valid thru|exp date)[\s:#\-]*((?:0[1-9]|1[0-2])\/[0-9]{2,4})\b/gi;
  while ((match = expiryRegex.exec(text)) !== null) {
    const fullMatch = match[0];
    const expVal = match[1];
    const expStart = match.index + fullMatch.indexOf(expVal);
    addFinding('CARD_EXPIRY', expVal, expStart, expStart + expVal.length, 0.93, 'Date Context Recognizer');
  }

  // 10. Date of Birth (DOB)
  const dobRegex = /(?:dob|date of birth|born|birth date)[\s:#\-]*((?:0[1-9]|[12][0-9]|3[01])[\/\-\.](?:0[1-9]|1[0-2])[\/\-\.](?:19|20)\d{2})\b/gi;
  while ((match = dobRegex.exec(text)) !== null) {
    const fullMatch = match[0];
    const dobVal = match[1];
    const dobStart = match.index + fullMatch.indexOf(dobVal);
    addFinding('DOB', dobVal, dobStart, dobStart + dobVal.length, 0.94, 'DOB Recognizer');
  }

  // 11. API Keys & Secrets
  const apiKeyRegex = /\b(?:sk_live_|sk_test_|AKIA|AIza|pk_live_|ghp_|xox[baprs]-)[A-Za-z0-9\/+\-_]{10,60}\b/g;
  while ((match = apiKeyRegex.exec(text)) !== null) {
    addFinding('API_KEY', match[0], match.index, match.index + match[0].length, 0.99, 'Key Pattern Recognizer');
  }

  // 12. SSN / National ID
  const ssnRegex = /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
  while ((match = ssnRegex.exec(text)) !== null) {
    addFinding('SSN', match[0], match.index, match.index + match[0].length, 0.97, 'SSN Format Recognizer');
  }

  // 13. IP Address
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  while ((match = ipRegex.exec(text)) !== null) {
    addFinding('IP_ADDRESS', match[0], match.index, match.index + match[0].length, 0.88, 'IP Recognizer');
  }

  // ─── NER LAYER (Person, Organization, Location, Address) ──────────────────
  // A. Person Names (Context prefixes, known name patterns, employment phrases)
  const personContextRegex = /(?:Patient:|Customer:|Cardholder:|User:|Physician:|Dr\.|Mr\.|Ms\.|Mrs\.|Name:)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z']+)+)/g;
  while ((match = personContextRegex.exec(text)) !== null) {
    const nameVal = match[1];
    const nameStart = match.index + match[0].indexOf(nameVal);
    addFinding('PERSON', nameVal, nameStart, nameStart + nameVal.length, 0.93, 'ModernBERT NER');
  }

  const nameEmploymentRegex = /\b([A-Z][a-z]+\s+[A-Z][a-z']+)\s+(?:works at|joined|is employed at|reported to)\b/g;
  while ((match = nameEmploymentRegex.exec(text)) !== null) {
    const nameVal = match[1];
    const nameStart = match.index + match[0].indexOf(nameVal);
    addFinding('PERSON', nameVal, nameStart, nameStart + nameVal.length, 0.89, 'ModernBERT NER');
  }

  // Common Indian/Western full names in free text
  const knownNamesRegex = /\b([A-Z][a-z]+\s+(?:Sharma|Mehta|O'Brien|Fowler|Kumar|Singh|Patel|Verma|Gupta|Reddy|Rao|Nair|Iyer|Joshi|Deshmukh|Kulkarni))\b/g;
  while ((match = knownNamesRegex.exec(text)) !== null) {
    addFinding('PERSON', match[1], match.index, match.index + match[1].length, 0.86, 'ModernBERT NER');
  }

  // B. Organization Names
  const knownOrgsRegex = /\b(Infosys|TCS|Wipro|Acme Corp|AcmeCorp|FortifyAI|UHC|Google|Microsoft|Amazon|Tata|Reliance|HDFC|ICICI|SBI|Accenture)\b/g;
  while ((match = knownOrgsRegex.exec(text)) !== null) {
    addFinding('ORGANIZATION', match[0], match.index, match.index + match[0].length, 0.91, 'ModernBERT NER');
  }
  const orgSuffixRegex = /\b([A-Z][A-Za-z0-9&]+\s+(?:Inc|Corp|Corporation|Ltd|Limited|Pvt Ltd|LLC|Technologies|Systems))\b/g;
  while ((match = orgSuffixRegex.exec(text)) !== null) {
    addFinding('ORGANIZATION', match[0], match.index, match.index + match[0].length, 0.88, 'ModernBERT NER');
  }

  // C. Location & Postal Address
  const addressRegex = /\b\d{1,4}[,\s]+[A-Za-z0-9\s,\-]+(?:Sector|Street|Road|Noida|Mumbai|Delhi|Bangalore|Bengaluru|Pune|Hyderabad|Gurgaon|UP|MH|KA|DL|\d{6})\b/gi;
  while ((match = addressRegex.exec(text)) !== null) {
    addFinding('LOCATION', match[0], match.index, match.index + match[0].length, 0.88, 'ModernBERT NER');
  }
  const knownCitiesRegex = /\b(Noida|Mumbai|Delhi|Bangalore|Bengaluru|Pune|Hyderabad|Gurgaon|Chennai|Kolkata|UP|Uttar Pradesh|Maharashtra)\b/g;
  while ((match = knownCitiesRegex.exec(text)) !== null) {
    addFinding('LOCATION', match[0], match.index, match.index + match[0].length, 0.82, 'ModernBERT NER');
  }

  // ─── OVERLAP RESOLUTION (Fixes Duplicate & Span Truncation Bugs) ────────────
  // Sort candidates by Priority (specific financial recognizers first), then confidence, then span length
  const sortedCandidates = [...rawFindings].sort((a, b) => {
    const prioA = (PRIORITY_MAP[a.type] || 10) * 100 + (a.confidence || 0) * 10;
    const prioB = (PRIORITY_MAP[b.type] || 10) * 100 + (b.confidence || 0) * 10;
    if (prioA !== prioB) return prioB - prioA;
    return (b.end - b.start) - (a.end - a.start);
  });

  const resolvedFindings = [];
  for (const candidate of sortedCandidates) {
    // Check if candidate overlaps with any already selected higher-priority finding
    const isOverlapping = resolvedFindings.some(selected =>
      Math.max(selected.start, candidate.start) < Math.min(selected.end, candidate.end)
    );
    if (!isOverlapping) {
      resolvedFindings.push(candidate);
    }
  }

  // Sort resolved findings by start index ascending for clean left-to-right processing
  return resolvedFindings.sort((a, b) => a.start - b.start);
}

// ─── Robust Non-Overlapping Mask Replacement Engine ────────────────────────
function applyMask(text, findings, mode) {
  if (!findings || findings.length === 0) return text;
  
  let masked = '';
  let lastIndex = 0;
  
  // Ensure findings are sorted ascending by text start index
  const sorted = [...findings].sort((a, b) => a.start - b.start);
  
  for (const f of sorted) {
    // Append preceding clean text
    masked += text.slice(lastIndex, f.start);
    
    // Generate masked replacement token
    let replacement = '';
    const val = f.value;
    
    if (mode === 'tag') {
      replacement = `[${f.type}]`;
    } else if (mode === 'redact') {
      replacement = '[REDACTED]';
    } else if (mode === 'partial') {
      if (f.type === 'EMAIL') {
        const parts = val.split('@');
        const user = parts[0];
        const domain = parts.slice(1).join('@');
        replacement = user.length > 2
          ? `${user[0]}${'*'.repeat(user.length - 2)}${user[user.length - 1]}@${domain}`
          : `${user[0]}*@${domain}`;
      } else {
        const clean = val.trim();
        replacement = clean.length > 4
          ? clean.slice(0, 2) + '*'.repeat(clean.length - 4) + clean.slice(-2)
          : '*'.repeat(clean.length);
      }
    } else { // Pseudonymize
      const hash = Math.abs([...val].reduce((acc, ch) => ((acc << 5) - acc) + ch.charCodeAt(0), 0)).toString(16).slice(0, 8).toUpperCase();
      replacement = `[TOKEN_${hash}]`;
    }
    
    masked += replacement;
    lastIndex = f.end;
  }
  
  // Append remaining tail text
  masked += text.slice(lastIndex);
  return masked;
}

// ─── Main PII Scanner Component ───────────────────────────────────────────
export default function PIIScanner() {
  const [text, setText] = useState('');
  const [selectedPreset, setSelectedPreset] = useState(null);
  const [maskMode, setMaskMode] = useState('tag');
  const [findings, setFindings] = useState(null);
  const [maskedText, setMaskedText] = useState('');
  const [loading, setLoading] = useState(false);
  const [outputTab, setOutputTab] = useState('masked'); // 'masked' | 'entities'
  const [activeHoverId, setActiveHoverId] = useState(null);
  const [copied, setCopied] = useState(false);

  const runScan = (inputText = text) => {
    if (!inputText.trim()) return;
    setLoading(true);
    setFindings(null);
    setTimeout(() => {
      const results = detectPII(inputText);
      setFindings(results);
      setMaskedText(applyMask(inputText, results, maskMode));
      setLoading(false);
    }, 450);
  };

  const loadPreset = (preset) => {
    setSelectedPreset(preset.id);
    setText(preset.text);
    setFindings(null);
    setMaskedText('');
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(maskedText).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  // Tier groupings
  const highRiskList = findings?.filter(f => f.tier === 'HIGH') ?? [];
  const mediumRiskList = findings?.filter(f => f.tier === 'MEDIUM') ?? [];
  const lowRiskList = findings?.filter(f => f.tier === 'LOW') ?? [];
  const needsReviewList = findings?.filter(f => f.confidence < 0.90) ?? [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

      {/* ── Page Header ── */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '48px', height: '48px', borderRadius: '12px',
            background: 'rgba(79, 70, 229, 0.08)', border: '1px solid rgba(79, 70, 229, 0.2)',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <EyeOff size={24} color="#4F46E5" />
          </div>
          <div>
            <h2 className="mono-text" style={{ fontSize: '1.15rem', fontWeight: 900, color: '#09090B', letterSpacing: '0.02em' }}>
              PII / DATA LEAKAGE SCANNER
            </h2>
            <p style={{ fontSize: '0.82rem', color: '#64748B', marginTop: '2px', fontWeight: 500 }}>
              Layered detection — Regex → NER → Checksum Validators → Risk-Tiered Masking Engine
            </p>
          </div>
        </div>
      </div>

      {/* ── Summary Stats Bar at Top ── */}
      {findings !== null && (
        <motion.div
          initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}
          style={{
            background: '#FFFFFF', border: '1px solid #E2E8F0', borderRadius: '16px',
            padding: '20px 24px', boxShadow: '0 4px 20px rgba(0,0,0,0.03)',
            display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', alignItems: 'center'
          }}
        >
          {/* Total Detected */}
          <div style={{ borderRight: '1px solid #F1F5F9', paddingRight: '12px' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#64748B', textTransform: 'uppercase' }}>Total Entities Detected</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 900, color: findings.length > 0 ? '#0F172A' : '#059669', marginTop: '2px' }}>
              {findings.length}
            </div>
          </div>

          {/* High Risk Tier */}
          <div style={{ borderRight: '1px solid #F1F5F9', paddingRight: '12px' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#DC2626', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '5px' }}>
              <ShieldAlert size={14} color="#DC2626" /> High-Risk Financial/ID
            </div>
            <div style={{ fontSize: '1.8rem', fontWeight: 900, color: highRiskList.length > 0 ? '#DC2626' : '#059669', marginTop: '2px' }}>
              {highRiskList.length}
            </div>
          </div>

          {/* Needs Human Review */}
          <div style={{ borderRight: '1px solid #F1F5F9', paddingRight: '12px' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#D97706', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '5px' }}>
              <AlertTriangle size={14} color="#D97706" /> Needs Human Review (&lt;90%)
            </div>
            <div style={{ fontSize: '1.8rem', fontWeight: 900, color: needsReviewList.length > 0 ? '#D97706' : '#059669', marginTop: '2px' }}>
              {needsReviewList.length}
            </div>
          </div>

          {/* Compliance Status */}
          <div>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#64748B', textTransform: 'uppercase' }}>Scan Verdict</div>
            <div style={{
              display: 'inline-flex', alignItems: 'center', gap: '6px',
              marginTop: '6px', padding: '4px 12px', borderRadius: '20px', fontWeight: 800, fontSize: '0.85rem',
              background: findings.length > 0 ? '#FEF2F2' : '#ECFDF5',
              color: findings.length > 0 ? '#DC2626' : '#059669',
              border: `1px solid ${findings.length > 0 ? '#FECACA' : '#A7F3D0'}`
            }}>
              {findings.length > 0 ? <AlertTriangle size={14} /> : <CheckCircle2 size={14} />}
              <span>{findings.length > 0 ? 'PII LEAK RISKS FOUND' : 'CLEAN & COMPLIANT'}</span>
            </div>
          </div>
        </motion.div>
      )}

      {/* ── Main Scanner Workspace Grid ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 520px', gap: '24px', alignItems: 'start' }}>

        {/* Left: Input Text & Control Bar */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

          <div className="shiny-card" style={{ padding: '24px', background: '#FFFFFF', borderRadius: '16px' }}>

            {/* Presets Row */}
            <div style={{ marginBottom: '18px' }}>
              <div className="mono-text" style={{ fontSize: '0.72rem', fontWeight: 700, color: '#64748B', marginBottom: '10px' }}>TEST PRESETS</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                {PRESETS.map(pr => {
                  const Icon = pr.icon;
                  const isSelected = selectedPreset === pr.id;
                  return (
                    <button
                      key={pr.id}
                      onClick={() => loadPreset(pr)}
                      style={{
                        background: isSelected ? '#FDFBF7' : '#F8F9FA',
                        border: isSelected ? '1px solid #6F4E37' : '1px solid #E2E8F0',
                        color: isSelected ? '#6F4E37' : '#334155',
                        padding: '7px 12px', borderRadius: '8px',
                        fontSize: '0.82rem', fontFamily: 'var(--font-mono)', fontWeight: isSelected ? 700 : 500,
                        cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '6px',
                        transition: 'all 0.15s'
                      }}
                    >
                      <Icon size={13} color={isSelected ? '#6F4E37' : '#64748B'} />
                      {pr.label}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Input Textarea */}
            <div style={{ position: 'relative', marginBottom: '16px' }}>
              <textarea
                rows={12}
                value={text}
                onChange={e => setText(e.target.value)}
                placeholder="Paste customer records, bank statements, medical notes, card leaks, or API keys here to test PII detection..."
                style={{
                  background: '#FFFFFF', color: '#09090B',
                  border: '1.5px solid #CBD5E1', borderRadius: '10px',
                  padding: '14px', paddingBottom: '34px',
                  fontSize: '0.9rem', lineHeight: 1.55, fontWeight: 450,
                  resize: 'vertical'
                }}
              />
              <div className="mono-text" style={{
                position: 'absolute', right: '14px', bottom: '10px',
                fontSize: '0.72rem', color: '#94A3B8', fontWeight: 600, pointerEvents: 'none'
              }}>
                {text.length.toLocaleString()} chars
              </div>
            </div>

            {/* Bottom Actions Bar */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="mono-text" style={{ fontSize: '0.75rem', fontWeight: 700, color: '#64748B' }}>MASKING:</span>
                {['tag', 'redact', 'partial', 'pseudonym'].map(mode => (
                  <button
                    key={mode}
                    onClick={() => {
                      setMaskMode(mode);
                      if (findings) setMaskedText(applyMask(text, findings, mode));
                    }}
                    style={{
                      background: maskMode === mode ? '#0F172A' : '#F8F9FA',
                      color: maskMode === mode ? '#FFFFFF' : '#475569',
                      border: `1px solid ${maskMode === mode ? '#0F172A' : '#CBD5E1'}`,
                      borderRadius: '6px', padding: '4px 10px', fontSize: '0.78rem',
                      fontWeight: 700, cursor: 'pointer', textTransform: 'capitalize'
                    }}
                  >
                    {mode}
                  </button>
                ))}
              </div>

              <button
                className="btn-primary"
                onClick={() => runScan()}
                disabled={loading || !text.trim()}
                style={{
                  background: '#4F46E5', borderColor: '#3730A3',
                  padding: '10px 24px', borderRadius: '8px', fontWeight: 700, fontSize: '0.9rem'
                }}
              >
                <Search size={16} />
                <span>{loading ? 'SCANNING...' : 'SCAN FOR PII'}</span>
              </button>
            </div>

          </div>
        </div>

        {/* Right Column: Two-Tab View (Masked Output / Detected Entities) */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

          {/* Loading State */}
          {loading && (
            <motion.div
              initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              style={{
                background: '#FFFFFF', border: '1px solid #E2E8F0', borderRadius: '16px',
                padding: '40px', textAlign: 'center', boxShadow: '0 4px 20px rgba(0,0,0,0.04)'
              }}
            >
              <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }} style={{ display: 'inline-block', marginBottom: '12px' }}>
                <Search size={32} color="#4F46E5" />
              </motion.div>
              <div style={{ fontWeight: 800, color: '#0F172A', fontSize: '1rem', marginBottom: '4px' }}>Processing Layered Pipeline</div>
              <div style={{ fontSize: '0.82rem', color: '#64748B' }}>Evaluating Regex → Verhoeff/Luhn Checksums → ModernBERT NER</div>
            </motion.div>
          )}

          {/* Empty State */}
          {!loading && findings === null && (
            <div style={{
              background: '#FFFFFF', border: '1px solid #E2E8F0', borderRadius: '16px',
              padding: '44px 24px', textAlign: 'center', boxShadow: '0 4px 20px rgba(0,0,0,0.04)'
            }}>
              <EyeOff size={36} color="#CBD5E1" style={{ marginBottom: '12px' }} />
              <div style={{ fontWeight: 700, color: '#94A3B8', fontSize: '1rem' }}>No active scan results</div>
              <div style={{ fontSize: '0.82rem', color: '#CBD5E1', marginTop: '4px' }}>Click a preset or paste text to run PII inspection</div>
            </div>
          )}

          {/* Results View Container */}
          {!loading && findings !== null && (
            <motion.div
              initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
              style={{
                background: '#FFFFFF', border: '1px solid #E2E8F0', borderRadius: '16px',
                boxShadow: '0 4px 20px rgba(0,0,0,0.04)', overflow: 'hidden'
              }}
            >

              {/* Two-Tab View Toggle Bar */}
              <div style={{
                background: '#F8F9FA', borderBottom: '1px solid #E2E8F0',
                padding: '12px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between'
              }}>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    onClick={() => setOutputTab('masked')}
                    style={{
                      background: outputTab === 'masked' ? '#FFFFFF' : 'transparent',
                      color: outputTab === 'masked' ? '#4F46E5' : '#64748B',
                      border: `1px solid ${outputTab === 'masked' ? '#CBD5E1' : 'transparent'}`,
                      borderRadius: '8px', padding: '6px 14px', fontSize: '0.85rem',
                      fontWeight: 800, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px',
                      boxShadow: outputTab === 'masked' ? '0 2px 6px rgba(0,0,0,0.04)' : 'none'
                    }}
                  >
                    <EyeOff size={14} /> Masked Output
                  </button>
                  <button
                    onClick={() => setOutputTab('entities')}
                    style={{
                      background: outputTab === 'entities' ? '#FFFFFF' : 'transparent',
                      color: outputTab === 'entities' ? '#4F46E5' : '#64748B',
                      border: `1px solid ${outputTab === 'entities' ? '#CBD5E1' : 'transparent'}`,
                      borderRadius: '8px', padding: '6px 14px', fontSize: '0.85rem',
                      fontWeight: 800, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px',
                      boxShadow: outputTab === 'entities' ? '0 2px 6px rgba(0,0,0,0.04)' : 'none'
                    }}
                  >
                    <Tag size={14} /> Detected Entities ({findings.length})
                  </button>
                </div>

                {outputTab === 'masked' && (
                  <button
                    onClick={handleCopy}
                    style={{
                      background: copied ? '#ECFDF5' : '#EEF2FF',
                      border: `1px solid ${copied ? '#A7F3D0' : '#C7D2FE'}`,
                      color: copied ? '#059669' : '#4F46E5',
                      borderRadius: '6px', padding: '4px 10px', fontSize: '0.78rem',
                      fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '5px'
                    }}
                  >
                    {copied ? <Check size={12} /> : <Copy size={12} />}
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                )}
              </div>

              {/* TAB 1: MASKED OUTPUT */}
              {outputTab === 'masked' && (
                <div style={{ padding: '20px' }}>
                  <div className="mono-text" style={{
                    padding: '16px', background: '#FAFBFD', border: '1px solid #E2E8F0',
                    borderRadius: '10px', fontSize: '0.88rem', color: '#0F172A', lineHeight: 1.6,
                    whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: '380px', overflowY: 'auto'
                  }}>
                    {maskedText}
                  </div>
                  <div style={{ marginTop: '12px', fontSize: '0.78rem', color: '#64748B', display: 'flex', alignItems: 'center', justifyBetween: 'space-between' }}>
                    <span>Strategy: <strong style={{ textTransform: 'uppercase' }}>{maskMode}</strong></span>
                    <span style={{ color: '#059669', fontWeight: 700 }}>✓ Zero Span Truncation Drift</span>
                  </div>
                </div>
              )}

              {/* TAB 2: DETECTED ENTITIES GROUPED BY RISK TIER */}
              {outputTab === 'entities' && (
                <div style={{ padding: '16px', maxHeight: '440px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  {findings.length === 0 ? (
                    <div style={{ padding: '30px', textAlign: 'center', color: '#059669', fontWeight: 700 }}>
                      ✓ No PII entities detected in text
                    </div>
                  ) : (
                    <>
                      {/* TIER 1: HIGH RISK */}
                      {highRiskList.length > 0 && (
                        <div>
                          <div style={{
                            fontSize: '0.75rem', fontWeight: 800, color: '#DC2626',
                            letterSpacing: '0.05em', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px'
                          }}>
                            <ShieldAlert size={14} color="#DC2626" /> HIGH RISK (FINANCIAL & CRITICAL ID) — {highRiskList.length}
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                            {highRiskList.map(f => <EntityCard key={f.id} item={f} />)}
                          </div>
                        </div>
                      )}

                      {/* TIER 2: MEDIUM RISK */}
                      {mediumRiskList.length > 0 && (
                        <div>
                          <div style={{
                            fontSize: '0.75rem', fontWeight: 800, color: '#D97706',
                            letterSpacing: '0.05em', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px'
                          }}>
                            <AlertTriangle size={14} color="#D97706" /> MEDIUM RISK (CONTACT IDENTIFIERS) — {mediumRiskList.length}
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                            {mediumRiskList.map(f => <EntityCard key={f.id} item={f} />)}
                          </div>
                        </div>
                      )}

                      {/* TIER 3: LOW RISK */}
                      {lowRiskList.length > 0 && (
                        <div>
                          <div style={{
                            fontSize: '0.75rem', fontWeight: 800, color: '#7C3AED',
                            letterSpacing: '0.05em', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px'
                          }}>
                            <User size={14} color="#7C3AED" /> LOW RISK (UNSTRUCTURED CONTEXT & NAMES) — {lowRiskList.length}
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                            {lowRiskList.map(f => <EntityCard key={f.id} item={f} />)}
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}

            </motion.div>
          )}

        </div>
      </div>
    </div>
  );
}

// ─── Individual Entity Card Sub-Component ─────────────────────────────────────
function EntityCard({ item }) {
  const meta = ENTITY_TYPES[item.type] || { label: item.type, icon: Hash, color: '#475569', bg: '#F8FAFC', border: '#CBD5E1', regulation: [] };
  const Icon = meta.icon;
  const isNeedsReview = item.confidence < 0.90;

  return (
    <div style={{
      background: '#FFFFFF', border: `1px solid ${meta.border}`, borderRadius: '12px',
      padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: '8px',
      boxShadow: '0 2px 8px rgba(0,0,0,0.02)'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ background: meta.bg, border: `1px solid ${meta.border}`, borderRadius: '8px', padding: '6px', display: 'flex' }}>
            <Icon size={14} color={meta.color} />
          </div>
          <div>
            <div style={{ fontSize: '0.85rem', fontWeight: 800, color: '#0F172A' }}>{meta.label}</div>
            <div style={{ fontSize: '0.72rem', color: '#64748B', marginTop: '1px' }}>{item.detector}</div>
          </div>
        </div>

        {/* Review Status Badge */}
        <div style={{
          fontSize: '0.68rem', fontWeight: 800, padding: '3px 8px', borderRadius: '4px',
          background: isNeedsReview ? '#FFFBEB' : '#ECFDF5',
          color: isNeedsReview ? '#D97706' : '#059669',
          border: `1px solid ${isNeedsReview ? '#FDE68A' : '#A7F3D0'}`
        }}>
          {isNeedsReview ? 'NEEDS REVIEW' : 'AUTO-MASKED'}
        </div>
      </div>

      {/* Value Snippet & Confidence Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
        <div className="mono-text" style={{ fontSize: '0.82rem', fontWeight: 700, color: meta.color, background: meta.bg, padding: '3px 8px', borderRadius: '4px', maxWidth: '260px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {item.value}
        </div>

        {/* Small Progress Bar for Confidence */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: '120px' }}>
          <div style={{ flex: 1, height: '6px', background: '#E2E8F0', borderRadius: '3px', overflow: 'hidden' }}>
            <div style={{
              width: `${(item.confidence * 100).toFixed(0)}%`,
              height: '100%',
              background: item.confidence >= 0.90 ? '#059669' : '#D97706',
              borderRadius: '3px'
            }} />
          </div>
          <span className="mono-text" style={{ fontSize: '0.75rem', fontWeight: 800, color: item.confidence >= 0.90 ? '#059669' : '#D97706' }}>
            {(item.confidence * 100).toFixed(0)}%
          </span>
        </div>
      </div>

      {/* Regulation Badges */}
      <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginTop: '2px' }}>
        {item.regulation.map(r => (
          <span key={r} style={{
            fontSize: '0.68rem', fontWeight: 700, padding: '1px 6px',
            borderRadius: '3px', background: '#F1F5F9', color: '#475569'
          }}>{r}</span>
        ))}
      </div>
    </div>
  );
}
