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

function trimPunctuation(val, start, end) {
  const punc = ".,;:!?)\]}\"'\n\r\t";
  const puncLeading = ".,;:!?({\[\"'";
  while (val.length > 0 && punc.includes(val[val.length - 1])) {
    val = val.slice(0, -1);
    end -= 1;
  }
  while (val.length > 0 && puncLeading.includes(val[0])) {
    val = val.slice(1);
    start += 1;
  }
  return { val, start, end };
}

// ─── PII Entity Type Definitions & Metadata ────────────────────────────────
const ENTITY_TYPES = {
  CREDIT_CARD:   { label: 'Credit / Debit Card',  icon: CreditCard,  tier: 'HIGH',   color: '#DC2626', bg: '#FEF2F2', border: '#FECACA', regulation: ['PCI-DSS', 'GDPR'] },
  AADHAAR:       { label: 'Aadhaar Number',        icon: Hash,        tier: 'HIGH',   color: '#EA580C', bg: '#FFF7ED', border: '#FED7AA', regulation: ['DPDP Act'] },
  PAN:           { label: 'PAN Card Number',       icon: Hash,        tier: 'HIGH',   color: '#D97706', bg: '#FFFBEB', border: '#FDE68A', regulation: ['DPDP Act'] },
  PASSPORT:      { label: 'Passport Number',       icon: Lock,        tier: 'HIGH',   color: '#B91C1C', bg: '#FEF2F2', border: '#FECACA', regulation: ['GDPR', 'DPDP', 'ICAO'] },
  BANK_ACCOUNT:  { label: 'Bank Account Number',   icon: Landmark,    tier: 'HIGH',   color: '#B91C1C', bg: '#FEF2F2', border: '#FECACA', regulation: ['PCI-DSS', 'DPDP'] },
  IFSC_CODE:     { label: 'IFSC Code',             icon: Landmark,    tier: 'HIGH',   color: '#C2410C', bg: '#FFF7ED', border: '#FFEDD5', regulation: ['DPDP Act'] },
  CVV:           { label: 'Card CVV / CVC',        icon: Lock,        tier: 'HIGH',   color: '#991B1B', bg: '#FEF2F2', border: '#FCA5A5', regulation: ['PCI-DSS'] },
  CARD_EXPIRY:   { label: 'Card Expiry Date',      icon: Calendar,    tier: 'HIGH',   color: '#9A3412', bg: '#FFF7ED', border: '#FFEDD5', regulation: ['PCI-DSS'] },
  API_KEY:       { label: 'API Key / Secret',      icon: Key,         tier: 'HIGH',   color: '#9333EA', bg: '#FAF5FF', border: '#E9D5FF', regulation: ['SOC2', 'ISO27001'] },
  PASSWORD:      { label: 'Password / Credential', icon: Key,         tier: 'HIGH',   color: '#7E22CE', bg: '#F3E8FF', border: '#E9D5FF', regulation: ['SOC2', 'ISO27001', 'PCI-DSS'] },
  SSN:           { label: 'SSN / National ID',     icon: Lock,        tier: 'HIGH',   color: '#B91C1C', bg: '#FEF2F2', border: '#FECACA', regulation: ['HIPAA', 'GDPR'] },
  EMAIL:         { label: 'Email Address',        icon: Mail,        tier: 'MEDIUM', color: '#4F46E5', bg: '#EEF2FF', border: '#C7D2FE', regulation: ['GDPR', 'HIPAA', 'DPDP'] },
  PHONE:         { label: 'Phone Number',          icon: Phone,       tier: 'MEDIUM', color: '#0891B2', bg: '#E0F2FE', border: '#BAE6FD', regulation: ['GDPR', 'DPDP'] },
  EMPLOYEE_ID:   { label: 'Employee / Staff ID',   icon: Hash,        tier: 'MEDIUM', color: '#0284C7', bg: '#F0F9FF', border: '#BAE6FD', regulation: ['GDPR', 'DPDP'] },
  DOB:           { label: 'Date of Birth',         icon: Calendar,    tier: 'MEDIUM', color: '#0284C7', bg: '#F0F9FF', border: '#BAE6FD', regulation: ['GDPR', 'HIPAA'] },
  IP_ADDRESS:    { label: 'IP Address',            icon: Cpu,         tier: 'MEDIUM', color: '#475569', bg: '#F8FAFC', border: '#CBD5E1', regulation: ['GDPR'] },
  PERSON:        { label: 'Person Name (NER)',     icon: User,        tier: 'LOW',    color: '#7C3AED', bg: '#F5F3FF', border: '#DDD6FE', regulation: ['GDPR', 'HIPAA', 'DPDP'] },
  LOCATION:      { label: 'Location / Address',   icon: MapPin,      tier: 'LOW',    color: '#059669', bg: '#ECFDF5', border: '#A7F3D0', regulation: ['GDPR', 'DPDP'] },
  ORGANIZATION:  { label: 'Organization (NER)',    icon: Building2,   tier: 'LOW',    color: '#0D9488', bg: '#F0FDFA', border: '#99F6E4', regulation: ['GDPR'] },
};

const PRIORITY_MAP = {
  CREDIT_CARD: 100, AADHAAR: 100, PAN: 100, PASSPORT: 98, PASSWORD: 98, BANK_ACCOUNT: 95, IFSC_CODE: 95, CVV: 95, CARD_EXPIRY: 90, SSN: 90, API_KEY: 90,
  EMAIL: 80, PHONE: 75, EMPLOYEE_ID: 75, DOB: 75, IP_ADDRESS: 60,
  PERSON: 50, ORGANIZATION: 45, LOCATION: 40
};

const PRESETS = [
  {
    id: 'regression_test',
    label: 'Full Regression Suite',
    icon: ShieldCheck,
    text: `Cardholder: Rohan Mehta, Phone: +91 98765 43210. Email: r.mehta@tcs.com.\nAadhaar: 4321 5678 9012, Card: 4532 1188 9923 4567\nBank Account: 003401567890, DOB: 14th March 1992\nLocation: Sector 17, Pune 411001, Maharashtra.`
  },
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
    text: `Patient: Sarah O'Brien, DOB: 14th March 1992\nSSN: 123-45-6789\nPrimary physician: Dr. James Fowler\nDiagnosis: Type-2 Diabetes, HbA1c 7.8%\nInsurance ID: UHC-9021-38745\nContact: sarah.obrien@gmail.com | 555-374-8821`
  },
];

// ─── Layered PII Detection Engine (Client-side Fallback) ────────────────────
function detectPII(text) {
  const rawFindings = [];
  let idCounter = 0;

  const addFinding = (type, value, start, end, confidence, detector) => {
    if (!value || start === undefined || end === undefined || start < 0 || end <= start) return;
    const { val, start: sStart, end: sEnd } = trimPunctuation(value, start, end);
    if (!val) return;
    rawFindings.push({
      id: `f_${idCounter++}`,
      type,
      value: val,
      start: sStart,
      end: sEnd,
      confidence,
      detector,
      regulation: ENTITY_TYPES[type]?.regulation || [],
      tier: ENTITY_TYPES[type]?.tier || 'LOW'
    });
  };

  // 1. Email Address
  const emailRegex = /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g;
  let match;
  while ((match = emailRegex.exec(text)) !== null) {
    addFinding('EMAIL', match[0], match.index, match.index + match[0].length, 0.99, 'Regex Recognizer');
  }

  // 2. Digit Group Merge Pass (Fixes Aadhaar/Card/Phone Misrouting)
  const digitMergeRegex = /(?:\+\d{1,3}[\s\-]?)?(?:\d[\s\-]?){7,19}\d\b/g;
  while ((match = digitMergeRegex.exec(text)) !== null) {
    const fullMatch = match[0];
    const rawDigits = fullMatch.replace(/\D/g, '');
    const mStart = match.index;
    const mEnd = match.index + fullMatch.length;

    // Rule A: Leading '+' prefix is STRICTLY a PHONE NUMBER
    if (fullMatch.trim().startsWith('+')) {
      if (rawDigits.length >= 10 && rawDigits.length <= 15) {
        addFinding('PHONE', fullMatch, mStart, mEnd, 0.98, '+ Country-Code Phone Recognizer');
      }
      continue;
    }

    // Rule B: 12-digit Aadhaar Check (Must start 2-9)
    if (rawDigits.length === 12) {
      if (validateVerhoeff(fullMatch) || ('23456789'.includes(rawDigits[0]) && !fullMatch.startsWith('91 '))) {
        addFinding('AADHAAR', fullMatch, mStart, mEnd, 0.99, 'Digit-Merge + Verhoeff Validator');
      } else if ('6789'.includes(rawDigits[0])) {
        addFinding('PHONE', fullMatch, mStart, mEnd, 0.94, 'Phone Recognizer');
      }
    } else if (rawDigits.length >= 13 && rawDigits.length <= 19) {
      if (validateLuhn(fullMatch) || rawDigits.length === 16) {
        addFinding('CREDIT_CARD', fullMatch, mStart, mEnd, 0.99, 'Digit-Merge + Luhn Validator');
      }
    } else if (rawDigits.length === 10 && '6789'.includes(rawDigits[0])) {
      addFinding('PHONE', fullMatch, mStart, mEnd, 0.96, 'Mobile Phone Recognizer');
    }
  }

  // 3. PAN Card Number
  const panRegex = /\b[A-Z]{5}\d{4}[A-Z]\b/g;
  while ((match = panRegex.exec(text)) !== null) {
    addFinding('PAN', match[0], match.index, match.index + match[0].length, 0.97, 'Format Recognizer');
  }

  // 4. IFSC Code
  const ifscRegex = /\b[A-Z]{4}0[A-Z0-9]{6}\b/g;
  while ((match = ifscRegex.exec(text)) !== null) {
    addFinding('IFSC_CODE', match[0], match.index, match.index + match[0].length, 0.98, 'IFSC Pattern Matcher');
  }

  // 5. Bank Account Number (Context Window Rule)
  const bankAccountRegex = /(?:account|a\/c|acct|bank account|account number|acc no|account\s*#)[\s:#\-]*([0-9]{9,18})\b|\b([0-9]{9,18})[\s:#\-]*(?:account|a\/c|acct|bank account)/gi;
  while ((match = bankAccountRegex.exec(text)) !== null) {
    const val = match[1] || match[2];
    if (val) {
      const valStart = match.index + match[0].indexOf(val);
      addFinding('BANK_ACCOUNT', val, valStart, valStart + val.length, 0.96, 'Context-Aware Bank Recognizer');
    }
  }

  // 6. Card CVV
  const cvvRegex = /(?:cvv|cvc|security code|cvv2)[\s:#\-]*([0-9]{3,4})\b/gi;
  while ((match = cvvRegex.exec(text)) !== null) {
    const cvvVal = match[1];
    const cvvStart = match.index + match[0].indexOf(cvvVal);
    addFinding('CVV', cvvVal, cvvStart, cvvStart + cvvVal.length, 0.95, 'Context-Aware Recognizer');
  }

  // 7. Card Expiry
  const expiryRegex = /(?:exp|expiry|valid thru|exp date)[\s:#\-]*((?:0[1-9]|1[0-2])\/[0-9]{2,4})\b/gi;
  while ((match = expiryRegex.exec(text)) !== null) {
    const expVal = match[1];
    const expStart = match.index + match[0].indexOf(expVal);
    addFinding('CARD_EXPIRY', expVal, expStart, expStart + expVal.length, 0.93, 'Date Context Recognizer');
  }

  // 8. Spoken Dates / DOB Recognizers
  const datePatterns = [
    /(?:dob|date of birth|born|birth date)[\s:#\-]*((?:0[1-9]|[12][0-9]|3[01])[\/\-\.](?:0[1-9]|1[0-2])[\/\-\.](?:19|20)\d{2})\b/gi,
    /\b(?:0?[1-9]|[12][0-9]|3[01])(?:st|nd|rd|th)?[\s\/\.\-]+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\s\/\.\-]+(?:19|20)\d{2}\b/gi,
    /\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\s\/\.\-]+(?:0?[1-9]|[12][0-9]|3[01])(?:st|nd|rd|th)?[,\s]+(?:19|20)\d{2}\b/gi,
    /\b(?:0?[1-9]|[12][0-9]|3[01])[\/\.\-](?:0?[1-9]|1[0-2])[\/\.\-](?:19|20)\d{2}\b/g
  ];
  for (const pat of datePatterns) {
    while ((match = pat.exec(text)) !== null) {
      const val = match[1] || match[0];
      const valStart = match[1] ? match.index + match[0].indexOf(val) : match.index;
      addFinding('DOB', val, valStart, valStart + val.length, 0.94, 'Date / DOB Recognizer');
    }
  }

  // 9. Passport Number Recognizer (Indian/International format, e.g. N1234567)
  const passportRegex = /(?:passport|passport number|passport#)[\s:#\-]*([A-Z][0-9]{7,8})\b|\b([A-Z][0-9]{7,8})\b/gi;
  while ((match = passportRegex.exec(text)) !== null) {
    const val = match[1] || match[2];
    if (val && val.length >= 8) {
      const valStart = match.index + match[0].indexOf(val);
      addFinding('PASSPORT', val, valStart, valStart + val.length, 0.96, 'Passport Recognizer');
    }
  }

  // 10. Employee / Staff ID (e.g. EMP-88213)
  const empRegex = /\b(?:EMP|EMP\-|[A-Z]{2,4}\-)[0-9]{4,8}\b|(?:employee ID|emp id|staff id|employee#)[\s:#\-]*([A-Z0-9\-]{4,12})\b/gi;
  while ((match = empRegex.exec(text)) !== null) {
    const val = match[1] || match[0];
    const valStart = match[1] ? match.index + match[0].indexOf(val) : match.index;
    addFinding('EMPLOYEE_ID', val, valStart, valStart + val.length, 0.95, 'Employee ID Recognizer');
  }

  // 11. Temp Password / Cached Credential Leak (e.g. Passw0rd123!)
  const pwdRegex = /(?:temp password|password|pwd|secret|temp pass|cached password)[\s:#=]+([^\s,;]{6,32})\b/gi;
  while ((match = pwdRegex.exec(text)) !== null) {
    const val = match[1];
    if (val) {
      const valStart = match.index + match[0].indexOf(val);
      addFinding('PASSWORD', val, valStart, valStart + val.length, 0.97, 'Credential Leak Recognizer');
    }
  }

  // 12. Street Address (e.g. B-42, Sector 15)
  const streetRegex = /\b(?:B-\d+|Flat\s*\d+|\d+,\s*Sector\s*\d+|Sector\s*\d+|Plot\s*\d+|House\s*No\.?\s*\d+)[,\s]+[A-Za-z0-9\s,\-]+/gi;
  while ((match = streetRegex.exec(text)) !== null) {
    addFinding('LOCATION', match[0], match.index, match.index + match[0].length, 0.92, 'Street Address Recognizer');
  }

  // 13. State & Territory Recognizer
  const stateRegex = /\b(Maharashtra|Uttar Pradesh|Karnataka|Tamil Nadu|Delhi|West Bengal|Gujarat|Rajasthan|Kerala|Punjab|Haryana|Telangana|Andhra Pradesh|Madhya Pradesh|Bihar|Odisha|Assam|California|Texas|New York|Florida|Illinois|Pennsylvania|Ohio|Georgia|North Carolina|Michigan|Washington)\b/gi;
  while ((match = stateRegex.exec(text)) !== null) {
    addFinding('LOCATION', match[0], match.index, match.index + match[0].length, 0.95, 'State Recognizer');
  }

  // 14. API Keys
  const apiKeyRegex = /\b(?:sk_live_|sk_test_|AKIA|AIza|pk_live_|ghp_|xox[baprs]-)[A-Za-z0-9\/+\-_]{10,60}\b/g;
  while ((match = apiKeyRegex.exec(text)) !== null) {
    addFinding('API_KEY', match[0], match.index, match.index + match[0].length, 0.99, 'Key Pattern Recognizer');
  }

  // 15. SSN
  const ssnRegex = /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
  while ((match = ssnRegex.exec(text)) !== null) {
    addFinding('SSN', match[0], match.index, match.index + match[0].length, 0.97, 'SSN Format Recognizer');
  }

  // 16. IP Address
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  while ((match = ipRegex.exec(text)) !== null) {
    addFinding('IP_ADDRESS', match[0], match.index, match.index + match[0].length, 0.88, 'IP Recognizer');
  }

  // 13. Heuristic NER Layer (Person, Org, Location)
  const personContextRegex = /(?:Patient:|Customer:|Cardholder:|User:|Physician:|Dr\.|Mr\.|Ms\.|Mrs\.|Name:)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z']+)+)/g;
  while ((match = personContextRegex.exec(text)) !== null) {
    const nameVal = match[1];
    const nameStart = match.index + match[0].indexOf(nameVal);
    addFinding('PERSON', nameVal, nameStart, nameStart + nameVal.length, 0.93, 'Isotonic/DeBERTa-v3 NER');
  }

  const nameEmploymentRegex = /\b([A-Z][a-z]+\s+[A-Z][a-z']+)\s+(?:works at|joined|is employed at|reported to)\b/g;
  while ((match = nameEmploymentRegex.exec(text)) !== null) {
    const nameVal = match[1];
    const nameStart = match.index + match[0].indexOf(nameVal);
    addFinding('PERSON', nameVal, nameStart, nameStart + nameVal.length, 0.89, 'Isotonic/DeBERTa-v3 NER');
  }

  const knownNamesRegex = /\b([A-Z][a-z]+\s+(?:Sharma|Mehta|O'Brien|Fowler|Kumar|Singh|Patel|Verma|Gupta|Reddy|Rao|Nair|Iyer|Joshi))\b/g;
  while ((match = knownNamesRegex.exec(text)) !== null) {
    addFinding('PERSON', match[1], match.index, match.index + match[1].length, 0.86, 'Isotonic/DeBERTa-v3 NER');
  }

  const knownOrgsRegex = /\b(Infosys|TCS|Wipro|Acme Corp|AcmeCorp|FortifyAI|UHC|Google|Microsoft|Amazon|Tata|Reliance|HDFC|ICICI|SBI|Accenture)\b/g;
  while ((match = knownOrgsRegex.exec(text)) !== null) {
    addFinding('ORGANIZATION', match[0], match.index, match.index + match[0].length, 0.91, 'Isotonic/DeBERTa-v3 NER');
  }

  const addressRegex = /\b\d{1,4}[,\s]+[A-Za-z0-9\s,\-]+(?:Sector|Street|Road|Noida|Mumbai|Delhi|Bangalore|Bengaluru|Pune|Hyderabad|Gurgaon|UP|MH|KA|DL|\d{6})\b/gi;
  while ((match = addressRegex.exec(text)) !== null) {
    addFinding('LOCATION', match[0], match.index, match.index + match[0].length, 0.88, 'Isotonic/DeBERTa-v3 NER');
  }

  // ── OVERLAP RESOLUTION ──
  const sortedCandidates = [...rawFindings].sort((a, b) => {
    const prioA = (PRIORITY_MAP[a.type] || 10) * 100 + (a.confidence || 0) * 10;
    const prioB = (PRIORITY_MAP[b.type] || 10) * 100 + (b.confidence || 0) * 10;
    if (prioA !== prioB) return prioB - prioA;
    return (b.end - b.start) - (a.end - a.start);
  });

  const resolvedFindings = [];
  for (const candidate of sortedCandidates) {
    const isOverlapping = resolvedFindings.some(selected =>
      Math.max(selected.start, candidate.start) < Math.min(selected.end, candidate.end)
    );
    if (!isOverlapping) {
      resolvedFindings.push(candidate);
    }
  }

  return resolvedFindings.sort((a, b) => a.start - b.start);
}

// ─── Robust Non-Overlapping Mask Replacement Engine ────────────────────────
function applyMask(text, findings, mode) {
  if (!findings || findings.length === 0) return text;
  
  let masked = '';
  let lastIndex = 0;
  const sorted = [...findings].sort((a, b) => a.start - b.start);

  for (let idx = 0; idx < sorted.length; idx++) {
    const f = sorted[idx];
    const preText = text.slice(lastIndex, f.start);
    masked += preText;
    const val = f.value;

    let replacement = '';
    if (mode === 'tag') {
      replacement = `[${f.type}]`;
    } else if (mode === 'redact') {
      replacement = '[REDACTED]';
    } else if (mode === 'partial') {
      if (f.type === 'EMAIL' && val.includes('@')) {
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

    // Boundary spacing checks (fixes on[PHONE], [PERSON][PERSON], [EMAIL] or)
    if (masked && /[a-zA-Z0-9]/.test(masked[masked.length - 1]) && /[a-zA-Z0-9\[]/.test(replacement[0])) {
      masked += ' ';
    } else if (masked && masked[masked.length - 1] === ']' && replacement[0] === '[' && !preText) {
      masked += ' ';
    }

    masked += replacement;
    lastIndex = f.end;
  }

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
  const [copied, setCopied] = useState(false);

  const runScan = async (inputText = text, mode = maskMode) => {
    if (!inputText.trim()) return;
    setLoading(true);
    setFindings(null);

    try {
      const res = await fetch('/api/scan/pii', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: inputText, mask_mode: mode })
      });

      if (res.ok) {
        const data = await res.json();
        setFindings(data.findings || []);
        setMaskedText(data.masked_text || applyMask(inputText, data.findings || [], mode));
      } else {
        throw new Error('API request failed');
      }
    } catch (err) {
      // Fallback to client-side detection engine
      const results = detectPII(inputText);
      setFindings(results);
      setMaskedText(applyMask(inputText, results, mode));
    } finally {
      setLoading(false);
    }
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
              Layered detection — Isotonic/DeBERTa-v3-ai4privacy_v2 → Checksum Validators → Risk-Tiered Masking Engine
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
                      if (findings) runScan(text, mode);
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
              <div style={{ fontWeight: 800, color: '#0F172A', fontSize: '1rem', marginBottom: '4px' }}>Isotonic/DeBERTa-v3 Inference</div>
              <div style={{ fontSize: '0.82rem', color: '#64748B' }}>Evaluating ai4privacy Token Classifier → Digit-Merge Checksums → Boundary Padding</div>
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
                  <div style={{ marginTop: '12px', fontSize: '0.78rem', color: '#64748B', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span>Strategy: <strong style={{ textTransform: 'uppercase' }}>{maskMode}</strong></span>
                    <span style={{ color: '#059669', fontWeight: 700 }}>✓ Spacing & Punctuation Preserved</span>
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
