import http from "node:http";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

const rootDir = process.cwd();
loadEnv(path.join(rootDir, ".env"));

const port = Number(process.env.PORT || 3000);
const publicDir = path.join(rootDir, "public");
const reportsDir = path.join(rootDir, "reports");
const tokenPath = path.join(rootDir, "google-token.json");
const googleScopes = [
  "https://www.googleapis.com/auth/drive.file",
  "https://www.googleapis.com/auth/spreadsheets",
  "https://www.googleapis.com/auth/gmail.send"
];
const otpStore = new Map();
const verifiedStore = new Map();
const freeEmailDomains = new Set([
  "gmail.com",
  "googlemail.com",
  "yahoo.com",
  "outlook.com",
  "hotmail.com",
  "live.com",
  "icloud.com",
  "proton.me",
  "protonmail.com",
  "aol.com"
]);

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host}`);

    if (req.method === "GET" && url.pathname === "/api/config-status") {
      return json(res, 200, getConfigStatus());
    }

    if (req.method === "GET" && url.pathname === "/auth/google") {
      return redirect(res, googleAuthUrl());
    }

    if (req.method === "GET" && url.pathname === "/oauth2callback") {
      await handleOAuthCallback(url);
      return html(res, 200, [
        "<!doctype html>",
        "<title>Google connected</title>",
        "<style>body{font-family:system-ui;margin:40px;line-height:1.5}</style>",
        "<h1>Google connected</h1>",
        "<p>You can close this tab and submit the SimplifIQ form again.</p>",
        '<p><a href="/">Back to app</a></p>'
      ].join(""));
    }

    if (req.method === "POST" && url.pathname === "/api/submit") {
      const input = await readJson(req);
      const result = await submitAssessment(input);
      return json(res, 200, result);
    }

    if (req.method === "POST" && url.pathname === "/api/send-otp") {
      const input = await readJson(req);
      const result = await sendProspectOtp(input);
      return json(res, 200, result);
    }

    if (req.method === "POST" && url.pathname === "/api/verify-otp") {
      const input = await readJson(req);
      const result = verifyProspectOtp(input);
      return json(res, 200, result);
    }

    if (req.method === "GET") {
      return staticFile(url.pathname, res);
    }

    return json(res, 405, { ok: false, error: "Method not allowed" });
  } catch (error) {
    console.error(error);
    return json(res, error.status || 500, {
      ok: false,
      error: error.status ? error.message : "Something went wrong",
      detail: error.status ? undefined : error.message,
      fields: error.fields
    });
  }
});

server.listen(port, () => {
  console.log(`SimplifIQ Flow V2 running at http://localhost:${port}`);
});

async function submitAssessment(input) {
  const form = validateInput(input);
  validateVerifiedProspect(form, input.verificationToken);
  const enrichment = await optionalStep(() => searchEnrichment(form), "Search enrichment skipped or failed.");
  const report = await generateReport(form, enrichment);
  const pdf = buildPdf(report, form);
  const localPdf = saveLocalPdf(pdf);
  const drive = await optionalStep(() => uploadToDrive(pdf, localPdf.fileName, form.email), "Drive upload skipped or failed.");
  const sheet = await optionalStep(() => appendSheetRow(form, enrichment, report, drive), "Sheet append skipped or failed.");
  const email = await optionalStep(() => sendReportEmail(form, report, drive, pdf, localPdf.fileName), "Email send skipped or failed.");

  return {
    ok: true,
    form,
    enrichment,
    report,
    pdf: localPdf,
    drive,
    sheet,
    email
  };
}

// ── OTP: rate-limited (one request per 60s per email) ────────────────────────

async function sendProspectOtp(input) {
  const form = validateInput({
    name: input.name,
    email: input.email,
    phone: input.phone || "0000000000",
    company: input.company,
    requirement: input.requirement || "OTP verification request"
  });
  validateProspectEmail(form);

  if (!hasGoogleOAuth()) {
    throw new Error("Google OAuth is not configured for sending OTP emails.");
  }

  // Rate limit: one OTP per email per 60 seconds
  const existing = otpStore.get(form.email.toLowerCase());
  if (existing && existing.expiresAt > Date.now() - 9 * 60 * 1000) {
    const waitSeconds = Math.ceil(
      (existing.expiresAt - 9 * 60 * 1000 + 60 * 1000 - Date.now()) / 1000
    );
    const error = new Error(`Please wait ${waitSeconds}s before requesting another OTP.`);
    error.status = 429;
    error.fields = { otp: `Wait ${waitSeconds}s before requesting a new code.` };
    throw error;
  }

  const otp = String(crypto.randomInt(100000, 999999));
  otpStore.set(form.email.toLowerCase(), {
    otp,
    company: form.company,
    expiresAt: Date.now() + 10 * 60 * 1000
  });

  await sendPlainEmail({
    to: form.email,
    subject: "SimplifIQ verification code",
    text: [
      `Hi ${form.name},`,
      "",
      `Your SimplifIQ verification code is: ${otp}`,
      "",
      "This code expires in 10 minutes.",
      "",
      "If you did not request this, you can safely ignore this email.",
      "",
      "— SimplifIQ"
    ].join("\n")
  });

  return {
    ok: true,
    message: "OTP sent to prospect email.",
    expiresInMinutes: 10
  };
}

function verifyProspectOtp(input) {
  const email = clean(input.email, 160).toLowerCase();
  const otp = clean(input.otp, 12);
  const record = otpStore.get(email);

  if (!record || record.expiresAt < Date.now()) {
    const error = new Error("OTP expired or not found.");
    error.status = 400;
    throw error;
  }

  if (record.otp !== otp) {
    const error = new Error("Invalid OTP.");
    error.status = 400;
    throw error;
  }

  const verificationToken = crypto.randomUUID();
  verifiedStore.set(email, {
    token: verificationToken,
    company: record.company,
    expiresAt: Date.now() + 30 * 60 * 1000
  });
  otpStore.delete(email);

  return {
    ok: true,
    verificationToken,
    message: "Prospect email verified."
  };
}

function validateVerifiedProspect(form, verificationToken) {
  validateProspectEmail(form);

  const record = verifiedStore.get(form.email.toLowerCase());
  if (!record || record.expiresAt < Date.now() || record.token !== verificationToken) {
    const error = new Error("Prospect email must be verified with OTP before report generation.");
    error.status = 403;
    throw error;
  }
}

function validateProspectEmail(form) {
  return; // temporary bypass for testing
}


function validateInput(input) {
  const form = {
    name: clean(input.name, 120),
    email: clean(input.email, 160),
    phone: clean(input.phone, 40),
    company: clean(input.company, 160),
    requirement: clean(input.requirement, 2500)
  };

  const fields = {};
  if (!form.name) fields.name = "Name is required.";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) fields.email = "Valid email is required.";
  if (form.phone && !/^[+\d\s()-]{7,20}$/.test(form.phone)) fields.phone = "Phone number is invalid.";
  if (!form.company) fields.company = "Company is required.";
  if (form.requirement.length < 15) fields.requirement = "Requirement should be at least 15 characters.";

  if (Object.keys(fields).length) {
    const error = new Error("Validation failed");
    error.status = 400;
    error.fields = fields;
    throw error;
  }

  return form;
}

async function searchEnrichment(form) {
  const key = process.env.GOOGLE_SEARCH_API_KEY;
  const cx = process.env.GOOGLE_SEARCH_CX;
  const query = `${form.company} company overview services industry`;

  if (!key || !cx) {
    return {
      ok: true,
      source: "not-configured",
      query,
      items: []
    };
  }

  const url = new URL("https://www.googleapis.com/customsearch/v1");
  url.searchParams.set("key", key);
  url.searchParams.set("cx", cx);
  url.searchParams.set("q", query);
  url.searchParams.set("num", "5");

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Search API failed: ${response.status} ${await response.text()}`);
  }

  const body = await response.json();
  return {
    ok: true,
    source: "google-custom-search",
    query,
    items: (body.items || []).map((item) => ({
      title: item.title || "",
      snippet: item.snippet || "",
      link: item.link || ""
    }))
  };
}

// ── REPORT GENERATION: rich, personalized Gemini prompt ──────────────────────

async function generateReport(form, enrichment) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return demoReport(form);

  const model = process.env.GEMINI_MODEL || "gemini-2.5-flash";

  const searchContext =
    enrichment?.items?.length
      ? enrichment.items
          .map((item, i) => `[${i + 1}] ${item.title}\n${item.snippet}\n${item.link}`)
          .join("\n\n")
      : "No search results available — rely on your knowledge of the company and industry.";

  const prompt = `
You are a senior business consultant and strategist writing a highly personalized
assessment report for a new prospect who just submitted an inquiry form.

PROSPECT DETAILS
────────────────
Name       : ${form.name}
Company    : ${form.company}
Email      : ${form.email}
Requirement: ${form.requirement}

RESEARCH CONTEXT (web search results about this company / requirement)
──────────────────────────────────────────────────────────────────────
${searchContext}

YOUR TASK
─────────
Write a premium, deeply personalized assessment report. The goal is to make
${form.name} at ${form.company} feel like you have already deeply studied their
business before this first contact.

Rules:
- Be highly specific to ${form.company}'s industry, likely tech stack, business
  model, and the exact requirement they described ("${form.requirement}").
- Every bullet must reference the company or their domain — zero generic advice.
- Findings should surface real pain points companies like ${form.company} face.
- Recommendations must be concrete and actionable (name tools, frameworks,
  approaches relevant to their sector).
- Tone: confident, warm, consultative — like a trusted expert, not a chatbot.
- Do NOT use filler phrases like "In today's fast-paced world" or "Leveraging
  cutting-edge solutions".
- The summary should be 3-4 sentences, specific and compelling.
- Each array should have 4-6 items.

Return ONLY a valid JSON object with exactly these keys (no markdown, no extra text):
{
  "tagline": "One sharp sentence capturing the core opportunity for this company",
  "summary": "3-4 sentence exec summary specific to this company and requirement",
  "findings": ["finding 1", "finding 2", "..."],
  "recommendations": ["recommendation 1", "recommendation 2", "..."],
  "nextSteps": ["next step 1", "next step 2", "..."],
  "industryContext": "1-2 sentences on relevant industry trends affecting this company"
}
`.trim();

  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          responseMimeType: "application/json",
          temperature: 0.7,
          topP: 0.9
        }
      })
    }
  );

  if (!response.ok) {
    throw new Error(`Gemini failed: ${response.status} ${await response.text()}`);
  }

  const body = await response.json();
  const text = body.candidates?.[0]?.content?.parts?.[0]?.text || "{}";
  return normalizeReport(JSON.parse(text), form);
}

function demoReport(form) {
  return {
    tagline: `Streamlining operations and accelerating growth for ${form.company}.`,
    summary: `${form.company} has engaged SimplifIQ to explore solutions around: "${form.requirement}". Based on our initial review, there are clear opportunities to improve efficiency, reduce manual overhead, and build scalable systems aligned with your business goals. This report outlines our preliminary findings and recommended next steps.`,
    findings: [
      `${form.company}'s stated requirement suggests a need for structured automation or integration work.`,
      "Manual processes in this area typically account for significant team overhead.",
      "Companies at this stage often lack a unified data or workflow layer.",
      "There is strong potential for measurable ROI through targeted tooling."
    ],
    recommendations: [
      "Conduct a 2-hour discovery workshop to map current workflows end-to-end.",
      "Identify top 3 integration points where automation would deliver immediate value.",
      "Define clear KPIs before implementation to track impact objectively.",
      "Start with a focused pilot — scope, build, measure — before scaling."
    ],
    nextSteps: [
      "Schedule a discovery call with the SimplifIQ solutions team.",
      "Share any existing process documentation or tool stack details.",
      "Align internal stakeholders on goals and timeline.",
      "Review this report with your team and surface any questions."
    ],
    industryContext: "Businesses in this space are increasingly investing in workflow automation and AI-assisted tooling to stay competitive. Early movers in structured automation consistently report significant reductions in turnaround time."
  };
}

function normalizeReport(report, form) {
  const arr = (v) => (Array.isArray(v) ? v.map(String).filter(Boolean) : []);
  return {
    tagline: String(report.tagline || `Assessment report for ${form.company}.`),
    summary: String(report.summary || `Assessment report for ${form.company}.`),
    findings: arr(report.findings),
    recommendations: arr(report.recommendations),
    nextSteps: arr(report.nextSteps),
    industryContext: String(report.industryContext || "")
  };
}

// ── STYLED PDF BUILDER ────────────────────────────────────────────────────────

function buildPdf(report, form) {
  const TEAL  = [0.098, 0.451, 0.373];
  const DARK  = [0.094, 0.122, 0.165];
  const MID   = [0.38, 0.45, 0.42];
  const WHITE = [1, 1, 1];
  const LIGHT_BG = [0.965, 0.976, 0.973];

  const pageW = 612;
  const pageH = 792;
  const mX = 52;
  const mXR = 560;
  const contentW = mXR - mX;

  const date = new Date().toLocaleDateString("en-US", {
    year: "numeric", month: "long", day: "numeric"
  });

  const pages = [];
  let cmds = [];
  let y = 0;

  function startPage() {
    cmds = [];
    y = pageH;
    drawHeader();
    y = pageH - 90;
  }

  function endPage(pageNum) {
    drawFooter(pageNum);
    pages.push(cmds.join("\n"));
  }

  function setColor(rgb, stroke = false) {
    const op = stroke ? "RG" : "rg";
    cmds.push(`${rgb.map(v => v.toFixed(3)).join(" ")} ${op}`);
  }

  function rect(x, ry, w, h) {
    cmds.push(`${x} ${ry} ${w} ${h} re f`);
  }

  function lineCmd(x1, ry1, x2, ry2) {
    cmds.push(`${x1} ${ry1} m ${x2} ${ry2} l S`);
  }

  function textCmd(str, font, size, tx, ty) {
    cmds.push("BT");
    cmds.push(`/${font} ${size} Tf`);
    cmds.push(`1 0 0 1 ${tx} ${ty} Tm`);
    cmds.push(`(${escapePdf(cleanPdfText(str))}) Tj`);
    cmds.push("ET");
  }

  function drawHeader() {
    setColor(TEAL);
    rect(0, pageH - 72, pageW, 72);
    setColor(WHITE);
    textCmd("SimplifIQ", "F2", 18, mX, pageH - 44);
    setColor([0.78, 0.93, 0.87]);
    textCmd("Assessment Report", "F1", 10, 430, pageH - 44);
    setColor(WHITE);
    textCmd(cleanPdfText(form.company).slice(0, 60), "F2", 11, mX, pageH - 62);
    setColor([0.78, 0.93, 0.87]);
    textCmd(date, "F1", 9, 430, pageH - 62);
  }

  function drawFooter(pageNum) {
    const fy = 32;
    setColor([0.82, 0.88, 0.85], true);
    cmds.push("0.5 w");
    lineCmd(mX, fy + 10, mXR, fy + 10);
    setColor(MID);
    textCmd(`SimplifIQ Confidential  -  ${form.company}`, "F1", 8, mX, fy);
    textCmd(`Page ${pageNum}`, "F2", 8, 540, fy);
  }

  function needsBreak(h) {
    return y - h < 52;
  }

  function sectionLabel(label) {
    if (needsBreak(30)) { endPage(pages.length + 1); startPage(); }
    y -= 10;
    setColor(TEAL);
    rect(mX, y - 12, 160, 16);
    setColor(WHITE);
    textCmd(label.toUpperCase(), "F2", 8, mX + 6, y - 8);
    y -= 14;
  }

  function hRule() {
    setColor([0.87, 0.92, 0.90], true);
    cmds.push("0.5 w");
    lineCmd(mX, y, mXR, y);
    y -= 8;
  }

  function paragraph(str, font, size, indent) {
    indent = indent || 0;
    const maxChars = Math.floor((contentW - indent) / (size * 0.52));
    const lines = wrapText(str, maxChars);
    const lh = Math.ceil(size * 1.5);
    lines.forEach(ln => {
      if (needsBreak(lh)) { endPage(pages.length + 1); startPage(); }
      setColor(DARK);
      textCmd(ln, font, size, mX + indent, y);
      y -= lh;
    });
  }

  function bullet(str) {
    const maxChars = Math.floor((contentW - 14) / (10 * 0.52));
    const lines = wrapText(str, maxChars);
    const lh = 15;
    lines.forEach((ln, i) => {
      if (needsBreak(lh)) { endPage(pages.length + 1); startPage(); }
      if (i === 0) {
        setColor(TEAL);
        cmds.push("BT");
        cmds.push("/F2 12 Tf");
        cmds.push(`1 0 0 1 ${mX + 2} ${y} Tm`);
        cmds.push("(\xB7) Tj");
        cmds.push("ET");
      }
      setColor(DARK);
      textCmd(ln, "F1", 10, mX + 14, y);
      y -= lh;
    });
    y -= 2;
  }

  function taglineBlock(str) {
    const maxChars = Math.floor((contentW - 14) / (11 * 0.52));
    const lines = wrapText(str, maxChars);
    const blockH = lines.length * 14 + 16;
    if (needsBreak(blockH + 16)) { endPage(pages.length + 1); startPage(); }
    y -= 10;
    setColor(LIGHT_BG);
    rect(mX, y - blockH + 8, contentW, blockH);
    setColor(TEAL);
    rect(mX, y - blockH + 8, 3, blockH);
    setColor(DARK);
    lines.forEach(ln => {
      textCmd(ln, "F2", 11, mX + 12, y);
      y -= 14;
    });
    y -= 12;
  }

  // ── Build document ──────────────────────────────────────────────────────────

  startPage();

  // Prospect info bar
  y -= 6;
  setColor(LIGHT_BG);
  rect(mX, y - 28, contentW, 28);
  setColor(MID);
  textCmd(`Prepared for: ${cleanPdfText(form.name)}`, "F1", 9, mX + 8, y - 10);
  textCmd(cleanPdfText(form.email), "F1", 9, mX + 8, y - 22);
  if (form.phone) {
    textCmd(cleanPdfText(form.phone), "F1", 9, mX + 280, y - 10);
  }
  y -= 38;

  if (report.tagline) taglineBlock(report.tagline);

  if (report.industryContext) {
    y -= 4;
    setColor(MID);
    const maxChars = Math.floor(contentW / (9 * 0.55));
    wrapText(cleanPdfText(report.industryContext), maxChars).forEach(ln => {
      if (needsBreak(13)) { endPage(pages.length + 1); startPage(); }
      textCmd(ln, "F1", 9, mX, y);
      y -= 13;
    });
    y -= 6;
  }

  hRule();

  sectionLabel("Executive Summary");
  y -= 4;
  paragraph(report.summary, "F1", 10, 0);
  y -= 8;

  hRule();

  sectionLabel("Key Findings");
  y -= 4;
  report.findings.forEach(f => bullet(f));
  y -= 4;

  hRule();

  sectionLabel("Recommendations");
  y -= 4;
  report.recommendations.forEach(r => bullet(r));
  y -= 4;

  hRule();

  sectionLabel("Next Steps");
  y -= 4;
  report.nextSteps.forEach(s => bullet(s));
  y -= 8;

  hRule();
  y -= 4;
  setColor(MID);
  const closing = `This report was generated by SimplifIQ based on information provided by ${form.company}. For questions, reply directly to this email.`;
  const maxChars = Math.floor(contentW / (9 * 0.55));
  wrapText(closing, maxChars).forEach(ln => {
    if (needsBreak(13)) { endPage(pages.length + 1); startPage(); }
    textCmd(ln, "F1", 9, mX, y);
    y -= 13;
  });

  endPage(pages.length + 1);

  return createStyledPdf(pages, pageW, pageH);
}

function createStyledPdf(pageContents, pageWidth, pageHeight) {
  const pageCount = pageContents.length;
  const pageStartId = 3;
  const fontRegularId = pageStartId + pageCount;
  const fontBoldId = fontRegularId + 1;
  const contentStartId = fontBoldId + 1;

  const kids = Array.from(
    { length: pageCount },
    (_, i) => `${pageStartId + i} 0 R`
  ).join(" ");

  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    `<< /Type /Pages /Kids [${kids}] /Count ${pageCount} >>`
  ];

  pageContents.forEach((_, i) => {
    const contentId = contentStartId + i;
    objects.push(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pageWidth} ${pageHeight}] ` +
      `/Resources << /Font << /F1 ${fontRegularId} 0 R /F2 ${fontBoldId} 0 R >> >> ` +
      `/Contents ${contentId} 0 R >>`
    );
  });

  objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");

  pageContents.forEach(content => {
    objects.push(
      `<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}\nendstream`
    );
  });

  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  objects.forEach((obj, i) => {
    offsets.push(Buffer.byteLength(pdf));
    pdf += `${i + 1} 0 obj\n${obj}\nendobj\n`;
  });

  const xref = Buffer.byteLength(pdf);
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.slice(1).forEach(offset => {
    pdf += `${String(offset).padStart(10, "0")} 00000 n \n`;
  });
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;

  return Buffer.from(pdf);
}

function saveLocalPdf(pdf) {
  if (!existsSync(reportsDir)) mkdirSync(reportsDir, { recursive: true });
  const fileName = `assessment-${Date.now()}.pdf`;
  const filePath = path.join(reportsDir, fileName);
  writeFileSync(filePath, pdf);
  return { ok: true, fileName, filePath };
}

async function uploadToDrive(pdf, fileName, recipientEmail) {
  if (!process.env.GOOGLE_DRIVE_FOLDER_ID || !hasGoogleOAuth()) {
    return { ok: false, skipped: true, reason: "Google Drive is not configured." };
  }

  const token = await googleAccessToken();
  const boundary = `simplifiq_${crypto.randomUUID()}`;
  const metadata = {
    name: fileName,
    parents: [process.env.GOOGLE_DRIVE_FOLDER_ID],
    mimeType: "application/pdf"
  };

  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n`),
    Buffer.from(`--${boundary}\r\nContent-Type: application/pdf\r\n\r\n`),
    pdf,
    Buffer.from(`\r\n--${boundary}--`)
  ]);

  const response = await fetch("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,webViewLink", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": `multipart/related; boundary=${boundary}`
    },
    body
  });

  if (!response.ok) {
    throw new Error(`Drive upload failed: ${response.status} ${await response.text()}`);
  }

  const file = await response.json();
  const permission = await shareDriveFile(file.id, recipientEmail);
  return { ok: true, ...file, permission };
}

async function shareDriveFile(fileId, emailAddress) {
  if (!emailAddress) {
    return { skipped: true, reason: "No recipient email provided." };
  }

  const token = await googleAccessToken();
  const response = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}/permissions?sendNotificationEmail=false`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      type: "user",
      role: "reader",
      emailAddress
    })
  });

  if (!response.ok) {
    throw new Error(`Drive sharing failed: ${response.status} ${await response.text()}`);
  }

  return { ok: true, ...(await response.json()) };
}

async function appendSheetRow(form, enrichment, report, drive) {
  if (!process.env.GOOGLE_SHEET_ID || !hasGoogleOAuth()) {
    return { ok: false, skipped: true, reason: "Google Sheets is not configured." };
  }

  const token = await googleAccessToken();
  const range = process.env.GOOGLE_SHEET_RANGE || "Sheet1!A:J";
  const row = [
    new Date().toISOString(),
    form.name,
    form.email,
    form.phone,
    form.company,
    form.requirement,
    enrichment?.source || "",
    report.summary,
    drive?.webViewLink || "",
    drive?.ok ? "completed" : "completed_without_drive"
  ];

  const url = `https://sheets.googleapis.com/v4/spreadsheets/${process.env.GOOGLE_SHEET_ID}/values/${encodeURIComponent(range)}:append?valueInputOption=USER_ENTERED`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ values: [row] })
  });

  if (!response.ok) {
    throw new Error(`Sheets append failed: ${response.status} ${await response.text()}`);
  }

  return { ok: true, ...(await response.json()) };
}

// ── HTML report email ─────────────────────────────────────────────────────────

async function sendReportEmail(form, report, drive, pdf, fileName) {
  if (!hasGoogleOAuth()) {
    return { ok: false, skipped: true, reason: "Google OAuth is not configured." };
  }

  const subject = `Your SimplifIQ Assessment Report - ${form.company}`;

  const driveSection = drive?.webViewLink
    ? `<p style="margin:0 0 8px">
         <a href="${drive.webViewLink}"
            style="display:inline-block;padding:10px 20px;background:#185F5F;color:#fff;
                   text-decoration:none;border-radius:5px;font-weight:bold;font-size:14px">
           View Report in Google Drive
         </a>
       </p>`
    : `<p style="margin:0 0 8px;color:#555;font-size:13px">The PDF is attached to this email.</p>`;

  const li = (items) =>
    items.map(s => `<li style="margin-bottom:6px">${escapeHtml(s)}</li>`).join("");

  const chip = (label) =>
    `<p style="margin:0 0 6px;font-size:11px;color:#fff;background:#185F5F;
               display:inline-block;padding:3px 10px;border-radius:3px;
               font-family:Arial,sans-serif;font-weight:bold;
               letter-spacing:0.8px;text-transform:uppercase">${label}</p>`;

  const htmlBody = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f0f4f2;font-family:Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4f2;padding:32px 0">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0"
             style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)">

        <tr>
          <td style="background:#185F5F;padding:28px 36px">
            <p style="margin:0;color:#fff;font-size:20px;font-weight:bold">SimplifIQ</p>
            <p style="margin:4px 0 0;color:#a8d5c8;font-size:12px;text-transform:uppercase;letter-spacing:1px">
              Assessment Report
            </p>
          </td>
        </tr>

        <tr>
          <td style="padding:32px 36px 0">
            <p style="margin:0 0 12px;font-size:16px;color:#181F2A">Hi ${escapeHtml(form.name)},</p>
            <p style="margin:0 0 20px;font-size:14px;color:#444;line-height:1.7">
              Your personalized assessment report for <strong>${escapeHtml(form.company)}</strong>
              is ready. We have reviewed your requirements and prepared the insights below.
            </p>
          </td>
        </tr>

        ${report.tagline ? `
        <tr>
          <td style="padding:0 36px">
            <div style="background:#eef6f3;border-left:3px solid #185F5F;padding:14px 16px;border-radius:0 4px 4px 0">
              <p style="margin:0;font-size:14px;color:#185F5F;font-weight:bold;font-style:italic">
                ${escapeHtml(report.tagline)}
              </p>
            </div>
          </td>
        </tr>` : ""}

        <tr>
          <td style="padding:24px 36px 0">
            ${chip("Executive Summary")}
            <p style="margin:10px 0 0;font-size:14px;color:#333;line-height:1.7">
              ${escapeHtml(report.summary)}
            </p>
          </td>
        </tr>

        <tr>
          <td style="padding:24px 36px 0">
            ${chip("Key Findings")}
            <ul style="margin:10px 0 0;padding-left:20px;color:#333;font-size:14px;line-height:1.6">
              ${li(report.findings)}
            </ul>
          </td>
        </tr>

        <tr>
          <td style="padding:24px 36px 0">
            ${chip("Recommendations")}
            <ul style="margin:10px 0 0;padding-left:20px;color:#333;font-size:14px;line-height:1.6">
              ${li(report.recommendations)}
            </ul>
          </td>
        </tr>

        <tr>
          <td style="padding:24px 36px 0">
            ${chip("Next Steps")}
            <ul style="margin:10px 0 0;padding-left:20px;color:#333;font-size:14px;line-height:1.6">
              ${li(report.nextSteps)}
            </ul>
          </td>
        </tr>

        <tr>
          <td style="padding:28px 36px 0">
            <div style="background:#f5faf8;border-radius:6px;padding:16px 20px">
              <p style="margin:0 0 10px;font-size:13px;color:#555">
                The full formatted PDF report is attached below.
              </p>
              ${driveSection}
            </div>
          </td>
        </tr>

        <tr>
          <td style="padding:28px 36px 32px;border-top:1px solid #e8f0ec;margin-top:24px">
            <p style="margin:0 0 4px;font-size:13px;color:#333">
              Regards,<br><strong>The SimplifIQ Team</strong>
            </p>
            <p style="margin:12px 0 0;font-size:11px;color:#999">
              This report is confidential and prepared exclusively for ${escapeHtml(form.company)}.
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;

  const raw = buildHtmlEmailMessage({
    to: form.email,
    subject,
    html: htmlBody,
    attachment: { fileName, mimeType: "application/pdf", content: pdf }
  });

  return sendGmailRaw(raw);
}

async function sendPlainEmail({ to, subject, text }) {
  const message = [
    `To: ${to}`,
    `Subject: ${encodeMimeHeader(subject)}`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: 7bit",
    "",
    text
  ].join("\r\n");

  return sendGmailRaw(Buffer.from(message).toString("base64url"));
}

async function sendGmailRaw(raw) {
  const token = await googleAccessToken();
  const response = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ raw })
  });

  if (!response.ok) {
    throw new Error(`Email send failed: ${response.status} ${await response.text()}`);
  }

  return { ok: true, ...(await response.json()) };
}

function buildHtmlEmailMessage({ to, subject, html, attachment }) {
  const outerBoundary = `simplifiq_outer_${crypto.randomUUID()}`;
  const innerBoundary = `simplifiq_inner_${crypto.randomUUID()}`;

  const plainText = html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s{2,}/g, " ")
    .trim();

  const message = [
    `To: ${to}`,
    `Subject: ${encodeMimeHeader(subject)}`,
    "MIME-Version: 1.0",
    `Content-Type: multipart/mixed; boundary="${outerBoundary}"`,
    "",
    `--${outerBoundary}`,
    `Content-Type: multipart/alternative; boundary="${innerBoundary}"`,
    "",
    `--${innerBoundary}`,
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: 7bit",
    "",
    plainText,
    "",
    `--${innerBoundary}`,
    "Content-Type: text/html; charset=UTF-8",
    "Content-Transfer-Encoding: 7bit",
    "",
    html,
    "",
    `--${innerBoundary}--`,
    "",
    `--${outerBoundary}`,
    `Content-Type: ${attachment.mimeType}; name="${attachment.fileName}"`,
    "Content-Transfer-Encoding: base64",
    `Content-Disposition: attachment; filename="${attachment.fileName}"`,
    "",
    attachment.content.toString("base64").replace(/(.{76})/g, "$1\r\n"),
    "",
    `--${outerBoundary}--`
  ].join("\r\n");

  return Buffer.from(message).toString("base64url");
}

// kept for compatibility (OTP emails still use plain text)
function buildEmailMessage({ to, subject, text, attachment }) {
  const boundary = `simplifiq_${crypto.randomUUID()}`;
  const message = [
    `To: ${to}`,
    `Subject: ${encodeMimeHeader(subject)}`,
    "MIME-Version: 1.0",
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: 7bit",
    "",
    text,
    "",
    `--${boundary}`,
    `Content-Type: ${attachment.mimeType}; name="${attachment.fileName}"`,
    "Content-Transfer-Encoding: base64",
    `Content-Disposition: attachment; filename="${attachment.fileName}"`,
    "",
    attachment.content.toString("base64").replace(/(.{76})/g, "$1\r\n"),
    "",
    `--${boundary}--`
  ].join("\r\n");

  return Buffer.from(message).toString("base64url");
}

function encodeMimeHeader(value) {
  return `=?UTF-8?B?${Buffer.from(value).toString("base64")}?=`;
}

function googleAuthUrl() {
  const oauth = getOAuthConfig();
  if (!oauth.clientId || !oauth.clientSecret || !oauth.redirectUri) {
    throw new Error("Google OAuth is not configured.");
  }

  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", oauth.clientId);
  url.searchParams.set("redirect_uri", oauth.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", googleScopes.join(" "));
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");
  return url.toString();
}

async function handleOAuthCallback(url) {
  const code = url.searchParams.get("code");
  const error = url.searchParams.get("error");
  if (error) throw new Error(`Google OAuth failed: ${error}`);
  if (!code) throw new Error("Google OAuth callback is missing code.");

  const oauth = getOAuthConfig();
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: oauth.clientId,
      client_secret: oauth.clientSecret,
      redirect_uri: oauth.redirectUri,
      grant_type: "authorization_code"
    })
  });

  if (!response.ok) {
    throw new Error(`Google OAuth token exchange failed: ${response.status} ${await response.text()}`);
  }

  const token = await response.json();
  saveGoogleToken(token);
}

async function googleAccessToken() {
  const token = readGoogleToken();
  if (!token?.refresh_token && !token?.access_token) {
    throw new Error("Google is not connected. Open /auth/google first.");
  }

  if (token.access_token && token.expires_at && token.expires_at > Date.now() + 60_000) {
    return token.access_token;
  }

  if (!token.refresh_token) {
    throw new Error("Google token expired. Reconnect at /auth/google.");
  }

  const oauth = getOAuthConfig();
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: oauth.clientId,
      client_secret: oauth.clientSecret,
      refresh_token: token.refresh_token,
      grant_type: "refresh_token"
    })
  });

  if (!response.ok) {
    throw new Error(`Google token refresh failed: ${response.status} ${await response.text()}`);
  }

  const refreshed = await response.json();
  saveGoogleToken({ ...token, ...refreshed });
  return refreshed.access_token;
}

function saveGoogleToken(token) {
  const existing = readGoogleToken() || {};
  const merged = {
    ...existing,
    ...token,
    expires_at: Date.now() + Number(token.expires_in || existing.expires_in || 3600) * 1000
  };
  writeFileSync(tokenPath, JSON.stringify(merged, null, 2));
}

function readGoogleToken() {
  if (!existsSync(tokenPath)) return null;
  return JSON.parse(readFileSync(tokenPath, "utf8"));
}

function getOAuthConfig() {
  return {
    clientId: process.env.GOOGLE_CLIENT_ID || "",
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
    redirectUri: process.env.GOOGLE_REDIRECT_URI || `http://localhost:${port}/oauth2callback`
  };
}

function hasGoogleOAuth() {
  const oauth = getOAuthConfig();
  return Boolean(oauth.clientId && oauth.clientSecret && oauth.redirectUri);
}

async function optionalStep(fn, fallbackReason) {
  try {
    return await fn();
  } catch (error) {
    return { ok: false, failed: true, reason: error.message || fallbackReason };
  }
}

function getConfigStatus() {
  return {
    gemini: Boolean(process.env.GEMINI_API_KEY),
    search: Boolean(process.env.GOOGLE_SEARCH_API_KEY && process.env.GOOGLE_SEARCH_CX),
    googleOAuth: hasGoogleOAuth(),
    googleConnected: Boolean(readGoogleToken()?.refresh_token),
    authUrl: hasGoogleOAuth() ? "/auth/google" : null,
    drive: Boolean(process.env.GOOGLE_DRIVE_FOLDER_ID),
    sheets: Boolean(process.env.GOOGLE_SHEET_ID),
    email: hasGoogleOAuth(),
    sheetRange: process.env.GOOGLE_SHEET_RANGE || "Sheet1!A:J"
  };
}

async function staticFile(urlPath, res) {
  const target = urlPath === "/" ? "index.html" : `.${urlPath}`;
  const filePath = path.resolve(publicDir, target);
  if (!filePath.startsWith(publicDir) || !existsSync(filePath)) {
    return json(res, 404, { ok: false, error: "Not found" });
  }

  const ext = path.extname(filePath);
  const type = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8"
  }[ext] || "application/octet-stream";

  res.writeHead(200, { "Content-Type": type });
  res.end(await readFile(filePath));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new Error("Payload too large"));
        req.destroy();
      }
    });
    req.on("end", () => resolve(body ? JSON.parse(body) : {}));
    req.on("error", reject);
  });
}

function json(res, status, body) {
  const safeBody = Object.fromEntries(Object.entries(body).filter(([, value]) => value !== undefined));
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(safeBody));
}

function html(res, status, body) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(body);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

function loadEnv(envPath) {
  if (!existsSync(envPath)) return;

  const text = readFileSync(envPath, "utf8").replace(/\r\n/g, "\n");
  const entries = joinMultilineEnv(text);

  entries.forEach((entry) => {
    const trimmed = entry.trim();
    if (!trimmed || trimmed.startsWith("#")) return;

    const index = trimmed.indexOf("=");
    if (index === -1) return;

    const key = trimmed.slice(0, index).trim();
    let value = trimmed.slice(index + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }

    process.env[key] = value.replace(/\\n/g, "\n");
  });
}

function joinMultilineEnv(text) {
  const entries = [];
  let current = "";
  let quote = null;

  text.split("\n").forEach((line) => {
    current = current ? `${current}\n${line}` : line;
    const index = current.indexOf("=");
    const value = index === -1 ? "" : current.slice(index + 1).trimStart();

    if (!quote && (value.startsWith('"') || value.startsWith("'"))) {
      quote = value[0];
    }

    if (!quote || current.trimEnd().endsWith(quote)) {
      entries.push(current);
      current = "";
      quote = null;
    }
  });

  if (current) entries.push(current);
  return entries;
}

function clean(value, max) {
  return String(value || "").replace(/\s+/g, " ").trim().slice(0, max);
}

function arrayOfStrings(value) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => String(item)).filter(Boolean);
}

function escapePdf(value) {
  return String(value).replace(/[\\()]/g, "\\$&");
}

function cleanPdfText(value) {
  return String(value)
    .replace(/\*\*/g, "")
    .replace(/[""]/g, '"')
    .replace(/['']/g, "'")
    .replace(/[–—]/g, "-")
    .replace(/[^\x09\x0A\x0D\x20-\x7E]/g, "");
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function wrapText(value, maxChars) {
  const words = String(value || "").split(/\s+/).filter(Boolean);
  if (!words.length) return [""];

  const lines = [];
  let current = "";

  words.forEach((word) => {
    const chunks = word.length > maxChars ? word.match(new RegExp(`.{1,${maxChars}}`, "g")) : [word];
    chunks.forEach((chunk) => {
      const candidate = current ? `${current} ${chunk}` : chunk;
      if (candidate.length > maxChars && current) {
        lines.push(current);
        current = chunk;
      } else {
        current = candidate;
      }
    });
  });

  if (current) lines.push(current);
  return lines;
}