const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, VerticalAlign, PageNumber, PageBreak, LevelFormat,
  TabStopType, TabStopPosition
} = require('docx');
const fs = require('fs');

const NAVY   = "0D1B2A";
const BLUE   = "1A3A5C";
const ACCENT = "1E6DB5";
const SILVER = "C8D6E5";
const LIGHT  = "EAF1F8";
const WHITE  = "FFFFFF";
const DARK   = "0D1B2A";
const GRAY   = "4A5568";
const LGRAY  = "F4F7FA";
const RED    = "C0392B";
const GREEN  = "1A6B3C";
const AMBER  = "B7600A";

function h1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 400, after: 160 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: ACCENT, space: 6 } },
    children: [new TextRun({ text, font: "Arial", size: 36, bold: true, color: NAVY })]
  });
}

function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 280, after: 100 },
    children: [new TextRun({ text, font: "Arial", size: 28, bold: true, color: BLUE })]
  });
}

function body(text, opts = {}) {
  return new Paragraph({
    spacing: { before: 60, after: 60 },
    children: [new TextRun({ text, font: "Arial", size: 22, color: opts.color || "2D3748", bold: opts.bold || false })]
  });
}

function bullet(text, level = 0) {
  return new Paragraph({
    numbering: { reference: "bullets", level },
    spacing: { before: 40, after: 40 },
    children: [new TextRun({ text, font: "Arial", size: 21, color: "2D3748" })]
  });
}

function numbered(text, level = 0) {
  return new Paragraph({
    numbering: { reference: "numbers", level },
    spacing: { before: 40, after: 40 },
    children: [new TextRun({ text, font: "Arial", size: 21, color: "2D3748" })]
  });
}

function spacer(lines = 1) {
  return new Paragraph({ spacing: { before: lines * 80, after: 0 }, children: [new TextRun("")] });
}

function pageBreak() {
  return new Paragraph({ children: [new PageBreak()] });
}

function sectionBanner(text) {
  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: [9360],
    rows: [new TableRow({ children: [
      new TableCell({
        width: { size: 9360, type: WidthType.DXA },
        shading: { fill: NAVY, type: ShadingType.CLEAR },
        margins: { top: 160, bottom: 160, left: 240, right: 240 },
        borders: { top: { style: BorderStyle.NONE }, bottom: { style: BorderStyle.NONE }, left: { style: BorderStyle.NONE }, right: { style: BorderStyle.NONE } },
        children: [new Paragraph({ alignment: AlignmentType.LEFT, children: [new TextRun({ text, font: "Arial", size: 28, bold: true, color: WHITE, allCaps: true })] })]
      })
    ]})]
  });
}

const titlePage = [
  spacer(4),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 120 }, children: [new TextRun({ text: "FAFO", font: "Arial", size: 96, bold: true, color: NAVY })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 80 }, children: [new TextRun({ text: "Facts · Accountability · Forensics · Observation", font: "Arial", size: 30, color: ACCENT, italics: true })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 200 }, children: [new TextRun({ text: "INCIDENT PRESERVATION SYSTEM", font: "Arial", size: 36, bold: true, color: BLUE, allCaps: true })] }),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [9360],
    rows: [new TableRow({ children: [new TableCell({
      width: { size: 9360, type: WidthType.DXA },
      shading: { fill: NAVY, type: ShadingType.CLEAR },
      margins: { top: 240, bottom: 240, left: 360, right: 360 },
      borders: { top: { style: BorderStyle.NONE }, bottom: { style: BorderStyle.NONE }, left: { style: BorderStyle.NONE }, right: { style: BorderStyle.NONE } },
      children: [
        new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "MASTER PROJECT PLAN", font: "Arial", size: 32, bold: true, color: WHITE, allCaps: true })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Full Development Lifecycle · Use Cases · Implementation", font: "Arial", size: 22, color: SILVER, italics: true })] }),
      ]
    })] })]
  }),
  spacer(2),
  new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "PREPARED FOR: ANTIGRAVITY", font: "Arial", size: 24, bold: true, color: NAVY, allCaps: true })] }),
  pageBreak(),
];

const section1 = [
  sectionBanner("Section 1 — Project Overview"),
  spacer(1),
  h1("1. What Is FAFO?"),
  body("FAFO (Facts, Accountability, Forensics, and Observation) is a private, secure, enterprise-grade cybersecurity evidence preservation and incident documentation platform."),
  pageBreak(),
];

const doc = new Document({
  numbering: {
    config: [
      { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "numbers", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    ]
  },
  sections: [{
    properties: {
      page: {
        size: { width: 12240, height: 15840 }, // US Letter
        margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 }
      }
    },
    children: [
      ...titlePage,
      ...section1
    ]
  }]
});

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync("FAFO_Master_Project_Plan.docx", buffer);
  console.log("Successfully generated FAFO_Master_Project_Plan.docx");
});
