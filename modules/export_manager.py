import os
import io
import zipfile
import json
import csv
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from config.settings import EXPORTS_DIR, EVIDENCE_REPO_PATH, DATABASE_PATH
from database.connection import get_db_connection
from modules.audit_logger import log_action
from modules.utils import generate_uuid, get_utc_now

def generate_pdf_report(incident_id: str) -> Path:
    """Generate a highly professional, legal-ready forensic PDF report for an incident."""
    conn = get_db_connection(str(DATABASE_PATH))
    cursor = conn.cursor()
    
    # Fetch details
    cursor.execute("SELECT category, severity, status, target, description, source_url, created_at FROM incidents WHERE incident_id = ?", (incident_id,))
    incident = cursor.fetchone()
    if not incident:
        conn.close()
        raise ValueError(f"Incident {incident_id} not found.")
        
    category, severity, status, target, description, source_url, created_at = incident
    
    # Fetch Evidence
    cursor.execute("SELECT filename, file_type, file_size, file_hash, uploaded_at FROM evidence WHERE incident_id = ?", (incident_id,))
    evidence_list = cursor.fetchall()
    
    # Fetch OCR
    cursor.execute("SELECT extracted_text, confidence_score, detected_threats FROM ocr_results WHERE incident_id = ?", (incident_id,))
    ocr_list = cursor.fetchall()
    
    # Fetch AI
    cursor.execute("SELECT suggested_category, suggested_severity, threat_score, ai_confidence, reviewed_by_human FROM ai_analysis WHERE incident_id = ?", (incident_id,))
    ai_analysis = cursor.fetchone()
    
    # Fetch Audit Logs
    cursor.execute("SELECT username, action, timestamp FROM audit_logs WHERE target_id = ? ORDER BY timestamp ASC", (incident_id,))
    audit_list = cursor.fetchall()
    
    conn.close()
    
    pdf_path = EXPORTS_DIR / f"{incident_id}_Case_Summary.pdf"
    
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    
    # Define custom professional styles matching our dark navy theme
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0D1B2A"),
        spaceAfter=15
    )
    
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1E6DB5"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#333333"),
        spaceAfter=6
    )
    
    label_style = ParagraphStyle(
        'Label_Custom',
        parent=body_style,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor("#0D1B2A")
    )
    
    code_style = ParagraphStyle(
        'Code_Custom',
        parent=body_style,
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#444444")
    )

    elements = []
    
    # Header Banner
    header_data = [
        [Paragraph("<b>FAFO INCIDENT PRESERVATION SYSTEM</b>", ParagraphStyle('HText', parent=body_style, fontSize=11, textColor=colors.white, fontName='Helvetica-Bold')),
         Paragraph("<b>CONFIDENTIAL FORENSIC REPORT</b>", ParagraphStyle('HTextR', parent=body_style, fontSize=8.5, textColor=colors.white, alignment=2))]
    ]
    header_table = Table(header_data, colWidths=[300, 232])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#0D1B2A")),
        ('PADDING', (0,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 15))
    
    # Document Title
    elements.append(Paragraph(f"Case File: {incident_id}", title_style))
    elements.append(Paragraph(f"<b>Report Generated:</b> {datetime.now(timezone.utc).isoformat()[:19]} UTC", body_style))
    elements.append(Spacer(1, 10))
    
    # Section 1: Metadata Summary Table
    elements.append(Paragraph("1. Incident Metadata", h1_style))
    meta_data = [
        [Paragraph("Category", label_style), Paragraph(category, body_style), Paragraph("Initial Severity", label_style), Paragraph(severity.upper(), body_style)],
        [Paragraph("Status", label_style), Paragraph(status.upper(), body_style), Paragraph("Target Entity", label_style), Paragraph(target, body_style)],
        [Paragraph("Source URL", label_style), Paragraph(source_url or "N/A", body_style), Paragraph("Created At", label_style), Paragraph(created_at, body_style)]
    ]
    meta_table = Table(meta_data, colWidths=[90, 176, 90, 176])
    meta_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#DDDDDD")),
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#F4F6F9")),
        ('BACKGROUND', (2,0), (2,-1), colors.HexColor("#F4F6F9")),
        ('PADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 10))
    
    # Section 2: Case Description
    elements.append(Paragraph("2. Primary Incident Description", h1_style))
    elements.append(Paragraph(description, body_style))
    elements.append(Spacer(1, 10))
    
    # Section 3: AI Analysis Findings
    elements.append(Paragraph("3. FAFO AI Insights & Scoring", h1_style))
    if ai_analysis:
        s_cat, s_sev, t_score, confidence, human_approved = ai_analysis
        ai_data = [
            [Paragraph("Suggested Category", label_style), Paragraph(s_cat, body_style)],
            [Paragraph("Suggested Severity", label_style), Paragraph(s_sev.upper(), body_style)],
            [Paragraph("Threat Score", label_style), Paragraph(f"{t_score:.2f} (Scale 0.0 - 1.0)", body_style)],
            [Paragraph("Confidence Score", label_style), Paragraph(f"{confidence:.1f}%", body_style)],
            [Paragraph("Human Approval Status", label_style), Paragraph("APPROVED AND CONFIRMED BY REVIEWER" if human_approved else "PENDING HUMAN REVIEW", ParagraphStyle('AppStatus', parent=body_style, textColor=colors.HexColor("#2B7A78") if human_approved else colors.HexColor("#E05A47"), fontName='Helvetica-Bold'))]
        ]
        ai_table = Table(ai_data, colWidths=[150, 382])
        ai_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#DDDDDD")),
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#F4F6F9")),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(ai_table)
    else:
        elements.append(Paragraph("AI classifier details are not available for this case.", body_style))
    elements.append(Spacer(1, 10))
    
    # Section 4: Evidence Inventory & Integrity
    elements.append(Paragraph("4. Chain of Custody & Evidence Vault", h1_style))
    if evidence_list:
        ev_header = [Paragraph("<b>Filename</b>", label_style), Paragraph("<b>Type</b>", label_style), Paragraph("<b>Size (KB)</b>", label_style), Paragraph("<b>SHA-256 Hash</b>", label_style)]
        ev_table_data = [ev_header]
        for name, f_type, size, f_hash, uld_at in evidence_list:
            ev_table_data.append([
                Paragraph(name, body_style),
                Paragraph(f_type, body_style),
                Paragraph(f"{size/1024:.1f}", body_style),
                Paragraph(f_hash[:32] + "...", ParagraphStyle('Hash', parent=code_style, fontSize=7.5))
            ])
        ev_table = Table(ev_table_data, colWidths=[120, 70, 62, 280])
        ev_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#DDDDDD")),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F4F6F9")),
            ('PADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(ev_table)
    else:
        elements.append(Paragraph("No evidence files registered to this incident.", body_style))
    elements.append(Spacer(1, 10))
    
    # Section 5: OCR Extractions
    elements.append(Paragraph("5. Extracted Evidence Text (OCR Extractions)", h1_style))
    if ocr_list:
        for idx, (txt, score, threats) in enumerate(ocr_list):
            elements.append(Paragraph(f"<b>Extraction {idx+1} (OCR Confidence: {score:.2f})</b>", label_style))
            clean_txt = txt.replace('\n', '<br/>') if txt else "No text extracted."
            snippet_style = ParagraphStyle('Snippet', parent=code_style, backColor=colors.HexColor("#F9F9F9"), borderPadding=6, borderWidth=0.5, borderColor=colors.HexColor("#EAEAEA"))
            elements.append(Paragraph(clean_txt, snippet_style))
            if threats and threats != '[]':
                elements.append(Paragraph(f"<b>Flagged OCR Threats:</b> <font color='#E05A47'>{threats}</font>", body_style))
            elements.append(Spacer(1, 8))
    else:
        elements.append(Paragraph("No textual extractions recorded.", body_style))
    elements.append(Spacer(1, 10))
    
    # Section 6: Security Audit Log
    elements.append(Paragraph("6. Incident Activity Audit Log", h1_style))
    if audit_list:
        aud_header = [Paragraph("<b>User</b>", label_style), Paragraph("<b>Action Performed</b>", label_style), Paragraph("<b>UTC Timestamp</b>", label_style)]
        aud_table_data = [aud_header]
        for user, act, ts in audit_list:
            aud_table_data.append([
                Paragraph(user, body_style),
                Paragraph(act, body_style),
                Paragraph(ts, body_style)
            ])
        aud_table = Table(aud_table_data, colWidths=[120, 232, 180])
        aud_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#DDDDDD")),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F4F6F9")),
            ('PADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(aud_table)
    else:
        elements.append(Paragraph("No logged activities registered for this case.", body_style))
        
    doc.build(elements)
    return pdf_path

def generate_zip_packet(incident_id: str, user_id: int = 0, username: str = "system") -> Path:
    """Generate a legal-review-ready ZIP packet of all evidence, metadata, and PDF summary."""
    incident_dir = EVIDENCE_REPO_PATH / incident_id
    if not incident_dir.exists():
        raise FileNotFoundError("Incident repository not found.")
        
    # Pre-generate the case summary PDF report
    pdf_report_path = generate_pdf_report(incident_id)
    with open(pdf_report_path, "rb") as f:
        pdf_hash = hashlib.sha256(f.read()).hexdigest()
    
    export_filename = f"{incident_id}_export_{generate_uuid().split('-')[0]}.zip"
    export_path = EXPORTS_DIR / export_filename
    
    with zipfile.ZipFile(export_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add all files recursively from the incident directory
        for root, _, files in os.walk(incident_dir):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(incident_dir)
                zipf.write(file_path, arcname)
                
        # Package the generated PDF report at the root of the ZIP
        zipf.write(pdf_report_path, arcname="case_summary_report.pdf")
                
        # Generate and add a chain_of_custody.json manifest for the export event
        coc = {
            "incident_id": incident_id,
            "export_timestamp": get_utc_now(),
            "certification": "Generated securely by FAFO System.",
            "pdf_report_integrity_hash": pdf_hash
        }
        zipf.writestr("chain_of_custody.json", json.dumps(coc, indent=4))

    try:
        log_action(user_id, username, "EXPORT_GENERATED", "incident", incident_id)
    except Exception:
        pass

    return export_path


# ── Phase 6 export/reporting helpers ───────────────────────────────────────


def generate_case_pdf(incident_id: str) -> Optional[bytes]:
    """Return a PDF report as bytes for download and export workflows."""
    try:
        pdf_path = generate_pdf_report(incident_id)
        if not pdf_path.exists():
            return None
        return pdf_path.read_bytes()
    except Exception as exc:
        print(f"[export_manager] PDF generation failed: {exc}")
        return None


def generate_evidence_zip(incident_id: str) -> Optional[bytes]:
    """Return a ZIP evidence packet as bytes for download and export workflows."""
    try:
        zip_path = generate_zip_packet(incident_id)
        if not zip_path.exists():
            return None
        return zip_path.read_bytes()
    except Exception as exc:
        print(f"[export_manager] ZIP generation failed: {exc}")
        return None


def export_cases_csv(incident_ids: List[str]) -> bytes:
    """Export multiple cases as CSV."""
    conn = get_db_connection(str(DATABASE_PATH))
    cursor = conn.cursor()

    placeholders = ','.join('?' * len(incident_ids))
    cursor.execute(f"""
        SELECT i.incident_id, i.category, i.severity, i.status, i.priority,
               i.target, i.created_at, i.created_by,
               COUNT(e.evidence_id) as evidence_count
        FROM incidents i
        LEFT JOIN evidence e ON i.incident_id = e.incident_id
        WHERE i.incident_id IN ({placeholders})
        GROUP BY i.incident_id
    """, incident_ids)

    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'incident_id', 'category', 'severity', 'status', 'priority',
        'target', 'created_at', 'created_by', 'evidence_count'
    ])
    writer.writerows(rows)
    return output.getvalue().encode('utf-8')


def export_cases_json(incident_ids: List[str]) -> bytes:
    """Export multiple cases as JSON."""
    conn = get_db_connection(str(DATABASE_PATH))
    cursor = conn.cursor()
    result = []

    for incident_id in incident_ids:
        cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
        row = cursor.fetchone()
        if not row:
            continue

        cursor.execute("PRAGMA table_info(incidents)")
        cols = [c[1] for c in cursor.fetchall()]
        case = dict(zip(cols, row))

        cursor.execute("""
            SELECT evidence_id, original_name, file_type, file_size,
                   file_hash, uploaded_at, status
            FROM evidence WHERE incident_id = ?
        """, (incident_id,))
        case['evidence'] = [dict(zip([
            'evidence_id', 'original_name', 'file_type', 'file_size',
            'file_hash', 'uploaded_at', 'status'
        ], item)) for item in cursor.fetchall()]

        cursor.execute("""
            SELECT suggested_category, suggested_severity, threat_score,
                   ai_confidence, reviewed_by_human, created_at
            FROM ai_analysis WHERE incident_id = ?
            ORDER BY created_at DESC LIMIT 1
        """, (incident_id,))
        ai = cursor.fetchone()
        if ai:
            case['ai_analysis'] = dict(zip([
                'suggested_category', 'suggested_severity', 'threat_score',
                'ai_confidence', 'reviewed_by_human', 'analyzed_at'
            ], ai))

        result.append(case)

    conn.close()
    return json.dumps(result, indent=2, default=str).encode('utf-8')


def render_export_panel(incident_id: str):
    """Render export controls for the incident detail view."""
    import streamlit as st

    st.subheader("📦 Export & Reports")
    st.write("Generate printable PDF summaries, forensic ZIP packets, and structured CSV/JSON exports for this case.")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("📄 Generate PDF Report", key=f"phase6_pdf_{incident_id}"):
            with st.spinner("Generating PDF report..."):
                pdf_bytes = generate_case_pdf(incident_id)
                if pdf_bytes:
                    st.download_button(
                        "Download PDF report",
                        data=pdf_bytes,
                        file_name=f"FAFO_{incident_id}_report.pdf",
                        mime="application/pdf",
                        key=f"download_pdf_{incident_id}",
                    )
                    log_action(1, "system", "EXPORT_PDF_GENERATED", "incident", incident_id)
                else:
                    st.error("PDF generation failed for this incident.")

        if st.button("🗜 Generate ZIP Packet", key=f"phase6_zip_{incident_id}"):
            with st.spinner("Packaging evidence..."):
                zip_bytes = generate_evidence_zip(incident_id)
                if zip_bytes:
                    st.download_button(
                        "Download ZIP packet",
                        data=zip_bytes,
                        file_name=f"FAFO_{incident_id}_evidence.zip",
                        mime="application/zip",
                        key=f"download_zip_{incident_id}",
                    )
                    log_action(1, "system", "EXPORT_ZIP_GENERATED", "incident", incident_id)
                else:
                    st.error("ZIP export generation failed for this incident.")

    with col2:
        export_format = st.selectbox("Export format", ["CSV", "JSON"], key=f"phase6_format_{incident_id}")
        if st.button("Export This Case", key=f"phase6_bulk_{incident_id}"):
            data = export_cases_csv([incident_id]) if export_format == "CSV" else export_cases_json([incident_id])
            mime = "text/csv" if export_format == "CSV" else "application/json"
            ext = "csv" if export_format == "CSV" else "json"
            st.download_button(
                f"Download {export_format}",
                data=data,
                file_name=f"FAFO_{incident_id}.{ext}",
                mime=mime,
                key=f"download_bulk_{incident_id}",
            )
