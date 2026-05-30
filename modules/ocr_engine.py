import os
import re
from pathlib import Path
import json

import numpy as np

from modules.ffmpeg_processor import extract_frames_for_ocr


def get_cv2():
    try:
        import cv2
        return cv2
    except Exception:
        return None


def get_pdf2image():
    try:
        from pdf2image import convert_from_path
        return convert_from_path
    except Exception:
        return None

VIDEO_EXTENSIONS = {'.mp4', '.mov', '.avi', '.mkv', '.webm'}
OCR_LANGUAGES = [lang.strip() for lang in os.getenv('OCR_LANGUAGES', 'en').split(',') if lang.strip()]
OCR_READER = None


def get_ocr_reader():
    global OCR_READER
    if OCR_READER is not None:
        return OCR_READER

    try:
        import easyocr
        OCR_READER = easyocr.Reader(OCR_LANGUAGES or ['en'], gpu=False)
    except Exception:
        OCR_READER = None
    return OCR_READER


def normalize_text(text: str) -> str:
    return ' '.join(re.sub(r'[^A-Za-z0-9 ]+', ' ', (text or '').strip().lower()).split())


def preprocess_image(image_path: Path) -> np.ndarray | None:
    if not image_path.exists():
        return None

    cv2 = get_cv2()
    if cv2 is None:
        return None

    image = cv2.imread(str(image_path))
    if image is None:
        return None

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)
    denoised = cv2.fastNlMeansDenoising(enhanced, h=10, templateWindowSize=7, searchWindowSize=21)
    blurred = cv2.GaussianBlur(denoised, (3, 3), 0)
    _, thresh = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
    return thresh


def extract_text_from_image(image_path: Path) -> dict:
    """Preprocess the image and extract text using easyocr as the preferred backend."""
    if not image_path.exists():
        return {"error": "Image not found"}

    try:
        processed = preprocess_image(image_path)
        if processed is None:
            return {"error": "Unable to load or preprocess image. Ensure OpenCV is installed."}

        reader = get_ocr_reader()
        text = ""
        confidences = []

        if reader is not None:
            raw = reader.readtext(processed, detail=1, paragraph=True)
            lines = [item[1] for item in raw if item and len(item) >= 2]
            text = "\n".join(lines).strip()
            confidences = [float(item[2]) for item in raw if item and len(item) >= 3 and isinstance(item[2], (int, float))]
        else:
            try:
                import pytesseract
                custom_config = r'--oem 3 --psm 6'
                data = pytesseract.image_to_data(processed, config=custom_config, output_type=pytesseract.Output.DICT)
                text = pytesseract.image_to_string(processed, config=custom_config)
                confidences = [int(c) for c in data['conf'] if c != '-1']
            except Exception:
                return {"error": "No OCR engine available. Install easyocr or pytesseract."}

        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        return {
            "text": text,
            "confidence": avg_confidence,
            "entities": extract_entities(text)
        }
    except Exception as e:
        return {"error": str(e)}


def extract_entities(text: str) -> dict:
    """Extract URLs, handles, and flagged keywords."""
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    handles = re.findall(r'@[a-zA-Z0-9_]+', text)
    
    # Basic threat keyword list for MVP
    threat_keywords = ["kill", "die", "dox", "address", "hurt", "shoot", "bomb"]
    threats_found = [word for word in threat_keywords if word.lower() in text.lower()]
    
    return {
        "urls": urls,
        "usernames": handles,
        "threats": threats_found
    }

def process_evidence_ocr(file_path: str, evidence_id: str, incident_id: str) -> dict:
    """Run OCR for images and PDFs as part of the evidence pipeline."""
    path = Path(file_path)
    if path.suffix.lower() == '.pdf':
        temp_dir = Path('temp_processing') / incident_id
        temp_dir.mkdir(parents=True, exist_ok=True)
        pages = process_pdf(path, temp_dir)
        text_parts = []
        confidence_scores = []
        urls = []
        usernames = []
        threats = []
        for page in pages:
            if 'error' in page:
                continue
            page_text = page.get('text', '')
            if page_text:
                text_parts.append(page_text)
            confidence_scores.append(page.get('confidence', 0))
            entities = page.get('entities', {})
            urls.extend(entities.get('urls', []))
            usernames.extend(entities.get('usernames', []))
            threats.extend(entities.get('threats', []))
        return {
            'text': '\n\n'.join(text_parts),
            'confidence': sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0,
            'urls': urls,
            'usernames': usernames,
            'threats': list(set(threats)),
            'evidence_id': evidence_id,
            'incident_id': incident_id,
        }

    if path.suffix.lower() in VIDEO_EXTENSIONS:
        temp_dir = Path('temp_processing') / incident_id
        temp_dir.mkdir(parents=True, exist_ok=True)

        frames = extract_frames_for_ocr(path, temp_dir, fps=1)
        if not frames:
            return {
                'text': '',
                'confidence': 0,
                'urls': [],
                'usernames': [],
                'threats': [],
                'evidence_id': evidence_id,
                'incident_id': incident_id,
            }

        text_parts = []
        confidence_scores = []
        urls = []
        usernames = []
        threats = []
        seen_frames = set()
        previous_frame_text = None

        for idx, frame_path in enumerate(frames, start=1):
            frame_result = extract_text_from_image(frame_path)
            if 'error' in frame_result:
                continue

            frame_text = frame_result.get('text', '').strip()
            normalized = normalize_text(frame_text)
            if not normalized:
                try:
                    frame_path.unlink()
                except Exception:
                    pass
                continue

            if normalized == previous_frame_text or normalized in seen_frames:
                try:
                    frame_path.unlink()
                except Exception:
                    pass
                continue

            seen_frames.add(normalized)
            previous_frame_text = normalized
            text_parts.append(f"Frame {idx}: {frame_text}")
            confidence_scores.append(frame_result.get('confidence', 0))
            entities = frame_result.get('entities', {})
            urls.extend(entities.get('urls', []))
            usernames.extend(entities.get('usernames', []))
            threats.extend(entities.get('threats', []))

            try:
                frame_path.unlink()
            except Exception:
                pass

        return {
            'text': '\n\n'.join(text_parts),
            'confidence': sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0,
            'urls': urls,
            'usernames': usernames,
            'threats': list(set(threats)),
            'evidence_id': evidence_id,
            'incident_id': incident_id,
        }

    result = extract_text_from_image(path)
    return {
        'text': result.get('text', ''),
        'confidence': result.get('confidence', 0),
        'urls': result.get('entities', {}).get('urls', []),
        'usernames': result.get('entities', {}).get('usernames', []),
        'threats': result.get('entities', {}).get('threats', []),
        'evidence_id': evidence_id,
        'incident_id': incident_id,
    }


def process_pdf(pdf_path: Path, temp_dir: Path) -> list:
    """Convert PDF to images and OCR each page."""
    results = []
    convert = get_pdf2image()
    if convert is None:
        return [{"error": "pdf2image is not installed. Cannot process PDF evidence."}]

    try:
        images = convert(str(pdf_path), dpi=300)
        for i, image in enumerate(images):
            # Save temporarily
            temp_img = temp_dir / f"page_{i}.png"
            image.save(temp_img, "PNG")

            # OCR
            res = extract_text_from_image(temp_img)
            res['page'] = i + 1
            results.append(res)

            # Cleanup
            temp_img.unlink()
    except Exception as e:
        results.append({"error": str(e)})
    return results
