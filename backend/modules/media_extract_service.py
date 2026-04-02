from __future__ import annotations

from collections import deque
from io import BytesIO
import os
from pathlib import Path
import shutil
from tempfile import NamedTemporaryFile
from statistics import median
from typing import Any, Dict, Optional, cast


def _decode_text_bytes(raw: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            text = raw.decode(encoding)
            if text.strip():
                return text
        except Exception:
            continue
    return raw.decode("latin-1", errors="ignore")


def _is_image(content_type: str, ext: str) -> bool:
    return content_type.startswith("image/") or ext in {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tiff"}


def _is_audio(content_type: str, ext: str) -> bool:
    return content_type.startswith("audio/") or ext in {".wav", ".mp3", ".m4a", ".ogg", ".flac", ".aac"}


def _is_punch_card(content_type: str, ext: str) -> bool:
    return _is_image(content_type, ext)


def _decode_hollerith_punches(punches: list[int]) -> str:
    unique = sorted(set(punches))
    if not unique:
        return " "

    if unique == [12]:
        return "&"
    if unique == [11]:
        return "-"
    if unique == [0]:
        return "0"

    if len(unique) == 1:
        value = unique[0]
        if 1 <= value <= 9:
            return str(value)

    zones = [value for value in unique if value in {12, 11, 0}]
    digits = [value for value in unique if value not in {12, 11, 0}]
    if len(zones) == 1 and len(digits) == 1:
        zone = zones[0]
        digit = digits[0]
        if zone == 12 and 1 <= digit <= 9:
            return chr(ord("A") + digit - 1)
        if zone == 11 and 1 <= digit <= 9:
            return chr(ord("J") + digit - 1)
        if zone == 0:
            if digit == 1:
                return "/"
            if 2 <= digit <= 9:
                return chr(ord("S") + digit - 2)

    if unique == [12, 11, 8]:
        return "?"
    if unique == [12, 8, 2]:
        return "["
    if unique == [11, 8, 2]:
        return "]"
    if unique == [11, 8, 7]:
        return "^"
    if unique == [0, 8, 2]:
        return "±"
    if unique == [0, 8, 5]:
        return "v"
    if unique == [0, 8, 7]:
        return "¶"

    return "?"


def _decode_punch_card_image(raw: bytes) -> str:
    try:
        from PIL import Image  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "Punch-card decoding requires Pillow to be installed."
        ) from exc

    try:
        with Image.open(BytesIO(raw)) as img:
            rgb = img.convert("RGB")
            width, height = rgb.size
            components: list[dict[str, float]] = []
            visited = [[False] * width for _ in range(height)]

            for y in range(height):
                for x in range(width):
                    if visited[y][x]:
                        continue
                    red, green, blue = cast(tuple[int, int, int], rgb.getpixel((x, y)))
                    if red <= 245 or green <= 240 or blue <= 220:
                        continue

                    queue = deque([(x, y)])
                    visited[y][x] = True
                    area = 0
                    sum_x = 0.0
                    sum_y = 0.0
                    min_x = x
                    max_x = x
                    min_y = y
                    max_y = y

                    while queue:
                        current_x, current_y = queue.popleft()
                        area += 1
                        sum_x += current_x
                        sum_y += current_y
                        if current_x < min_x:
                            min_x = current_x
                        if current_x > max_x:
                            max_x = current_x
                        if current_y < min_y:
                            min_y = current_y
                        if current_y > max_y:
                            max_y = current_y

                        for next_x, next_y in (
                            (current_x - 1, current_y),
                            (current_x + 1, current_y),
                            (current_x, current_y - 1),
                            (current_x, current_y + 1),
                        ):
                            if not (0 <= next_x < width and 0 <= next_y < height):
                                continue
                            if visited[next_y][next_x]:
                                continue
                            next_red, next_green, next_blue = cast(
                                tuple[int, int, int],
                                rgb.getpixel((next_x, next_y)),
                            )
                            if next_red <= 245 or next_green <= 240 or next_blue <= 220:
                                continue
                            visited[next_y][next_x] = True
                            queue.append((next_x, next_y))

                    if 10 <= area <= 100 and max_x < width - 10:
                        components.append(
                            {
                                "cx": sum_x / area,
                                "cy": sum_y / area,
                                "area": area,
                                "min_x": min_x,
                                "max_x": max_x,
                                "min_y": min_y,
                                "max_y": max_y,
                            }
                        )
    except Exception as exc:
        raise ValueError(f"failed to parse image: {exc}") from exc

    if len(components) < 10:
        raise ValueError("image does not resemble a punch card")

    x_positions = sorted(round(component["cx"]) for component in components)
    y_positions = sorted(round(component["cy"]) for component in components)

    x_gaps = [b - a for a, b in zip(x_positions, x_positions[1:]) if 2 <= (b - a) <= 20]
    y_gaps = [b - a for a, b in zip(y_positions, y_positions[1:]) if 10 <= (b - a) <= 40]
    if not x_gaps or not y_gaps:
        raise ValueError("image does not resemble a punch card")

    x_step = median(x_gaps)
    y_step = median(y_gaps)
    x_origin = min(component["cx"] for component in components)
    y_origin = min(component["cy"] for component in components)

    row_labels = [12, 11, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    columns: Dict[int, list[int]] = {}
    for component in components:
        row_index = int(round((component["cy"] - y_origin) / y_step))
        column_index = int(round((component["cx"] - x_origin) / x_step))
        if 0 <= row_index < len(row_labels):
            columns.setdefault(column_index, []).append(row_labels[row_index])

    if not columns:
        raise ValueError("image does not resemble a punch card")

    min_column = min(columns)
    max_column = max(columns)
    decoded = "".join(_decode_hollerith_punches(columns.get(column, [])) for column in range(min_column, max_column + 1))
    decoded = " ".join(decoded.split())
    if not decoded.strip():
        raise ValueError("no punch-card text could be decoded")

    return decoded


def _resolve_tesseract_cmd() -> Optional[str]:
    env_cmd = os.getenv("TESSERACT_CMD")
    if env_cmd and Path(env_cmd).exists():
        return env_cmd

    found = shutil.which("tesseract")
    if found:
        return found

    common_paths = [
        Path("C:/Program Files/Tesseract-OCR/tesseract.exe"),
        Path("C:/Program Files (x86)/Tesseract-OCR/tesseract.exe"),
    ]
    for candidate in common_paths:
        if candidate.exists():
            return str(candidate)
    return None


def extract_text_from_media(
    raw: bytes,
    filename: str,
    content_type: str,
    mode: str = "auto",
) -> Dict[str, Any]:
    if not raw:
        raise ValueError("uploaded file is empty")

    ext = Path(filename or "upload.bin").suffix.lower()
    selected_mode = mode.lower().strip() if mode else "auto"
    if selected_mode not in {"auto", "text", "image", "audio", "punch_card"}:
        raise ValueError("mode must be one of: auto, text, image, audio, punch_card")

    if selected_mode == "auto":
        if _is_punch_card(content_type, ext):
            try:
                text = _decode_punch_card_image(raw)
            except Exception:
                selected_mode = "image"
            else:
                return {
                    "mode": "punch_card",
                    "engine": "hollerith_card_decoder",
                    "extracted_text": text,
                    "content_type": content_type,
                    "filename": filename,
                }
        if _is_image(content_type, ext):
            selected_mode = "image"
        elif _is_audio(content_type, ext):
            selected_mode = "audio"
        else:
            selected_mode = "text"

    if selected_mode == "text":
        text = _decode_text_bytes(raw)
        return {
            "mode": "text",
            "engine": "bytes_decode",
            "extracted_text": text,
            "content_type": content_type,
            "filename": filename,
        }

    if selected_mode == "image":
        try:
            from PIL import Image  # type: ignore
            import pytesseract  # type: ignore
        except Exception as exc:
            raise RuntimeError(
                "Image OCR dependencies unavailable. Install Pillow and pytesseract, and ensure Tesseract OCR is installed on system PATH."
            ) from exc

        tesseract_cmd = _resolve_tesseract_cmd()
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd

        try:
            with Image.open(BytesIO(raw)) as img:
                text = pytesseract.image_to_string(img)
        except pytesseract.TesseractNotFoundError as exc:
            raise RuntimeError(
                "Tesseract is installed but not visible to the running backend process. "
                "Restart backend or set TESSERACT_CMD to the full path, e.g. C:/Program Files/Tesseract-OCR/tesseract.exe"
            ) from exc
        except Exception as exc:
            raise ValueError(f"failed to parse image: {exc}") from exc

        if not text.strip():
            raise ValueError("no text extracted from image")

        return {
            "mode": "image",
            "engine": "pytesseract",
            "extracted_text": text,
            "content_type": content_type,
            "filename": filename,
        }

    if selected_mode == "punch_card":
        text = _decode_punch_card_image(raw)
        return {
            "mode": "punch_card",
            "engine": "hollerith_card_decoder",
            "extracted_text": text,
            "content_type": content_type,
            "filename": filename,
        }

    # audio mode
    if shutil.which("ffmpeg") is None:
        raise RuntimeError(
            "Audio transcription dependencies unavailable. Install ffmpeg and ensure it is on PATH."
        )

    try:
        import whisper  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "Audio transcription dependencies unavailable. Install openai-whisper (and ffmpeg) to enable audio mode."
        ) from exc

    temp_path: Optional[str] = None
    try:
        with NamedTemporaryFile(delete=False, suffix=ext or ".wav") as temp:
            temp.write(raw)
            temp_path = temp.name

        model = whisper.load_model("base")
        result = model.transcribe(temp_path, fp16=False)
        text = str(result.get("text", ""))
    except Exception as exc:
        raise ValueError(f"failed to transcribe audio: {exc}") from exc
    finally:
        if temp_path:
            try:
                Path(temp_path).unlink(missing_ok=True)
            except Exception:
                pass

    if not text.strip():
        raise ValueError("no text extracted from audio")

    return {
        "mode": "audio",
        "engine": "openai-whisper-base",
        "extracted_text": text,
        "content_type": content_type,
        "filename": filename,
    }
