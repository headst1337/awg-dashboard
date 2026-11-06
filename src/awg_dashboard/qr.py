from __future__ import annotations

from io import BytesIO

import segno
from segno import DataOverflowError

from .errors import ValidationError


def generate_awg_qr_svg(config_text: str) -> str:
    if not config_text:
        raise ValidationError("cannot generate a QR code for an empty config")
    try:
        qr_code = segno.make(config_text, error="L", mode="byte", micro=False)
    except DataOverflowError as error:
        raise ValidationError(
            "AWG config is too large for a single QR code"
        ) from error
    output = BytesIO()
    qr_code.save(output, kind="svg", scale=5, border=4)
    return output.getvalue().decode("utf-8")
