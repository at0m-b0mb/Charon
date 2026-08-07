"""Icons drawn at runtime with QPainter.

No image files, no icon font, no emoji.  Emoji in Qt labels render differently
(or not at all) depending on the platform's font fallback, and shipping PNGs
means shipping a second set of assets for high-DPI screens.  Painting a handful
of simple shapes into a device-pixel-ratio-aware pixmap sidesteps both problems
and keeps every glyph tintable to the current palette.
"""

from __future__ import annotations

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

_CACHE: dict[tuple[str, str, int], QIcon] = {}
_ARROW_CACHE: dict[str, str] = {}


def chevron_path(color: str) -> str:
    """Write a small downward chevron PNG and return its path for use in QSS.

    Qt stylesheets cannot draw a shape — ``image:`` needs a real file, and the
    CSS-triangle border trick that works in a browser renders as a rectangle
    here.  A combo box with no arrow is indistinguishable from a text field, so
    the glyph is generated once per colour into a temp file and referenced by
    path.
    """
    if color not in _ARROW_CACHE:
        import tempfile

        size = 9
        pm = QPixmap(size * 2, size * 2)
        pm.setDevicePixelRatio(2)
        pm.fill(QColor(0, 0, 0, 0))
        painter = QPainter(pm)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        pen = QPen(QColor(color), 1.5)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.drawLine(QPointF(1.5, 3.0), QPointF(size / 2, size - 3.0))
        painter.drawLine(QPointF(size / 2, size - 3.0), QPointF(size - 1.5, 3.0))
        painter.end()

        handle = tempfile.NamedTemporaryFile(
            prefix=f"charon-chevron-{color.lstrip('#')}-", suffix=".png", delete=False)
        handle.close()
        pm.save(handle.name, "PNG")
        _ARROW_CACHE[color] = handle.name.replace("\\", "/")
    return _ARROW_CACHE[color]


def icon(name: str, color: str, size: int = 18) -> QIcon:
    key = (name, color, size)
    if key not in _CACHE:
        _CACHE[key] = QIcon(_pixmap(name, color, size))
    return _CACHE[key]


def clear_cache() -> None:
    """Drop cached glyphs so a palette change repaints them.

    The cache is keyed by colour, so stale entries are never *wrong* — but a
    theme switch would otherwise leave every already-built QIcon holding the
    old tint, because the widgets keep their own references.
    """
    _CACHE.clear()
    _ARROW_CACHE.clear()


def _pixmap(name: str, color: str, size: int) -> QPixmap:
    # Back the icon with twice as many real pixels so it stays crisp on Retina.
    # Setting the device-pixel-ratio is the *whole* adjustment: QPainter's
    # coordinate system on such a pixmap is already logical, so scaling the
    # painter as well would push three-quarters of every glyph off the canvas.
    scale = 2
    pm = QPixmap(size * scale, size * scale)
    pm.setDevicePixelRatio(scale)
    pm.fill(QColor(0, 0, 0, 0))

    painter = QPainter(pm)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    c = QColor(color)
    pen = QPen(c, 1.6)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)

    drawer = _DRAWERS.get(name, _draw_file)
    drawer(painter, size, c)
    painter.end()
    return pm


# --------------------------------------------------------------------- glyphs

def _draw_folder(p: QPainter, s: int, c: QColor) -> None:
    path = QPainterPath()
    path.moveTo(s * 0.12, s * 0.76)
    path.lineTo(s * 0.12, s * 0.26)
    path.lineTo(s * 0.42, s * 0.26)
    path.lineTo(s * 0.50, s * 0.36)
    path.lineTo(s * 0.88, s * 0.36)
    path.lineTo(s * 0.88, s * 0.76)
    path.closeSubpath()
    p.setBrush(QColor(c.red(), c.green(), c.blue(), 45))
    p.drawPath(path)


def _draw_file(p: QPainter, s: int, c: QColor) -> None:
    path = QPainterPath()
    path.moveTo(s * 0.24, s * 0.14)
    path.lineTo(s * 0.60, s * 0.14)
    path.lineTo(s * 0.78, s * 0.34)
    path.lineTo(s * 0.78, s * 0.86)
    path.lineTo(s * 0.24, s * 0.86)
    path.closeSubpath()
    p.setBrush(QColor(c.red(), c.green(), c.blue(), 35))
    p.drawPath(path)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawLine(QPointF(s * 0.60, s * 0.14), QPointF(s * 0.60, s * 0.34))
    p.drawLine(QPointF(s * 0.60, s * 0.34), QPointF(s * 0.78, s * 0.34))


def _draw_link(p: QPainter, s: int, c: QColor) -> None:
    p.drawArc(QRectF(s * 0.10, s * 0.42, s * 0.44, s * 0.40), 45 * 16, 220 * 16)
    p.drawArc(QRectF(s * 0.46, s * 0.18, s * 0.44, s * 0.40), 225 * 16, 220 * 16)
    p.drawLine(QPointF(s * 0.38, s * 0.60), QPointF(s * 0.62, s * 0.40))


def _draw_up(p: QPainter, s: int, c: QColor) -> None:
    p.drawLine(QPointF(s * 0.5, s * 0.80), QPointF(s * 0.5, s * 0.22))
    p.drawLine(QPointF(s * 0.5, s * 0.22), QPointF(s * 0.26, s * 0.46))
    p.drawLine(QPointF(s * 0.5, s * 0.22), QPointF(s * 0.74, s * 0.46))


def _draw_down(p: QPainter, s: int, c: QColor) -> None:
    p.drawLine(QPointF(s * 0.5, s * 0.20), QPointF(s * 0.5, s * 0.78))
    p.drawLine(QPointF(s * 0.5, s * 0.78), QPointF(s * 0.26, s * 0.54))
    p.drawLine(QPointF(s * 0.5, s * 0.78), QPointF(s * 0.74, s * 0.54))


def _draw_refresh(p: QPainter, s: int, c: QColor) -> None:
    p.drawArc(QRectF(s * 0.18, s * 0.18, s * 0.64, s * 0.64), 40 * 16, 280 * 16)
    p.drawLine(QPointF(s * 0.78, s * 0.30), QPointF(s * 0.80, s * 0.12))
    p.drawLine(QPointF(s * 0.78, s * 0.30), QPointF(s * 0.60, s * 0.26))


def _draw_lock(p: QPainter, s: int, c: QColor) -> None:
    p.setBrush(QColor(c.red(), c.green(), c.blue(), 50))
    p.drawRoundedRect(QRectF(s * 0.22, s * 0.44, s * 0.56, s * 0.40), 4, 4)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawArc(QRectF(s * 0.32, s * 0.16, s * 0.36, s * 0.42), 0, 180 * 16)


def _draw_unlock(p: QPainter, s: int, c: QColor) -> None:
    p.setBrush(QColor(c.red(), c.green(), c.blue(), 50))
    p.drawRoundedRect(QRectF(s * 0.22, s * 0.44, s * 0.56, s * 0.40), 4, 4)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawArc(QRectF(s * 0.44, s * 0.14, s * 0.36, s * 0.42), 10 * 16, 170 * 16)


def _draw_shield(p: QPainter, s: int, c: QColor) -> None:
    path = QPainterPath()
    path.moveTo(s * 0.50, s * 0.12)
    path.lineTo(s * 0.84, s * 0.26)
    path.lineTo(s * 0.84, s * 0.52)
    path.quadTo(s * 0.84, s * 0.78, s * 0.50, s * 0.90)
    path.quadTo(s * 0.16, s * 0.78, s * 0.16, s * 0.52)
    path.lineTo(s * 0.16, s * 0.26)
    path.closeSubpath()
    p.setBrush(QColor(c.red(), c.green(), c.blue(), 45))
    p.drawPath(path)


def _draw_warning(p: QPainter, s: int, c: QColor) -> None:
    path = QPainterPath()
    path.moveTo(s * 0.50, s * 0.14)
    path.lineTo(s * 0.90, s * 0.84)
    path.lineTo(s * 0.10, s * 0.84)
    path.closeSubpath()
    p.setBrush(QColor(c.red(), c.green(), c.blue(), 45))
    p.drawPath(path)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawLine(QPointF(s * 0.5, s * 0.40), QPointF(s * 0.5, s * 0.62))
    p.drawPoint(QPointF(s * 0.5, s * 0.73))


def _draw_plug(p: QPainter, s: int, c: QColor) -> None:
    p.drawLine(QPointF(s * 0.16, s * 0.50), QPointF(s * 0.40, s * 0.50))
    p.setBrush(QColor(c.red(), c.green(), c.blue(), 45))
    p.drawRoundedRect(QRectF(s * 0.40, s * 0.30, s * 0.26, s * 0.40), 4, 4)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawLine(QPointF(s * 0.66, s * 0.40), QPointF(s * 0.86, s * 0.40))
    p.drawLine(QPointF(s * 0.66, s * 0.60), QPointF(s * 0.86, s * 0.60))


def _draw_copy(p: QPainter, s: int, c: QColor) -> None:
    p.drawRoundedRect(QRectF(s * 0.14, s * 0.14, s * 0.48, s * 0.56), 3, 3)
    p.setBrush(QColor(c.red(), c.green(), c.blue(), 40))
    p.drawRoundedRect(QRectF(s * 0.36, s * 0.32, s * 0.50, s * 0.56), 3, 3)


def _draw_paste(p: QPainter, s: int, c: QColor) -> None:
    p.setBrush(QColor(c.red(), c.green(), c.blue(), 35))
    p.drawRoundedRect(QRectF(s * 0.20, s * 0.20, s * 0.60, s * 0.68), 4, 4)
    p.setBrush(QColor(c))
    p.drawRoundedRect(QRectF(s * 0.36, s * 0.10, s * 0.28, s * 0.18), 3, 3)


def _draw_trash(p: QPainter, s: int, c: QColor) -> None:
    p.drawLine(QPointF(s * 0.16, s * 0.28), QPointF(s * 0.84, s * 0.28))
    p.drawRoundedRect(QRectF(s * 0.26, s * 0.28, s * 0.48, s * 0.58), 3, 3)
    p.drawLine(QPointF(s * 0.38, s * 0.16), QPointF(s * 0.62, s * 0.16))


def _draw_newfolder(p: QPainter, s: int, c: QColor) -> None:
    _draw_folder(p, s, c)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawLine(QPointF(s * 0.50, s * 0.46), QPointF(s * 0.50, s * 0.66))
    p.drawLine(QPointF(s * 0.40, s * 0.56), QPointF(s * 0.60, s * 0.56))


def _draw_gear(p: QPainter, s: int, c: QColor) -> None:
    p.drawEllipse(QRectF(s * 0.34, s * 0.34, s * 0.32, s * 0.32))
    p.drawEllipse(QRectF(s * 0.16, s * 0.16, s * 0.68, s * 0.68))


def _draw_home(p: QPainter, s: int, c: QColor) -> None:
    p.drawLine(QPointF(s * 0.12, s * 0.50), QPointF(s * 0.50, s * 0.16))
    p.drawLine(QPointF(s * 0.50, s * 0.16), QPointF(s * 0.88, s * 0.50))
    p.setBrush(QColor(c.red(), c.green(), c.blue(), 35))
    p.drawRect(QRectF(s * 0.24, s * 0.50, s * 0.52, s * 0.36))


def _draw_stop(p: QPainter, s: int, c: QColor) -> None:
    p.setBrush(QColor(c.red(), c.green(), c.blue(), 45))
    p.drawRoundedRect(QRectF(s * 0.22, s * 0.22, s * 0.56, s * 0.56), 4, 4)


_DRAWERS = {
    "folder": _draw_folder,
    "file": _draw_file,
    "link": _draw_link,
    "up": _draw_up,
    "download": _draw_down,
    "upload": _draw_up,
    "refresh": _draw_refresh,
    "lock": _draw_lock,
    "unlock": _draw_unlock,
    "shield": _draw_shield,
    "warning": _draw_warning,
    "connect": _draw_plug,
    "copy": _draw_copy,
    "paste": _draw_paste,
    "trash": _draw_trash,
    "newfolder": _draw_newfolder,
    "gear": _draw_gear,
    "home": _draw_home,
    "stop": _draw_stop,
}
