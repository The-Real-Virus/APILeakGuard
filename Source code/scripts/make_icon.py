"""Rasterize the product icon at Windows shell resolutions."""
from pathlib import Path

from PIL import Image
from PySide6.QtCore import Qt
from PySide6.QtGui import QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

root = Path(__file__).resolve().parents[1]
asset = root / "assets" / "apileakguard.svg"
renderer = QSvgRenderer(str(asset))
raster = QImage(256, 256, QImage.Format.Format_RGBA8888)
raster.fill(Qt.GlobalColor.transparent)
painter = QPainter(raster)
painter.setRenderHint(QPainter.RenderHint.Antialiasing)
renderer.render(painter)
painter.end()
image = Image.frombytes("RGBA", (256, 256), bytes(raster.constBits()))
image.save(asset.with_suffix(".ico"), sizes=[(s, s) for s in (16, 20, 24, 32, 40, 48, 64, 128, 256)])
