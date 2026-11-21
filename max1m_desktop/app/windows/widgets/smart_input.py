from PySide6.QtWidgets import QTextEdit
from PySide6.QtCore import Qt, Signal, QByteArray, QBuffer, QIODevice
from PySide6.QtGui import QKeyEvent, QImage


class SmartInput(QTextEdit):
    """Умное поле ввода: авто-растягивание, Enter для отправки, Ctrl+V скриншотов/файлов и Drag & Drop."""

    returnPressed = Signal()
    imagePasted = Signal(bytes)
    filesDroppedOrPasted = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("MessageInput")
        self.setAcceptRichText(False)
        self.setAcceptDrops(True)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.document().setDocumentMargin(12)

        self.min_height = 56
        self.max_height = 160

        self.setMinimumHeight(self.min_height)
        self.setMaximumHeight(self.min_height)

        self.textChanged.connect(self._adjust_height)

    def _adjust_height(self):
        doc_height = int(self.document().size().height())
        margins = self.contentsMargins()
        target_height = doc_height + margins.top() + margins.bottom() + 4

        if target_height <= self.min_height:
            self.setMinimumHeight(self.min_height)
            self.setMaximumHeight(self.min_height)
            self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        elif target_height >= self.max_height:
            self.setMinimumHeight(self.max_height)
            self.setMaximumHeight(self.max_height)
            self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        else:
            self.setMinimumHeight(target_height)
            self.setMaximumHeight(target_height)
            self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

    def keyPressEvent(self, event: QKeyEvent):
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            if event.modifiers() & Qt.ShiftModifier:
                super().keyPressEvent(event)
            else:
                self.returnPressed.emit()
                event.accept()
        else:
            super().keyPressEvent(event)

    @staticmethod
    def _extract_local_file_paths(mime_data) -> list[str]:
        if mime_data is None or not mime_data.hasUrls():
            return []
        paths = []
        for url in mime_data.urls():
            if url.isLocalFile():
                p = url.toLocalFile()
                if p:
                    paths.append(p)
        return paths

    def insertFromMimeData(self, source):
        """Перехватываем вставку (Ctrl+V / Контекстное меню): скриншоты и скопированные файлы."""
        local_paths = self._extract_local_file_paths(source)
        if local_paths:
            self.filesDroppedOrPasted.emit(local_paths)
            return

        if source.hasImage():
            image = source.imageData()
            if image and not image.isNull():
                ba = QByteArray()
                buffer = QBuffer(ba)
                buffer.open(QIODevice.WriteOnly)
                image.save(buffer, "PNG")
                image_bytes = ba.data()
                self.imagePasted.emit(image_bytes)
                return

        super().insertFromMimeData(source)

    def dragEnterEvent(self, event):
        if self._extract_local_file_paths(event.mimeData()):
            event.acceptProposedAction()
            return
        super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if self._extract_local_file_paths(event.mimeData()):
            event.acceptProposedAction()
            return
        super().dragMoveEvent(event)

    def dropEvent(self, event):
        local_paths = self._extract_local_file_paths(event.mimeData())
        if local_paths:
            event.acceptProposedAction()
            self.filesDroppedOrPasted.emit(local_paths)
            return
        super().dropEvent(event)
