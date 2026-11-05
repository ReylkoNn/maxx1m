from PySide6.QtWidgets import QTextEdit
from PySide6.QtCore import Qt, Signal, QByteArray, QBuffer, QIODevice
from PySide6.QtGui import QKeyEvent, QImage


class SmartInput(QTextEdit):
    """Умное поле ввода (Premium UX): авто-растягивание, Enter для отправки, вставка картинок из буфера."""

    returnPressed = Signal()
    imagePasted = Signal(bytes)  # 🔥 НОВЫЙ СИГНАЛ ДЛЯ КАРТИНОК ИЗ БУФЕРА

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("MessageInput")
        self.setAcceptRichText(False)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        # Отодвигаем внутренний документ от краев для центрирования
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

    # 🔥 МАГИЯ БУФЕРА ОБМЕНА
    def insertFromMimeData(self, source):
        """Перехватываем вставку (Ctrl+V / Контекстное меню)"""
        if source.hasImage():
            # Если в буфере картинка — достаем её
            image = source.imageData()
            if image and not image.isNull():
                # Конвертируем QImage в сырые байты формата PNG
                ba = QByteArray()
                buffer = QBuffer(ba)
                buffer.open(QIODevice.WriteOnly)
                image.save(buffer, "PNG")
                image_bytes = ba.data()

                # Сигнализируем главному окну, что прилетела картинка!
                self.imagePasted.emit(image_bytes)
                return  # Останавливаем стандартную вставку (чтобы не рисовался мусор в тексте)

        # Если это обычный текст — пусть вставляется как обычно
        super().insertFromMimeData(source)