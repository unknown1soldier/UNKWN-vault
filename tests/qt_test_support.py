"""Small Qt lifecycle helpers shared by real-widget tests."""
from PyQt5.QtCore import QCoreApplication, QEvent


def flush_deferred_deletes() -> None:
    if QCoreApplication.instance() is not None:
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
