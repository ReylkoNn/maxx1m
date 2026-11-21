import threading
import time
import pytest
from PySide6.QtCore import QCoreApplication, QEventLoop, QTimer
from app.history_paging import HistoryCancelled, legacy_history_view, check_cancel
from app.history_activation import file_hash
from app.history_store import EncryptedHistory
from app.workers import HistoryPageWorker


def test_row_scan_can_cancel_without_mutation(tmp_path, monkeypatch):
    store = EncryptedHistory.create(tmp_path/'db.sqlite3', b'k'*32, 'alice', 'bob')
    with store._connection(write=True) as conn:
        for i in range(80): store._insert(conn, {'msg_id':str(i), 'text':'x', 'is_mine':False})
    reads = []
    decrypt = store._decrypt
    def count(*args): reads.append(True); return decrypt(*args)
    monkeypatch.setattr(store, '_decrypt', count)
    with pytest.raises(HistoryCancelled): store.page(cancel=lambda: len(reads)>=5)
    assert len(reads)==5
    assert store.page().total==80


def test_legacy_backup_hash_is_cooperatively_cancelled(tmp_path):
    path = tmp_path/'old.enc'
    path.write_bytes(b'x'*(5*1024*1024))
    calls=[]
    def cancelled(): calls.append(True); return len(calls)>=4
    with pytest.raises(HistoryCancelled): file_hash(path, cancel=cancelled)
    assert len(calls)==4 and path.stat().st_size==5*1024*1024


def test_legacy_filter_can_cancel_without_returning_partial_page():
    calls=[]
    def cancelled(): calls.append(True); return len(calls)>=10
    data=[{'msg_id':str(i), 'text':'x', 'is_mine':False} for i in range(100)]
    with pytest.raises(HistoryCancelled): legacy_history_view(data, cancel=cancelled)
    assert len(calls)==10 and len(data)==100


def test_qthread_worker_returns_results_and_cancels_safely():
    app=QCoreApplication.instance() or QCoreApplication([])
    loop=QEventLoop()
    entered=threading.Event()
    def slow(owner,chat,offset,*,page_size,query,cancel):
        entered.set()
        while True:
            check_cancel(cancel)
            time.sleep(0.005)
    worker=HistoryPageWorker('alice','bob',load_fn=slow)
    worker.finished.connect(loop.quit)
    worker.start()
    assert entered.wait(2)
    QTimer.singleShot(20, worker.cancel)
    QTimer.singleShot(3000, loop.quit)
    loop.exec()
    assert worker.wait(3000) and worker.result == ('cancelled',None)
    # A successful reader keeps its scope and result, after native finished.
    result=object(); loop2=QEventLoop()
    worker2=HistoryPageWorker('alice','bob',10,query='hello',
        load_fn=lambda owner,chat,offset,**kw: (owner,chat,offset,kw['query'],result))
    worker2.finished.connect(loop2.quit)
    QTimer.singleShot(3000, loop2.quit)
    worker2.start(); loop2.exec()
    assert worker2.wait(3000) and worker2.result == ('ok',('alice','bob',10,'hello',result))


def test_worker_does_not_retain_exception_or_plaintext_traceback():
    def bad(*args,**kwargs): raise ValueError('secret should not be retained')
    worker=HistoryPageWorker('alice','bob',load_fn=bad)
    worker.run()
    assert worker.result == ('error','ValueError')
