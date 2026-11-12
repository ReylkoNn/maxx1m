import ast
from pathlib import Path
from types import SimpleNamespace
import pytest
from app.history_paging import history_page, searchable_text, PAGE_SIZE, legacy_history_view
from app import secure_storage


def test_page_navigation_covers_history_without_discarding():
    data = list(range(138))
    offset = 0
    pages = []
    while True:
        page = history_page(data, offset)
        assert len(page.messages) <= PAGE_SIZE
        pages[:0] = page.messages
        if not page.has_older:
            break
        offset += PAGE_SIZE
    assert pages == data
    assert history_page(data, 10000).messages == [0]
    assert history_page([], 5).messages == []
    with pytest.raises(ValueError): history_page(data, -1)


def test_incoming_messages_do_not_shift_old_page():
    data = list(range(100))
    old = history_page(data, 25).messages
    data.append(100)
    assert history_page(data, 26).messages == old


def test_strict_history_errors_are_not_empty_history(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, 'BASE_DIR', tmp_path)
    monkeypatch.setattr(secure_storage.keyring, 'get_password', lambda *a: None)
    file = secure_storage.SecureStorage._get_messages_file('alice', 'bob')
    file.write_bytes(b'not encrypted')
    with pytest.raises(ValueError, match='key is missing'):
        secure_storage.SecureStorage.load_messages_strict('alice', 'bob')
    assert file.read_bytes() == b'not encrypted'


def load_render_method(env):
    path = Path(__file__).resolve().parents[1] / 'app/windows/main_screen.py'
    tree = ast.parse(path.read_text())
    nodes = [n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'MainScreen'
             for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_render_history_page']
    assert len(nodes) == 1
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(path), 'exec'), env)
    return env['_render_history_page']


class Label:
    def __init__(self, text=''): self.text, self.visible = text, True
    def setWordWrap(self, *_): pass
    def setAlignment(self, *_): pass
    def setText(self, text): self.text = text
    def setVisible(self, visible): self.visible = visible

class Layout:
    def __init__(self): self.items = []
    def count(self): return len(self.items) + 1
    def insertWidget(self, pos, widget): self.items.insert(pos, widget)

class FakeStorage:
    def __init__(self, messages): self.messages, self.marked = messages, []
    def load_messages_strict(self, *args):
        if isinstance(self.messages, Exception): raise self.messages
        return [dict(m) for m in self.messages]
    def load_history_page(self, owner, chat, offset=0, page_size=PAGE_SIZE, query=None):
        return legacy_history_view(self.load_messages_strict(owner, chat), offset, page_size, query)
    def mark_messages_as_read(self, owner, chat, ids):
        self.marked.extend(ids)
        return True


def make_screen(storage):
    state = SimpleNamespace(username='alice', server_url='https://node', device_id='dev', token='token', current_chat_type='ally', current_chat_username='bob', current_group_id=None)
    warnings = []
    env = {'state': state, 'storage': storage, 'history_page': history_page, 'searchable_text': searchable_text, 'QLabel': Label,
           'QMessageBox': SimpleNamespace(warning=lambda *a: warnings.append(a)),
           'Qt': SimpleNamespace(AlignCenter=0), 'MessageBubble': lambda **kw: SimpleNamespace(**kw)}
    class Screen:
        _render_history_page = load_render_method(env)
        def __init__(self):
            self._history_offset = 0; self._history_query = None; self._history_available = False
            self.chat_area = object(); self.right_stack = SimpleNamespace(currentWidget=lambda: self.chat_area)
            self.messages_layout = Layout(); self.history_nav = Label(); self.card = SimpleNamespace(badge=Label())
            self.shown, self.sent = [], []
        def clear_messages(self): self.messages_layout.items.clear()
        def _update_history_navigation(self): pass
        def window(self): return SimpleNamespace(isActiveWindow=lambda: True)
        def isVisible(self): return True
        def _get_ally_card(self, chat): return self.card
        def _load_message_history(self, chat, msgs): self.shown = [m['msg_id'] for m in msgs]
        def _send_system_payload(self, chat, payload): self.sent.append(payload)
        def _connect_bubble_signals(self, *args): pass
    return Screen(), warnings


def test_page_marks_only_visible_read_after_render_and_search_none():
    store = FakeStorage([{'msg_id': str(i), 'text': 'text', 'is_mine': False, 'is_read': False} for i in range(60)])
    screen, _ = make_screen(store)
    screen._render_history_page()
    assert screen.shown == [str(i) for i in range(35, 60)]
    assert store.marked == screen.shown and screen.card.unread_count == 35
    assert screen.sent[0]['msg_ids'] == screen.shown
    store.marked.clear(); screen.sent.clear(); screen._history_query = 'text'
    screen._render_history_page()
    assert not store.marked and not screen.sent


def test_read_or_render_failure_does_not_ack_or_hide_error():
    store = FakeStorage(ValueError('missing key'))
    screen, _ = make_screen(store)
    screen._render_history_page()
    assert not screen._history_available and 'История недоступна' in screen.messages_layout.items[0].text
    assert not screen.sent
    store.messages = [{'msg_id': 'id', 'text': 'hello', 'is_mine': False, 'is_read': False}]
    screen._load_message_history = lambda *a: (_ for _ in ()).throw(ValueError('bad UI data'))
    screen._render_history_page()
    assert not screen._history_available and not store.marked and not screen.sent
    assert 'Не удалось отобразить' in screen.messages_layout.items[0].text


def test_search_never_exposes_attachment_keys():
    image = {"text": "[IMAGE_META]|file-id|secret-key|a beautiful sunset"}
    voice = {"text": "[VOICE_META]|file-id|secret-key|1.0"}
    assert searchable_text(image) == "Фото a beautiful sunset"
    assert searchable_text(voice) == "Голосовое сообщение"
    assert all("secret-key" not in searchable_text(m) for m in (image, voice))


def test_incoming_while_viewing_older_page_stays_unread_and_keeps_anchor():
    import json
    path = Path(__file__).resolve().parents[1] / 'app/windows/main_screen.py'
    tree = ast.parse(path.read_text())
    nodes = [n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'MainScreen'
             for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_handle_decrypted_payload']
    saved = []
    state = SimpleNamespace(username='alice', current_chat_username='bob')
    store = SimpleNamespace(save_message=lambda *a, **kw: saved.append(kw) or True)
    env = {'state': state, 'storage': store, 'json': json}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(path), 'exec'), env)
    card = SimpleNamespace(update_preview=lambda *_: None, increment_unread=lambda: saved.append('badge'))
    class Screen:
        _handle_decrypted_payload = env['_handle_decrypted_payload']
        _history_available = True
        _history_offset = 25
        _history_total = 100
        _history_query = None
        def window(self): return SimpleNamespace(isActiveWindow=lambda: True)
        def _get_ally_card(self, *_): return card
        def _get_ally_item(self, *_): return None
        def _update_history_navigation(self): pass
        def _send_system_payload(self, *args): raise AssertionError('must not acknowledge hidden messages')
    screen = Screen()
    assert screen._handle_decrypted_payload('bob', json.dumps({'type':'text', 'text':'new', 'msg_id':'new'}), 'sig')
    assert saved[0]['is_read'] is False and saved[1] == 'badge'
    assert screen._history_offset == 26 and screen._history_total == 101

    state.server_url='https://node'; state.device_id='dev'; state.token='token'
    state.current_chat_type='ally'; state.current_group_id=None
    context=('alice','https://node','dev','token','ally','bob',None,26,None)
    screen._history_worker=SimpleNamespace(history_request=(1, context, 'bob', 'target'))
    screen._history_pending=None
    targets=[]
    screen._request_history_target=lambda target: targets.append(target)
    assert screen._handle_decrypted_payload('bob', json.dumps({'type':'text','text':'newer','msg_id':'newer'}), 'sig')
    assert screen._history_offset == 27 and targets == ['target']


def test_failed_read_persistence_never_sends_receipt():
    store = FakeStorage([{'msg_id':'id', 'text':'hello', 'is_mine':False, 'is_read':False}])
    store.mark_messages_as_read = lambda *a: (_ for _ in ()).throw(OSError('failed'))
    screen, warnings = make_screen(store)
    screen._render_history_page()
    assert not screen.sent and screen.card.unread_count == 1 and warnings


def test_history_names_are_not_silently_collapsed(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, 'BASE_DIR', tmp_path)
    valid = secure_storage.SecureStorage._get_messages_file('alice', 'bob')
    valid.write_bytes(b'important')
    for value in ('b.o.b', '../bob', '', '🙂', 'bob/else'):
        with pytest.raises(ValueError, match='Invalid chat history identifier'):
            secure_storage.SecureStorage._get_messages_file('alice', value)
    assert valid.read_bytes() == b'important'
    assert secure_storage.SecureStorage._get_messages_file('alice', 'group_01234567-89ab-cdef-0123-0123456789ab').name.endswith('.enc')


def test_legacy_and_row_store_produce_same_view_and_ui_receipts(tmp_path, monkeypatch):
    from app.history_store import EncryptedHistory, migrate_legacy_copy
    monkeypatch.setattr(secure_storage, 'BASE_DIR', tmp_path)
    keys = {}
    monkeypatch.setattr(secure_storage.keyring, 'get_password', lambda service, name: keys.get(name))
    monkeypatch.setattr(secure_storage.keyring, 'set_password', lambda service, name, value: keys.__setitem__(name, value))
    legacy = secure_storage.SecureStorage
    for i in range(60):
        assert legacy.save_message('alice', 'bob', f'text {i}', False, msg_id=f'msg-{i}', is_read=i < 10)
    source = legacy._get_messages_file('alice', 'bob')
    key = legacy._get_or_create_local_key('alice')
    row_store = migrate_legacy_copy(source, tmp_path/'new.sqlite3', key, 'alice', 'bob')

    class Rows:
        def load_history_page(self, owner, chat, offset=0, page_size=PAGE_SIZE, query=None):
            assert (owner, chat) == ('alice', 'bob')
            return row_store.page(offset, page_size, query)
        def mark_messages_as_read(self, owner, chat, ids):
            return bool(row_store.update(ids, mark_read=True))

    rows = Rows()
    # The candidate DB is compared while disconnected: the live storage still
    # writes exclusively to the old encrypted JSON file.
    for offset in (0, 25, 100):
        for query in (None, 'text 5', 'missing'):
            assert legacy.load_history_page('alice', 'bob', offset, query=query) == rows.load_history_page('alice', 'bob', offset, query=query)
    assert legacy.history_offset_for_id('alice', 'bob', 'msg-33') == row_store.offset_for_id('msg-33')
    assert legacy.history_offset_for_id('alice', 'bob', 'missing') is None

    legacy_ui = SimpleNamespace(load_history_page=legacy.load_history_page,
                                mark_messages_as_read=legacy.mark_messages_as_read)
    legacy_screen, _ = make_screen(legacy_ui)
    row_screen, _ = make_screen(rows)
    legacy_screen._render_history_page()
    row_screen._render_history_page()
    assert legacy_screen.shown == row_screen.shown == [f'msg-{i}' for i in range(35,60)]
    assert legacy_screen.sent == row_screen.sent
    assert legacy_screen.card.unread_count == row_screen.card.unread_count == 25
    assert legacy.load_history_page('alice', 'bob') == rows.load_history_page('alice', 'bob')


def test_history_offset_preserves_first_duplicate_and_ignores_deleted(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_storage, 'BASE_DIR', tmp_path)
    keys = {}
    monkeypatch.setattr(secure_storage.keyring, 'get_password', lambda service, name: keys.get(name))
    monkeypatch.setattr(secure_storage.keyring, 'set_password', lambda service, name, value: keys.__setitem__(name, value))
    rows = [{'msg_id':'duplicate', 'text':'first'}, {'msg_id':'deleted', 'deleted':True},
            {'msg_id':'duplicate', 'text':'second'}, {'msg_id':'last'}]
    secure_storage.SecureStorage._save_messages_to_file('alice', 'bob', rows)
    assert secure_storage.SecureStorage.history_offset_for_id('alice', 'bob', 'duplicate') == 2
    page, _ = secure_storage.SecureStorage.load_history_page_background('alice', 'bob', target_id='duplicate')
    assert page.offset == 2 and page.messages[-1]['text'] == 'first'
    page, _ = secure_storage.SecureStorage.load_history_page_background('alice', 'bob', target_id='deleted')
    assert page is None
    assert secure_storage.SecureStorage.history_offset_for_id('alice', 'bob', 'deleted') is None
    with pytest.raises(ValueError): secure_storage.SecureStorage.history_offset_for_id('alice', 'bob', '')


def extract_screen_method(name, env):
    path = Path(__file__).resolve().parents[1] / 'app/windows/main_screen.py'
    tree = ast.parse(path.read_text())
    node = next(n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'MainScreen'
                for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(path), 'exec'), env)
    return env[name]


def test_chat_previews_use_bounded_page_interface_and_report_errors():
    from datetime import datetime
    from app.history_paging import HistoryView
    calls = []
    class List:
        def addItem(self, item): self.item = item
        def setItemWidget(self, item, card): self.card = card
        def sortItems(self, *args): pass
    class Item:
        def __init__(self, *args): self.last_activity = None
        def setSizeHint(self, *args): pass
    class Card:
        def __init__(self, *args): self.preview = ''; self.badge = Label(); self.unread_count = 0
        def update_preview(self, text): self.preview = text
    class Store:
        fail = False
        def load_history_page(self, owner, chat, page_size):
            calls.append((owner, chat, page_size))
            if self.fail: raise ValueError('damaged history')
            return HistoryView([{'text':'[IMAGE_META]|id|key|caption','timestamp':'2025-01-01T00:00:00'}], 0, 50, 7, True, False)
    store = Store()
    env = {'storage':store, 'state':SimpleNamespace(username='alice'),
           'AllyListItem':Item, 'GroupListItem':Item, 'AllyCardWidget':Card, 'GroupCardWidget':Card,
           'QSize':lambda *a: None, 'Qt':SimpleNamespace(DescendingOrder=0), 'datetime':datetime}
    Screen = type('Screen', (), {'_add_ally_card':extract_screen_method('_add_ally_card', env),
                                 '_add_group_card':extract_screen_method('_add_group_card', env)})
    screen = Screen(); screen.allies_list = List(); screen.groups_list = List()
    screen._add_ally_card('bob'); screen._add_group_card('g1', 'group')
    assert calls == [('alice','bob',1), ('alice','group_g1',1)]
    assert screen.allies_list.card.preview == 'Фото' and screen.allies_list.card.unread_count == 7
    assert screen.groups_list.card.preview == 'Фото'
    store.fail = True
    screen._add_ally_card('bob'); screen._add_group_card('g1', 'group')
    assert screen.allies_list.card.preview == screen.groups_list.card.preview == 'История недоступна'


def test_reply_navigation_requests_background_target_and_guards_reveal():
    calls = []
    state = SimpleNamespace(username='alice', server_url='https://node', device_id='dev', token='token',
                            current_chat_type='ally', current_chat_username='bob', current_group_id=None)
    env = {'state':state}
    scroll = extract_screen_method('_scroll_to_message', env)
    reveal = extract_screen_method('_reveal_history_message', env)
    class Screen:
        _scroll_to_message = scroll
        _reveal_history_message = reveal
        def __init__(self):
            self.messages_layout = SimpleNamespace(count=lambda: 1)
            self._history_query = None; self._history_offset = 40
        def _request_history_target(self, target): calls.append(target)
    screen = Screen()
    screen._scroll_to_message('target')
    assert calls == ['target']
    context = ('alice','https://node','dev','token','ally','bob',None,40,None)
    state.current_chat_username = 'other'
    screen._reveal_history_message('target', context)  # Must not touch the new chat.


def make_activation_screen(mark):
    state = SimpleNamespace(username='alice', server_url='https://node', device_id='dev', token='token',
                            current_chat_type='ally', current_chat_username='bob', current_group_id=None)
    alerts = []
    env = {'state':state, 'storage':SimpleNamespace(mark_messages_as_read=mark),
           'QMessageBox':SimpleNamespace(warning=lambda *a: alerts.append(a))}
    method = extract_screen_method('_mark_visible_history_read', env)
    class Entry:
        def __init__(self, item): self.item = item
        def widget(self): return self.item
    class Box:
        def __init__(self, widgets): self.widgets=widgets
        def count(self): return len(self.widgets)+1
        def itemAt(self, i): return Entry(self.widgets[i])
    class Screen:
        _mark_visible_history_read = method
        def __init__(self):
            self._history_available=True; self._history_offset=25; self._history_query=None
            self.active=True; self.chat_area=object(); self.current=self.chat_area
            self.right_stack=SimpleNamespace(currentWidget=lambda: self.current)
            self.widgets=[SimpleNamespace(msg_id='incoming',is_mine=False,is_read=False),
                          SimpleNamespace(msg_id='already',is_mine=False,is_read=True),
                          SimpleNamespace(msg_id='outgoing',is_mine=True,is_read=False)]
            self.messages_layout=Box(self.widgets)
            self.card=SimpleNamespace(unread_count=4,badge=Label()); self.sent=[]
        def window(self): return SimpleNamespace(isActiveWindow=lambda: self.active)
        def _get_ally_card(self, chat): return self.card
        def _send_system_payload(self, chat, payload): self.sent.append((chat,payload))
        def clear_messages(self): raise AssertionError('must not disturb voice playback')
    return Screen(), state, alerts


def test_window_activation_marks_only_current_displayed_page_without_rendering():
    saved=[]
    screen,state,alerts=make_activation_screen(lambda *args: saved.append(args) or True)
    screen._mark_visible_history_read()
    assert saved == [('alice','bob',['incoming'])]
    assert screen.widgets[0].is_read and not screen.widgets[2].is_read
    assert screen.card.unread_count == 3 and screen.sent == [('bob',{'type':'read_ack','msg_ids':['incoming']})]
    screen._mark_visible_history_read()
    assert len(saved) == 1 and len(screen.sent) == 1 and not alerts


def test_activation_never_marks_search_hidden_inactive_or_group():
    calls=[]
    screen,state,_=make_activation_screen(lambda *args: calls.append(args) or True)
    screen._history_query='search'; screen._mark_visible_history_read()
    screen._history_query=None; screen.active=False; screen._mark_visible_history_read()
    screen.active=True; screen.current=object(); screen._mark_visible_history_read()
    screen.current=screen.chat_area; state.current_chat_type='group'; screen._mark_visible_history_read()
    assert calls == [] and not screen.sent


def test_activation_write_failure_and_context_change_never_send_read_receipt():
    def fail(*args): raise OSError('write failed')
    screen,state,alerts=make_activation_screen(fail)
    screen._mark_visible_history_read()
    assert alerts and not screen.sent and not screen.widgets[0].is_read and screen.card.unread_count == 4
    screen,state,_=make_activation_screen(lambda *args: True)
    def switch(*args): state.current_chat_username='carol'; return True
    screen._mark_visible_history_read.__func__.__globals__['storage'].mark_messages_as_read = switch
    screen._mark_visible_history_read()
    assert not screen.sent and not screen.widgets[0].is_read and screen.card.unread_count == 4


def test_render_updates_existing_incoming_bubble_read_flags():
    store=FakeStorage([{'msg_id':'id','text':'hello','is_mine':False,'is_read':False}])
    screen,_=make_screen(store)
    bubble=SimpleNamespace(msg_id='id', is_mine=False, is_read=False)
    def render(chat, messages):
        screen.shown=[m['msg_id'] for m in messages]
        class Entry:
            def widget(self): return bubble
        class BubbleLayout(Layout):
            def count(self): return 2
            def itemAt(self, index): return Entry()
        screen.messages_layout=BubbleLayout()
    screen._load_message_history=render
    screen._render_history_page()
    assert bubble.is_read and screen.sent[0]['msg_ids']==['id']


def test_read_ack_handler_enforces_bounded_ids_before_storage():
    import json
    from app.delivery import MAX_READ_ACK_IDS
    calls=[]
    state=SimpleNamespace(username='alice',current_chat_username=None)
    storage=SimpleNamespace(mark_messages_as_read=lambda *args, **kw: calls.append((args,kw)) or False)
    env={'state':state,'storage':storage,'json':json,'MAX_READ_ACK_IDS':MAX_READ_ACK_IDS}
    method=extract_screen_method('_handle_decrypted_payload',env)
    screen=SimpleNamespace()
    msg=lambda ids: json.dumps({'type':'read_ack','msg_ids':ids})
    assert method(screen,'bob',msg(['x']*MAX_READ_ACK_IDS),'sig')
    assert len(calls)==1 and calls[0][1] == {'only_mine':True}
    assert not method(screen,'bob',msg(['x']*(MAX_READ_ACK_IDS+1)),'sig')
    assert not method(screen,'bob',msg(['x'*257]),'sig')
    assert not method(screen,'bob',msg(['', 'ok']),'sig')
    assert len(calls)==1


def test_render_ignores_page_or_receipt_after_account_switch():
    store=FakeStorage([{'msg_id':'id','text':'hello','is_mine':False,'is_read':False}])
    screen,_=make_screen(store)
    state=screen._render_history_page.__func__.__globals__['state']
    original=store.load_history_page
    def change_during_load(*args,**kwargs):
        page=original(*args,**kwargs)
        state.current_chat_username='carol'
        return page
    store.load_history_page=change_during_load
    screen._render_history_page()
    assert not screen.shown and not screen.sent and not store.marked
    state.current_chat_username='bob'; store.load_history_page=original
    def change_during_write(*args):
        state.username='other'
        return True
    store.mark_messages_as_read=change_during_write
    screen._render_history_page()
    assert not screen.sent and not hasattr(screen.card, 'unread_count')


def test_window_activation_dispatch_requires_visible_main_screen():
    path=Path(__file__).resolve().parents[1]/'app/windows/app_window.py'
    tree=ast.parse(path.read_text())
    node=next(n for c in tree.body if isinstance(c,ast.ClassDef) and c.name=='AppWindow'
              for n in c.body if isinstance(n,ast.FunctionDef) and n.name=='_on_window_activated')
    env={}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),str(path),'exec'),env)
    hits=[]
    screen=SimpleNamespace(_mark_visible_history_read=lambda:hits.append(True))
    window=SimpleNamespace(main_screen=screen,stack=SimpleNamespace(currentWidget=lambda:screen),isActiveWindow=lambda:True)
    env['_on_window_activated'](window)
    assert hits==[True]
    window.isActiveWindow=lambda:False
    env['_on_window_activated'](window)
    window.isActiveWindow=lambda:True
    window.stack.currentWidget=lambda:object()
    env['_on_window_activated'](window)
    assert hits==[True]


def test_live_message_hidden_by_settings_does_not_generate_read_ack():
    import json
    saved=[]; sent=[]; badges=[]
    state=SimpleNamespace(username='alice',current_chat_username='bob')
    storage=SimpleNamespace(save_message=lambda *a,**kw:saved.append(kw) or True)
    class Bubble:
        def __init__(self,*args,**kwargs): self.is_mine=kwargs['is_mine']; self.is_read=kwargs['is_read']
    class Layout:
        def __init__(self): self.items=[]
        def count(self): return len(self.items)+1
        def itemAt(self,i): return SimpleNamespace(widget=lambda:self.items[i])
        def insertWidget(self,i,w): self.items.insert(i,w)
    env={'state':state,'storage':storage,'json':json,'MessageBubble':Bubble,
         'QTimer':SimpleNamespace(singleShot=lambda *a:None)}
    method=extract_screen_method('_handle_decrypted_payload',env)
    class Screen:
        _handle_decrypted_payload=method
        _history_available=True; _history_offset=0; _history_total=0; _history_query=None
        def __init__(self):
            self.messages_layout=Layout(); self.chat_area=object()
            self.right_stack=SimpleNamespace(currentWidget=lambda:object())
        def window(self): return SimpleNamespace(isActiveWindow=lambda:True)
        def isVisible(self): return True
        def _get_ally_card(self,*a): return SimpleNamespace(update_preview=lambda *a:None,increment_unread=lambda:badges.append(1))
        def _get_ally_item(self,*a): return None
        def _connect_bubble_signals(self,*a): pass
        def _trim_live_history(self): pass
        def _send_system_payload(self,*a): sent.append(a)
    screen=Screen()
    assert screen._handle_decrypted_payload('bob',json.dumps({'type':'text','text':'hi','msg_id':'one'}),'sig')
    assert saved[0]['is_read'] is False and not screen.messages_layout.items[0].is_read
    assert badges==[1] and sent==[]
