class AppState:
    def __init__(self):
        self.server_url: str = ""
        self.username: str = ""
        self.device_name: str = ""
        self.device_id: str = ""
        self.token: str = ""

        # ── Личные чаты ──────────────────────────────────────────
        self.current_chat_username: str | None = None
        self.current_chat_device_id: str | None = None
        self.allies: dict = {}

        # ── Группы ───────────────────────────────────────────────
        # Текущий открытый чат — либо личный либо групповой
        self.current_chat_type: str = "ally"  # "ally" | "group"
        self.current_group_id: str | None = None

        # groups = {
        #     "group_id": {
        #         "name": "Название группы",
        #         "created_by_device_id": "...",
        #         "members": [
        #             {
        #                 "device_id": "...",
        #                 "device_name": "...",
        #                 "public_key": "...",
        #                 "role": "owner" | "member"
        #             }
        #         ],
        #         "my_sender_key": {
        #             "key_id": "...",
        #             "key": "base64...",
        #             "chain_index": 0
        #         },
        #         "sender_keys": {
        #             "device_id": {
        #                 "key_id": "...",
        #                 "key": "base64...",
        #                 "chain_index": 0
        #             }
        #         }
        #     }
        # }
        self.groups: dict = {}


state = AppState()