from burp import IBurpExtender, IContextMenuFactory
from java.io import PrintWriter
from javax.swing import JMenuItem, JFrame, JPanel, JLabel, JTextArea, JScrollPane, JButton
from java.awt import GridBagLayout, GridBagConstraints, Insets
import json

class BurpExtender(IBurpExtender, IContextMenuFactory):

    DEFAULT_HEADERS_TO_REMOVE = [
        "sec-", "if-", "accept-encoding", "accept-language",
        "cache-control", "pragma", "priority", "baggage", "sentry-trace"
    ]

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("Request Cleaner")
        callbacks.registerContextMenuFactory(self)

        self.saved_headers = json.loads(callbacks.loadExtensionSetting("HEADERS_TO_REMOVE") or "[]")
        self.saved_cookies = json.loads(callbacks.loadExtensionSetting("COOKIES_TO_REMOVE") or "[]")

        self._stdout.println("[*] Request Cleaner loaded.")

    def createMenuItems(self, invocation):
        menu = []
        menu.append(JMenuItem("Clean", actionPerformed=lambda x: self.simplify_request(invocation)))
        menu.append(JMenuItem("Settings", actionPerformed=lambda x: self.open_settings(invocation)))
        return menu

    def simplify_request(self, invocation):
        selected_items = invocation.getSelectedMessages()
        if not selected_items:
            self._stdout.println("[!] No request selected.")
            return

        message = selected_items[0]
        request_info = self._helpers.analyzeRequest(message)

        headers = list(request_info.getHeaders())
        body = message.getRequest()[request_info.getBodyOffset():]
        new_headers = []

        saved_headers_json = self._callbacks.loadExtensionSetting("HEADERS_TO_REMOVE")
        saved_cookies_json = self._callbacks.loadExtensionSetting("COOKIES_TO_REMOVE")

        if saved_headers_json is None or saved_headers_json.strip() == "":
            headers_to_remove = self.DEFAULT_HEADERS_TO_REMOVE
        else:
            headers_to_remove = [h.lower() for h in json.loads(saved_headers_json)]

        if saved_cookies_json is None or saved_cookies_json.strip() == "":
            cookies_to_remove = []
        else:
            cookies_to_remove = [c.strip() for c in json.loads(saved_cookies_json)]

        for header in headers:
            header_lower = header.lower()
            header_name = header.split(":", 1)[0].strip().lower()

            if header_name == "host":
                new_headers.append(header)
                continue

            if header_name == "cookie":
                cookie_value = header.split(":", 1)[1].strip()
                cookies = cookie_value.split(";")
                filtered_cookies = []
                for cookie in cookies:
                    name = cookie.strip().split("=")[0]
                    if name not in cookies_to_remove:
                        filtered_cookies.append(cookie.strip())
                if filtered_cookies:
                    new_headers.append("Cookie: " + "; ".join(filtered_cookies))
                continue

            if any(header_name.startswith(prefix) for prefix in headers_to_remove):
                continue

            new_headers.append(header)

        new_request = self._helpers.buildHttpMessage(new_headers, body)

        self._callbacks.sendToRepeater(
            message.getHttpService().getHost(),
            message.getHttpService().getPort(),
            message.getHttpService().getProtocol() == "https",
            new_request,
            "clean"
        )


    def open_settings(self, invocation):
        selected_items = invocation.getSelectedMessages()
        if not selected_items:
            self._stdout.println("[!] No request selected to get headers/cookies.")
            return

        message = selected_items[0]
        request_info = self._helpers.analyzeRequest(message)
        headers = request_info.getHeaders()

        filtered_headers = self.saved_headers or [
            h.split(":", 1)[0].strip() for h in headers[1:] if not h.lower().startswith(("cookie", "host"))
        ]

        cookie_names = self.saved_cookies or []
        if not cookie_names:
            cookie_headers = [h for h in headers if h.lower().startswith("cookie")]
            if cookie_headers:
                cookie_str = cookie_headers[0].split(":", 1)[1].strip()
                cookie_names = [c.strip().split("=", 1)[0] for c in cookie_str.split(";")]

        frame = JFrame("Request Cleaner - Settings")
        frame.setSize(600, 400)
        frame.setLocationRelativeTo(None)

        main_panel = JPanel()
        main_panel.setLayout(GridBagLayout())
        gbc = GridBagConstraints()

        label_insets = Insets(5, 10, 5, 10)
        text_insets = Insets(5, 10, 10, 10)

        def save_settings(headers_area, cookies_area, frame):
            headers_to_remove = [line.strip() for line in headers_area.getText().split("\n") if line.strip()]
            cookies_to_remove = [line.strip() for line in cookies_area.getText().split("\n") if line.strip()]

            self._callbacks.saveExtensionSetting("HEADERS_TO_REMOVE", json.dumps(headers_to_remove))
            self._callbacks.saveExtensionSetting("COOKIES_TO_REMOVE", json.dumps(cookies_to_remove))
            self.saved_headers = headers_to_remove
            self.saved_cookies = cookies_to_remove
            frame.dispose()

        gbc.gridx = 0
        gbc.gridy = 0
        gbc.weightx = 0.6
        gbc.weighty = 0
        gbc.fill = GridBagConstraints.NONE
        gbc.insets = label_insets
        gbc.anchor = GridBagConstraints.WEST
        main_panel.add(JLabel("Headers to remove:"), gbc)

        gbc.gridy = 1
        gbc.fill = GridBagConstraints.BOTH
        gbc.weighty = 0.2
        gbc.insets = text_insets
        headers_area = JTextArea("\n".join(filtered_headers))
        headers_area.setLineWrap(True)
        headers_scroll = JScrollPane(headers_area)
        main_panel.add(headers_scroll, gbc)

        gbc.gridx = 1
        gbc.gridy = 0
        gbc.weightx = 0.6
        gbc.weighty = 0
        gbc.fill = GridBagConstraints.NONE
        gbc.insets = label_insets
        gbc.anchor = GridBagConstraints.WEST
        main_panel.add(JLabel("Cookies to remove:"), gbc)

        gbc.gridy = 1
        gbc.fill = GridBagConstraints.BOTH
        gbc.weighty = 0.2
        gbc.insets = text_insets
        cookies_area = JTextArea("\n".join(cookie_names))
        cookies_area.setLineWrap(True)
        cookies_scroll = JScrollPane(cookies_area)
        main_panel.add(cookies_scroll, gbc)

        gbc.gridx = 0
        gbc.gridy = 2
        gbc.gridwidth = 2
        gbc.weighty = 0.0
        save_button = JButton("Save", actionPerformed=lambda e: save_settings(headers_area, cookies_area, frame))
        main_panel.add(save_button, gbc)

        frame.getContentPane().add(main_panel)
        frame.setVisible(True)
