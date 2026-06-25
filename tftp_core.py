from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Optional, Union


LOGGER = logging.getLogger(__name__)


class TFTPServer:
    def __init__(
        self,
        root_dir: Union[str, Path] = "tftpboot",
        listen_ip: str = "0.0.0.0",
        port: int = 69,
    ) -> None:
        self.root_dir = Path(root_dir)
        self.listen_ip = listen_ip
        self.port = port
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._server: Optional[Any] = None
        self.last_error: Optional[str] = None

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            self.root_dir.mkdir(parents=True, exist_ok=True)
            self.last_error = None
            self._thread = threading.Thread(
                target=self._serve,
                daemon=True,
                name="tftp-server",
            )
            self._thread.start()

    def stop(self) -> None:
        server = self._server
        if server is None:
            return
        try:
            server.stop(now=True)
        except TypeError:
            server.stop()
        except Exception:
            LOGGER.debug("Не удалось остановить TFTP-сервер", exc_info=True)

    def _serve(self) -> None:
        try:
            import tftpy

            self._server = tftpy.TftpServer(str(self.root_dir))
            LOGGER.info(
                "TFTP-сервер слушает %s:%d, root=%s",
                self.listen_ip,
                self.port,
                self.root_dir,
            )
            self._server.listen(listenip=self.listen_ip, listenport=self.port)
        except Exception as exc:
            self.last_error = str(exc)
            LOGGER.exception("TFTP-сервер остановлен из-за ошибки")
