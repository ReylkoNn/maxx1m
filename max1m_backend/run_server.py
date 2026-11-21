import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        # WebSocket connections are kept in process memory; multiple workers
        # cannot deliver events to clients connected to a different worker.
        workers=1,
        ws_max_size=128 * 1024,
        log_level="info",
    )