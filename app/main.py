from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import (
    FastAPI,
    UploadFile,
    File,
    BackgroundTasks,
    HTTPException,
)

from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import (
    DATA_DIR,
    UPLOAD_DIR,
    STATIC_DIR,
    MAX_UPLOAD_BYTES,
)

from .database import (
    init_db,
    create_job,
    get_job,
    get_findings,
    get_chunks,
)

from .model_client import LocalModelClient
from .analyzer import analyze_job


@asynccontextmanager
async def lifespan(app: FastAPI):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    init_db()

    yield


app = FastAPI(
    title="Cultive8 Local AI Security Log Analyzer",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIR),
    name="static",
)


@app.get("/", include_in_schema=False)
async def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def api_health():

    model = LocalModelClient()

    ready = await model.health()

    return {
        "status": "ok",
        "model_status": "ready" if ready else "offline",
        "model_endpoint": "127.0.0.1:8080",
        "analysis_mode": "local-only",
    }


@app.post("/api/analyze")
async def upload_log(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):

    filename = Path(file.filename or "upload.log").name

    suffix = Path(filename).suffix.lower()

    if suffix not in {".log", ".txt"}:
        raise HTTPException(
            status_code=400,
            detail="Only .log and .txt files are accepted.",
        )

    job_id = uuid.uuid4().hex

    destination = UPLOAD_DIR / f"{job_id}{suffix}"

    total = 0

    try:

        with destination.open("wb") as target:

            while True:

                block = await file.read(1024 * 1024)

                if not block:
                    break

                total += len(block)

                if total > MAX_UPLOAD_BYTES:

                    target.close()

                    destination.unlink(missing_ok=True)

                    raise HTTPException(
                        status_code=413,
                        detail=(
                            f"Upload exceeds "
                            f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit."
                        ),
                    )

                target.write(block)

    finally:
        await file.close()

    if total == 0:

        destination.unlink(missing_ok=True)

        raise HTTPException(
            status_code=400,
            detail="The uploaded file is empty.",
        )

    try:

        with destination.open("rb") as source:
            sample = source.read(4096)

        if b"\x00" in sample:

            destination.unlink(missing_ok=True)

            raise HTTPException(
                status_code=400,
                detail=(
                    "Binary files are not supported. "
                    "Upload a text log."
                ),
            )

    except OSError as exc:

        destination.unlink(missing_ok=True)

        raise HTTPException(
            status_code=500,
            detail=f"Could not save upload: {exc}",
        )

    create_job(
        job_id,
        filename,
        str(destination),
    )

    background_tasks.add_task(
        analyze_job,
        job_id,
    )

    return {
        "job_id": job_id,
        "filename": filename,
        "bytes": total,
        "status": "queued",
    }


@app.get("/api/jobs/{job_id}")
async def job_status(job_id: str):

    job = get_job(job_id)

    if not job:

        raise HTTPException(
            status_code=404,
            detail="Analysis job not found.",
        )

    chunks = get_chunks(job_id)

    completed_chunks = sum(
        1
        for chunk in chunks
        if chunk["status"] == "completed"
    )

    failed_chunks = sum(
        1
        for chunk in chunks
        if chunk["status"] == "failed"
    )

    return {
        "id": job["id"],
        "filename": job["filename"],
        "status": job["status"],
        "phase": job["phase"],
        "processed_chunks": job["processed_chunks"],
        "completed_chunks": completed_chunks,
        "failed_chunks": failed_chunks,
        "findings_count": job["findings_count"],
        "error": job["error"],
        "created_at": job["created_at"],
        "updated_at": job["updated_at"],
        "report": job["report"],
        "chunks": chunks,
        "findings": get_findings(job_id),
    }


@app.get("/api/jobs/{job_id}/report")
async def job_report(job_id: str):

    job = get_job(job_id)

    if not job:

        raise HTTPException(
            status_code=404,
            detail="Analysis job not found.",
        )

    return JSONResponse({

        "job_id": job_id,

        "filename": job["filename"],

        "status": job["status"],

        "report": job["report"],

        "findings": get_findings(job_id),

        "chunks": get_chunks(job_id),

    })