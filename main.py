from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import uvicorn
from analyzer import analyze_file

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        "index.html", {"request": request, "result": None}
    )


@app.post("/", response_class=HTMLResponse)
async def analyze_code(request: Request, code: str = Form(...)):
    result = analyze_file(code)
    return templates.TemplateResponse(
        "index.html", {"request": request, "result": result, "code": code}
    )

def start():
    uvicorn.run("main:app", port=8000, host="0.0.0.0", log_level="info", reload=True)


if __name__ == "__main__":
    start()
