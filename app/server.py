import uvicorn
from core.config import settings

if __name__ == "__main__":
    uvicorn.run("app:app", host=settings.APP_URI, port=settings.PORT, reload=True)