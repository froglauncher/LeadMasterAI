import os
from main import app

# Initialize the app
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')

# Export the WSGI application
application = app

if __name__ == "__main__":
    app.run() 