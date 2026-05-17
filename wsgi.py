from app import app, init_db

# Initialize database
init_db()

# This is what Vercel will call
if __name__ == "__main__":
    app.run()
