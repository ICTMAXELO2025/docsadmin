# setup.py - Optional setup script
import os
import sys
import subprocess

def setup_environment():
    print("Setting up Document Manager...")
    
    # Check if .env exists
    if not os.path.exists('.env'):
        print("Creating .env file...")
        with open('.env', 'w') as f:
            f.write("""SECRET_KEY=your-super-secret-key-change-this-in-production
DATABASE_URL=postgresql://postgres:Maxelo@2023@localhost:5432/admin_docs
DEBUG=True
""")
        print("Please edit .env file with your actual configuration")
    
    print("Setup complete!")
    print("Don't forget to:")
    print("1. Activate virtual environment: venv\\Scripts\\activate (Windows) or source venv/bin/activate (Mac/Linux)")
    print("2. Install dependencies: pip install -r requirements.txt")
    print("3. Run the app: python app.py")

if __name__ == '__main__':
    setup_environment()