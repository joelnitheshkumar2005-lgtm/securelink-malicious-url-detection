import os
import subprocess
import sys

def main():
    print("=== SecureLink Deployment Prep ===")
    
    # Check if waitress is installed
    try:
        import waitress
        print("Waitress found.")
    except ImportError:
        print("Waitress not found. Installing dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    
    print("\nStarting Production Server...")
    print("Access the app at: http://localhost:8080")
    print("Press CTRL+C to stop.\n")
    
    # Run the production script
    subprocess.call([sys.executable, "run_production.py"])

if __name__ == "__main__":
    main()
