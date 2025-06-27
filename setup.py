"""
Setup script for the CyberWatch CTI Dashboard
- Creates a virtual environment
- Installs dependencies
- Sets up the initial database
"""
import os
import subprocess
import platform
import sys
from pathlib import Path

def print_step(message):
    """Print a highlighted step message"""
    print("\n" + "=" * 80)
    print(f" {message}")
    print("=" * 80)

def run_command(command):
    """Run a shell command"""
    print(f"Running: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return False
    print(result.stdout)
    return True

def main():
    """Main setup function"""
    print_step("Setting up CyberWatch CTI Dashboard")
    
    # Determine the Python executable
    python_exe = sys.executable
    print(f"Using Python: {python_exe}")
    
    # Create virtual environment
    print_step("Creating virtual environment")
    venv_dir = "venv"
    if not os.path.exists(venv_dir):
        if not run_command([python_exe, "-m", "venv", venv_dir]):
            print("Failed to create virtual environment.")
            return
    
    # Determine the pip executable based on the platform
    if platform.system() == "Windows":
        pip_exe = os.path.join(venv_dir, "Scripts", "pip")
        activate_script = os.path.join(venv_dir, "Scripts", "activate")
    else:
        pip_exe = os.path.join(venv_dir, "bin", "pip")
        activate_script = os.path.join(venv_dir, "bin", "activate")
    
    # Install dependencies
    print_step("Installing dependencies")
    if not run_command([pip_exe, "install", "--upgrade", "pip"]):
        print("Failed to upgrade pip.")
        return
    
    if not run_command([pip_exe, "install", "-r", "requirements.txt"]):
        print("Failed to install dependencies.")
        return
    
    # Create .env file if it doesn't exist
    print_step("Setting up environment")
    env_path = ".env"
    env_example_path = ".env.example"
    
    if not os.path.exists(env_path) and os.path.exists(env_example_path):
        print("Creating .env file from .env.example")
        with open(env_example_path, "r") as example_file:
            with open(env_path, "w") as env_file:
                env_file.write(example_file.read())
        print("Created .env file. Please update it with your API keys.")
    
    # Print setup complete message
    print_step("Setup complete!")
    print("\nTo activate the virtual environment:")
    
    if platform.system() == "Windows":
        print(f"    {venv_dir}\\Scripts\\activate")
    else:
        print(f"    source {venv_dir}/bin/activate")
    
    print("\nTo run the application:")
    print("    flask run")
    print("\nOr use the VS Code task: 'Run Flask Application'")

if __name__ == "__main__":
    main()
