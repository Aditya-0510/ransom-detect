#!/usr/bin/env python3
"""
Project Setup and Runner Script
Place this file in your project root directory as 'run_detector.py'
"""

import sys
import os
from pathlib import Path

def setup_project_paths():
    """Add necessary paths to Python sys.path"""
    project_root = Path(__file__).parent
    src_path = project_root / "src"
    
    # Add both project root and src to Python path
    for path in [str(project_root), str(src_path)]:
        if path not in sys.path:
            sys.path.insert(0, path)
    
    return project_root, src_path

def check_requirements():
    """Check if required packages are installed"""
    required_packages = [
        'numpy', 'pandas', 'scikit-learn', 'psutil', 
        'watchdog', 'matplotlib', 'seaborn'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("📦 Install with: pip install -r requirements.txt")
        return False
    
    print("✅ All required packages are installed")
    return True

def run_detection_system():
    """Run the main detection system"""
    print("🛡️ Starting Ransomware Detection System...")
    print("=" * 60)
    
    # Setup paths
    project_root, src_path = setup_project_paths()
    
    # Check requirements
    if not check_requirements():
        return
    
    # Import and run the main detector
    try:
        # Change working directory to project root
        os.chdir(project_root)
        
        # Now import the main detector
        from src.main_detector import main
        
        print("🚀 Initializing detection system...")
        main()
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("🔧 Make sure all files are in the correct locations")
    except Exception as e:
        print(f"❌ Error starting detection system: {e}")

def run_web_interface():
    """Run the web interface"""
    print("🌐 Starting Web Interface...")
    print("=" * 60)
    
    # Setup paths
    project_root, src_path = setup_project_paths()
    
    # Check requirements
    if not check_requirements():
        return
    
    try:
        # Additional web requirements
        import flask
        import flask_socketio
        print("✅ Web interface packages available")
        
        # Change working directory to project root
        os.chdir(project_root)
        
        # Import and run web interface
        from web_interface.app import run_web_interface
        
        print("🌐 Starting web interface on http://127.0.0.1:5000")
        run_web_interface()
        
    except ImportError as e:
        print(f"❌ Web interface import error: {e}")
        print("📦 Install web packages: pip install flask flask-socketio")
    except Exception as e:
        print(f"❌ Error starting web interface: {e}")

def test_components():
    """Test individual components"""
    print("🧪 Testing System Components...")
    print("=" * 60)
    
    # Setup paths
    project_root, src_path = setup_project_paths()
    os.chdir(project_root)
    
    tests = {
        "Data Collector": "src.data_collector",
        "Feature Extractor": "src.feature_extractor", 
        "ML Models": "src.ml_models",
        "Response System": "src.response_system"
    }
    
    for component_name, module_name in tests.items():
        try:
            print(f"Testing {component_name}... ", end="")
            __import__(module_name)
            print("✅ OK")
        except Exception as e:
            print(f"❌ FAILED: {e}")

def main():
    """Main menu"""
    print("""
🛡️  RANSOMWARE DETECTION SYSTEM
=====================================

Choose an option:
1. 🚀 Run Detection System (Command Line)
2. 🌐 Run Web Interface
3. 🧪 Test Components
4. ❌ Exit

""")
    
    while True:
        try:
            choice = input("Enter your choice (1-4): ").strip()
            
            if choice == "1":
                run_detection_system()
                break
            elif choice == "2":
                run_web_interface()
                break
            elif choice == "3":
                test_components()
                break
            elif choice == "4":
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please enter 1, 2, 3, or 4.")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()