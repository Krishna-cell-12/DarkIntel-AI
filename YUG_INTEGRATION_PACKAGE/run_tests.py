"""
Complete Test Runner for DarkIntel-AI Backend
Run all tests, check coverage, generate reports
"""

import subprocess
import sys
import os
from pathlib import Path

class TestRunner:
    """Run all tests and generate reports"""
    
    def __init__(self):
        self.backend_dir = Path(__file__).parent / "backend"
        self.test_dir = self.backend_dir / "tests"
        self.passed = 0
        self.failed = 0
    
    def run_command(self, command, description):
        """Run a command and print results"""
        print(f"\n{'='*60}")
        print(f"📋 {description}")
        print(f"{'='*60}")
        print(f"Running: {' '.join(command)}\n")
        
        result = subprocess.run(command, cwd=str(self.backend_dir))
        
        if result.returncode == 0:
            print(f"✅ {description} - PASSED")
            self.passed += 1
        else:
            print(f"❌ {description} - FAILED")
            self.failed += 1
        
        return result.returncode == 0
    
    def run_unit_tests(self):
        """Run unit tests"""
        command = [
            sys.executable, "-m", "pytest",
            "tests/test_api.py",
            "-v", "--tb=short"
        ]
        return self.run_command(command, "Unit Tests (API Endpoints)")
    
    def run_websocket_tests(self):
        """Run WebSocket tests"""
        command = [
            sys.executable, "-m", "pytest",
            "tests/test_websocket.py",
            "-v", "--tb=short"
        ]
        return self.run_command(command, "WebSocket Tests")
    
    def run_all_tests(self):
        """Run all tests"""
        command = [
            sys.executable, "-m", "pytest",
            "tests/",
            "-v", "--tb=short"
        ]
        return self.run_command(command, "All Tests")
    
    def run_coverage(self):
        """Run tests with coverage report"""
        command = [
            sys.executable, "-m", "pytest",
            "tests/",
            "--cov=orchestrator",
            "--cov=crawler",
            "--cov-report=html",
            "--cov-report=term",
            "-v"
        ]
        return self.run_command(command, "Tests with Coverage Report")
    
    def run_linting(self):
        """Run linting checks"""
        # Try pylint if available
        command = [
            sys.executable, "-m", "pylint",
            "orchestrator/",
            "--disable=all",
            "--enable=error"
        ]
        try:
            return self.run_command(command, "Linting Checks")
        except:
            print("⚠️  Pylint not available (optional)")
            return True
    
    def check_imports(self):
        """Check if all imports are valid"""
        print(f"\n{'='*60}")
        print("📋 Checking Imports")
        print(f"{'='*60}\n")
        
        try:
            # Try importing main modules
            sys.path.insert(0, str(Path(__file__).parent))
            
            print("Importing orchestrator.main...")
            from backend.orchestrator import main
            print("✅ orchestrator.main imported successfully")
            
            print("Importing orchestrator.models...")
            from backend.orchestrator import models
            print("✅ orchestrator.models imported successfully")
            
            print("Importing crawler.tor_crawler...")
            from backend.crawler import tor_crawler
            print("✅ crawler.tor_crawler imported successfully")
            
            print("\n✅ All imports successful")
            self.passed += 1
            return True
        except Exception as e:
            print(f"\n❌ Import failed: {e}")
            self.failed += 1
            return False
    
    def print_summary(self):
        """Print test summary"""
        print(f"\n{'='*60}")
        print("📊 Test Summary")
        print(f"{'='*60}")
        print(f"✅ Passed: {self.passed}")
        print(f"❌ Failed: {self.failed}")
        print(f"📈 Total: {self.passed + self.failed}")
        
        if self.failed == 0:
            print("\n🎉 All tests passed!")
            return 0
        else:
            print(f"\n⚠️  {self.failed} test suite(s) failed")
            return 1
    
    def run_all(self):
        """Run all test suites"""
        print("🧪 DarkIntel-AI Backend Test Suite")
        print("="*60)
        
        # Check imports first
        self.check_imports()
        
        # Run tests
        self.run_all_tests()
        
        # Try to run WebSocket tests separately
        if Path(self.test_dir / "test_websocket.py").exists():
            self.run_websocket_tests()
        
        # Generate coverage
        try:
            self.run_coverage()
        except:
            print("\n⚠️  Coverage report generation skipped")
        
        # Print summary
        return self.print_summary()

def quick_test():
    """Run quick tests only"""
    print("⚡ Quick Test Run (API Endpoints Only)")
    print("="*60)
    
    backend_dir = Path(__file__).parent / "backend"
    command = [
        sys.executable, "-m", "pytest",
        str(backend_dir / "tests" / "test_api.py"),
        "-v", "-k", "root or health or demo",
        "--tb=short"
    ]
    
    result = subprocess.run(command)
    return result.returncode

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DarkIntel-AI Backend Test Runner")
    parser.add_argument("--quick", action="store_true", help="Run quick tests only")
    parser.add_argument("--coverage", action="store_true", help="Generate coverage report")
    parser.add_argument("--websocket", action="store_true", help="Run WebSocket tests only")
    parser.add_argument("--imports", action="store_true", help="Check imports only")
    
    args = parser.parse_args()
    
    runner = TestRunner()
    
    if args.imports:
        return 0 if runner.check_imports() else 1
    elif args.websocket:
        return 0 if runner.run_websocket_tests() else 1
    elif args.coverage:
        return 0 if runner.run_coverage() else 1
    elif args.quick:
        return quick_test()
    else:
        return runner.run_all()

if __name__ == "__main__":
    sys.exit(main())
