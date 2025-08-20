#!/usr/bin/env python3
"""
Example Python script for testing the secure execution endpoint.
This script demonstrates safe Python code execution in containers.
"""

import math
import random
from datetime import datetime

def calculate_fibonacci(n):
    """Calculate the nth Fibonacci number."""
    if n <= 1:
        return n
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b

def main():
    print("🚀 Starting secure Python execution test...")
    print(f"⏰ Current time: {datetime.now()}")
    
    # Test basic arithmetic
    print("\n📊 Basic arithmetic:")
    x = random.randint(1, 100)
    y = random.randint(1, 100)
    print(f"Random numbers: {x}, {y}")
    print(f"Sum: {x + y}")
    print(f"Product: {x * y}")
    print(f"Power: {x ** 2}")
    
    # Test mathematical functions
    print("\n🔢 Mathematical functions:")
    print(f"Square root of {x}: {math.sqrt(x):.2f}")
    print(f"Log base 10 of {x}: {math.log10(x):.2f}")
    print(f"Sine of {x} degrees: {math.sin(math.radians(x)):.4f}")
    
    # Test Fibonacci sequence
    print("\n🐰 Fibonacci sequence:")
    for i in range(10):
        fib = calculate_fibonacci(i)
        print(f"F({i}) = {fib}")
    
    # Test list operations
    print("\n📝 List operations:")
    numbers = [random.randint(1, 50) for _ in range(5)]
    print(f"Random list: {numbers}")
    print(f"Sorted: {sorted(numbers)}")
    print(f"Sum: {sum(numbers)}")
    print(f"Average: {sum(numbers) / len(numbers):.2f}")
    
    # Test string operations
    print("\n🔤 String operations:")
    message = "Hello from secure container execution!"
    print(f"Original: {message}")
    print(f"Uppercase: {message.upper()}")
    print(f"Length: {len(message)}")
    print(f"Words: {len(message.split())}")
    
    print("\n✅ Test completed successfully!")
    print("🎉 Python code executed securely in isolated container!")

if __name__ == "__main__":
    main()
