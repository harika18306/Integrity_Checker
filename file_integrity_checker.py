import hashlib
import os

def calculate_hash(file_path, hash_algorithm):
   
    hash_algorithm = hash_algorithm.lower()
    try:
        hash_object = getattr(hashlib, hash_algorithm)()
    except AttributeError:
        raise ValueError(f"Invalid hash algorithm: {hash_algorithm}")
    
    try:
        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b""):
                hash_object.update(chunk)
        return hash_object.hexdigest()
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")
    except PermissionError:
        raise PermissionError(f"Permission denied: {file_path}")

def compare_hashes(file_path, expected_hash, hash_algorithm):
   
    actual_hash = calculate_hash(file_path, hash_algorithm)
    return actual_hash == expected_hash

def check_file_integrity(file_path):
    """
    Check basic file integrity attributes
    """
    try:
        file_size = os.path.getsize(file_path)
        last_modified = os.path.getmtime(file_path)
        is_readable = os.access(file_path, os.R_OK)
        return {
            "size": file_size,
            "last_modified": last_modified,
            "is_readable": is_readable
        }
    except OSError as e:
        return f"Error checking file: {str(e)}"

def main():
    file_path = input("Enter the file path: ")
    hash_algorithm = input("Enter the hash algorithm (e.g., sha256, md5): ").lower()
    expected_hash = input("Enter the expected hash value: ")

    # Get file integrity info
    integrity_info = check_file_integrity(file_path)
    print("\nFile Integrity Report:")
    print("-" * 50)
    print(f"File Path: {file_path}")
    print(f"File Size: {integrity_info['size']/1024:.2f} KB")
    print(f"Last Modified: {os.path.getmtime(file_path)}")
    print(f"File is Readable: {'Yes' if integrity_info['is_readable'] else 'No'}")
    
    actual_hash = calculate_hash(file_path, hash_algorithm)
    if compare_hashes(file_path, expected_hash, hash_algorithm):
        print("\nHash Verification:")
        print("-" * 50)
        print("✅ Hashes match. File integrity is verified.")
        print(f"Hash ({hash_algorithm}): {actual_hash}")
    else:
        print("\nHash Verification:")
        print("-" * 50)
        print("❌ Hashes do not match. File integrity is compromised!")
        print(f"Expected hash: {expected_hash}")
        print(f"Actual hash: {actual_hash}")

if __name__ == "__main__":
    main()
