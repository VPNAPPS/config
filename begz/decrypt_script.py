#!/usr/bin/env python3
"""
Python script to fetch and decrypt configuration data
Uses .env file for API_URL and DECRYPT_KEY
"""

import os
import requests
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from dotenv import load_dotenv
from v2ray2json import generateConfig

# Load environment variables from .env file
load_dotenv()

def base64_decode_safe(data):
    """Safely decode base64 data with proper padding"""
    # Add padding if needed
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    
    # Handle URL-safe base64
    data = data.replace('-', '+').replace('_', '/')
    
    return base64.b64decode(data)

def decrypt_chacha20(encrypted_data, key_string):
    """
    Decrypt ChaCha20-Poly1305 encrypted data
    
    Args:
        encrypted_data: dict with 'ciphertext', 'nonce', 'tag'
        key_string: the encryption key as string
    
    Returns:
        decrypted string data
    """
    try:
        # Decode the components
        ciphertext = base64_decode_safe(encrypted_data['ciphertext'])
        nonce = base64_decode_safe(encrypted_data['nonce'])
        tag = base64_decode_safe(encrypted_data['tag'])
        
        # Prepare the key - might need derivation or direct use
        if isinstance(key_string, str):
            # Try different key derivation methods
            try:
                # Method 1: Direct base64 decode of key
                key = base64_decode_safe(key_string)
                if len(key) != 32:
                    raise ValueError("Key length not 32 bytes")
            except:
                # Method 2: Use key string directly as bytes and pad/truncate to 32 bytes
                key_bytes = key_string.encode('utf-8')
                if len(key_bytes) < 32:
                    key = key_bytes + b'\x00' * (32 - len(key_bytes))
                else:
                    key = key_bytes[:32]
        else:
            key = key_string
        
        # Ensure nonce is 12 bytes for ChaCha20
        if len(nonce) != 12:
            if len(nonce) > 12:
                nonce = nonce[:12]
            else:
                nonce = nonce + b'\x00' * (12 - len(nonce))
        
        # Combine ciphertext and tag
        ciphertext_with_tag = ciphertext + tag
        
        # Initialize ChaCha20Poly1305
        cipher = ChaCha20Poly1305(key)
        
        # Decrypt
        decrypted = cipher.decrypt(nonce, ciphertext_with_tag, None)
        
        return decrypted.decode('utf-8')
        
    except Exception as e:
        return f'Error during decryption: {str(e)}'

def fetch_and_decrypt():
    """
    Fetch data from API and decrypt it using environment variables
    
    Returns:
        Decrypted data as string
    """
    try:
        # Get URL and key from environment variables
        api_url = os.getenv('API_URL')
        decrypt_key = os.getenv('DECRYPT_KEY')
        
        if not api_url:
            return "Error: API_URL environment variable not set"
        
        if not decrypt_key:
            return "Error: DECRYPT_KEY environment variable not set"
        
        # Construct full URL with key
        full_url = f"{api_url}/{decrypt_key}"
        
        print(f"Fetching data from API...")
        
        # Make request
        response = requests.get(full_url, timeout=30)
        response.raise_for_status()
        
        # Parse JSON response
        data = response.json()
        
        if not data.get('status', False):
            return "API returned status: false"
        
        # Extract encryption components
        secure_data = data['data']['secure']
        x1 = data['data']['x1']  # nonce
        x2 = data['data']['x2']  # tag
        
        print(f"Extracted components:")
        print(f"- Secure data length: {len(secure_data)}")
        print(f"- Nonce (x1): {x1}")
        print(f"- Tag (x2): {x2}")
        
        # Prepare encrypted data dict
        encrypted_data = {
            'ciphertext': secure_data,
            'nonce': x1,
            'tag': x2
        }
        
        # Decrypt
        decrypted_result = decrypt_chacha20(encrypted_data, decrypt_key)
        
        return decrypted_result
        
    except requests.RequestException as e:
        return f"Request error: {str(e)}"
    except json.JSONDecodeError as e:
        return f"JSON decode error: {str(e)}"
    except KeyError as e:
        return f"Missing key in response: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"

def create_config_with_debug():
    print("=== Debug Info ===")
    print(f"Current directory: {os.getcwd()}")
    print(f"configs.txt exists: {os.path.exists('begz/configs.txt')}")
    print(f"template.json exists: {os.path.exists('template.json')}")
    print(f"Parent directory exists: {os.path.exists('..')}")
    print(f"Can write to parent: {os.access('..', os.W_OK)}")
    
    try:
        # Read configs
        with open('configs.txt', 'r', encoding='utf-8') as file:
            lines = file.readlines()
            print(f"Found {len(lines)} lines in configs.txt")
            
        proxies = []
        i = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue
            i += 1
            
            try:
                print(f"Processing line {i}: {line[:50]}...")
                json_config = generateConfig(line)
                config = json.loads(json_config)
                
                if "outbounds" not in config or len(config["outbounds"]) == 0:
                    print(f"Warning: No outbounds in config for line {i}")
                    continue
                    
                config["outbounds"][0]["tag"] = f"proxy{i}"
                proxies.append(config["outbounds"][0])
                print(f"Successfully processed line {i}")
                
            except Exception as e:
                print(f"Error processing line {i}: {e}")
                continue
        
        print(f"Total proxies created: {len(proxies)}")
        
        # Load template
        with open("template.json", "r") as f:
            template = json.loads(f.read())
        print("Template loaded successfully")
        
        # Modify template
        original_count = len(template.get("outbounds", []))
        template["outbounds"][:0] = proxies
        new_count = len(template.get("outbounds", []))
        print(f"Template outbounds: {original_count} -> {new_count}")
        
        # Write config
        config_path = os.path.abspath("config.json")
        print(f"Writing to: {config_path}")
        
        with open("config.json", "w", encoding='utf-8') as f:
            json.dump(template, f, indent=4, ensure_ascii=False)
        
        print("✓ config.json created successfully!")
        print(f"File size: {os.path.getsize('config.json')} bytes")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()

def main():
    """Main function"""
    print("Configuration Data Decryption Tool")
    print("=" * 50)
    
    # Debug: Check environment variables
    api_url = os.getenv('API_URL')
    decrypt_key = os.getenv('DECRYPT_KEY')
    
    print(f"Environment check:")
    print(f"- API_URL set: {'✅' if api_url else '❌'}")
    print(f"- DECRYPT_KEY set: {'✅' if decrypt_key else '❌'}")
    
    if api_url:
        print(f"- API_URL value: {api_url}")
    if decrypt_key:
        print(f"- DECRYPT_KEY length: {len(decrypt_key)} characters")
    
    # Fetch and decrypt data
    result = fetch_and_decrypt()
    
    print("\nDecryption completed.")
    print("-" * 30)
    
    # Write result to configs.txt
    try:
        with open('configs.txt', 'w', encoding='utf-8') as f:
            f.write(result)
        print("✅ Result saved to configs.txt")
        
        # Show first few lines if successful
        if not result.startswith('Error'):
            lines = result.split('\n')[:5]
            print("\nFirst few lines of decrypted data:")
            for line in lines:
                print(f"  {line}")
            if len(result.split('\n')) > 5:
                print("  ...")
        else:
            print(f"❌ Decryption failed: {result}")
        
        #Creating config.json
        create_config_with_debug()
    except Exception as e:
        print(f"❌ Error writing to file: {str(e)}")

if __name__ == "__main__":
    main()