# test_httpx_import.py
try:
    from lib.downloads import download_with_retry
    print("Successfully imported httpx!")
except ImportError as e:
    print(f"Failed to import httpx: {e}")
