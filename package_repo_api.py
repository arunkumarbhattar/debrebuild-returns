import json
from flask import Flask, request, jsonify
import subprocess
import os
import requests
from multiprocessing import Process

app = Flask(__name__)

REPO_PATH = "/home/arun/Desktop/other/package_repo"
LOCAL_REPO_API_URL = 'http://localhost:5000'
server_process = None  # Global variable to keep track of the server process


def query_local_repo(package_name, package_version=None):
    params = {'package_name': package_name}
    if package_version:
        params['package_version'] = package_version
    response = requests.get(f'{LOCAL_REPO_API_URL}/query_package', params=params)
    return response.json()


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"}), 200


def check_server_health():
    try:
        response = requests.get(f'{LOCAL_REPO_API_URL}/health')
        if response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException:
        return False


def add_package_to_local_repo(package_name, package_version, package_content):
    url = f'{LOCAL_REPO_API_URL}/add_package'
    data = {
        "package_name": package_name,
        "package_version": package_version,
        "package_content": package_content.hex()
    }
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, data=json.dumps(data), headers=headers, timeout=45)
    return response.status_code == 201


@app.route('/add_package', methods=['POST'])
def add_package():
    package_name = request.json.get('package_name')
    package_version = request.json.get('package_version')
    package_content = request.json.get('package_content')

    if not all([package_name, package_version, package_content]):
        return jsonify({"error": "Missing package data"}), 400

    package_file = f"{package_name}_{package_version}.deb"
    package_dir = os.path.join(REPO_PATH, "pool/main")
    os.makedirs(package_dir, exist_ok=True)
    package_path = os.path.join(package_dir, package_file)

    with open(package_path, 'wb') as f:
        f.write(bytes.fromhex(package_content))

    update_repo_metadata()
    return jsonify({"message": "Package added successfully"}), 201


def update_repo_metadata():
    pool_dir = os.path.join(REPO_PATH, 'pool/main')
    packages_file = os.path.join(REPO_PATH, 'dists/stable/main/binary-amd64/Packages')
    packages_gz_file = os.path.join(REPO_PATH, 'dists/stable/main/binary-amd64/Packages.gz')
    release_file = os.path.join(REPO_PATH, 'dists/stable/Release')

    os.makedirs(os.path.dirname(packages_file), exist_ok=True)
    with open(packages_file, 'w') as f:
        subprocess.run(['dpkg-scanpackages', pool_dir, '/dev/null'], stdout=f)
    with open(packages_gz_file, 'wb') as f:
        subprocess.run(['gzip', '-9c', packages_file], stdout=f)
    with open(release_file, 'w') as f:
        subprocess.run(['apt-ftparchive', 'release', os.path.join(REPO_PATH, 'dists/stable')], stdout=f)


def start_api_server():
    global server_process
    if server_process is None or not server_process.is_alive():
        server_process = Process(target=lambda: app.run(debug=True, host='0.0.0.0', port=5000, threaded=True))
        server_process.start()
        print("Server started as a new process.")
    else:
        print("Server is already running.")


if __name__ == '__main__':
    # Ensure the Flask server is running
    start_api_server()
