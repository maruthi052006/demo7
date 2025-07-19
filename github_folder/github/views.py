import os
import zipfile
import base64
import requests
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from .models import UserProfiles, ProjectUploads
from django.contrib.auth.decorators import login_required


def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        github_username = request.POST.get('github_username')
        github_token = request.POST.get('github_token')

        if not User.objects.filter(username=username).exists():
            user = User.objects.create_user(username=username, email=email, password=password)
            UserProfiles.objects.create(user=user, github_username=github_username, github_token=github_token)
            return redirect('login')
        else:
            return render(request, 'register.html', {'error': 'Username already exists'})
    return render(request, 'register.html')


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user:
            login(request, user)
            return redirect('upload')
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials'})
    return render(request, 'login.html')


def logout_view(request):
    logout(request)
    return redirect('login')


@login_required
def upload_view(request):
    if request.method == 'POST':
        repo_name = request.POST.get('repository_name', '').strip()
        zip_file = request.FILES.get('project_zip')

        if not repo_name or not zip_file:
            return render(request, 'upload.html', {'error': 'All fields are required'})

        # Replace spaces with underscores and convert to lowercase
        repo_name_clean = repo_name.replace(' ', '_').lower()

        # Validate repository name (only letters, numbers, underscores, hyphens allowed)
        if not all(c.isalnum() or c in ['-', '_'] for c in repo_name_clean):
            return render(request, 'upload.html', {'error': 'Repository name can only have letters, numbers, hyphens, or underscores.'})

        project = ProjectUploads.objects.create(
            user=request.user,
            repository_name=repo_name_clean,
            project_zip=zip_file
        )

        user_profile = UserProfiles.objects.get(user=request.user)
        upload_status = extract_and_upload(
            project.project_zip.path,
            user_profile.github_username,
            user_profile.github_token,
            project.repository_name
        )

        if upload_status == 'success':
            return redirect('success')
        else:
            return render(request, 'upload.html', {'error': upload_status})

    return render(request, 'upload.html')



@login_required
def success_view(request):
    return render(request, 'success.html')


def extract_and_upload(zip_path, github_username, github_token, repo_name):
    headers = {
        "Authorization": f"token {github_token}",
        "User-Agent": "MyDjangoApp"
    }

    # Create Repository
    repo_api = "https://api.github.com/user/repos"
    repo_data = {
        "name": repo_name,
        "auto_init": True,
        "private": False
    }

    try:
        response = requests.post(repo_api, headers=headers, json=repo_data, timeout=10)
        if response.status_code == 201:
            print("✅ Repository created successfully!")
        elif response.status_code == 422:
            print("⚠️ Repository already exists. Proceeding to upload files.")
        else:
            return f"❌ Failed to create repository: {response.status_code} - {response.text}"
    except Exception as e:
        return f"❌ GitHub API Error (Repo Creation): {e}"

    # Get Authenticated Username
    try:
        user_resp = requests.get("https://api.github.com/user", headers=headers, timeout=10)
        if user_resp.status_code == 200:
            actual_username = user_resp.json().get('login')
            print(f"✅ Authenticated GitHub Username: {actual_username}")
        else:
            return f"❌ Failed to fetch username: {user_resp.status_code} - {user_resp.text}"
    except Exception as e:
        return f"❌ Error fetching username: {e}"

    # Check Repo Root Access
    try:
        check_url = f"https://api.github.com/repos/{actual_username}/{repo_name}/contents"
        check_resp = requests.get(check_url, headers=headers, timeout=10)
        if check_resp.status_code != 200:
            return f"❌ Repo check failed: {check_resp.status_code} - {check_resp.text}"
        print("✅ Repo root is accessible. Uploading files...")
    except Exception as e:
        return f"❌ Error checking repo: {e}"

    # Extract & Upload Files
    try:
        extract_dir = os.path.splitext(zip_path)[0]
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)

        print(f"✅ Extracted ZIP to: {extract_dir}")
        any_upload_failed = False

        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if (
                    file.startswith('.') or
                    '__MACOSX' in root or
                    file.endswith('.DS_Store') or
                    file.endswith('.pyc') or
                    file.endswith('.pyo') or
                    '__pycache__' in root
                ):
                    print(f"⚠️ Skipping unwanted file: {file}")
                    continue

                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, extract_dir).replace("\\", "/")

                print(f"📁 Uploading file: {rel_path}")

                upload_result = upload_file_to_github(file_path, rel_path, actual_username, github_token, repo_name)
                if upload_result != 'success':
                    print(f"❌ Failed to upload {rel_path}: {upload_result}")
                    any_upload_failed = True
                else:
                    print(f"✅ Uploaded {rel_path} successfully")

        if any_upload_failed:
            return "⚠️ Some files failed to upload. Check logs for details."

    except Exception as e:
        return f"❌ Error processing ZIP: {e}"

    print("✅ All files uploaded successfully!")
    return 'success'


def upload_file_to_github(local_path, github_path, username, token, repo):
    try:
        with open(local_path, 'rb') as f:
            content = base64.b64encode(f.read()).decode('utf-8')

        url = f"https://api.github.com/repos/{username}/{repo}/contents/{github_path}"
        headers = {
            "Authorization": f"token {token}",
            "User-Agent": "MyDjangoApp"
        }
        data = {
            "message": f"Add {github_path}",
            "content": content
        }

        response = requests.put(url, headers=headers, json=data, timeout=10)
        print(f"📤 Uploading {github_path} — Status: {response.status_code}")

        if response.status_code in [200, 201]:
            return 'success'
        else:
            return f"{response.status_code} - {response.text}"

    except Exception as e:
        return f"❌ Upload Error: {e}"
