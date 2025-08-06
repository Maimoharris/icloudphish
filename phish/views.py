# views.py
import os
import json
import hashlib
from datetime import datetime, timedelta
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import uuid

class TextFileAuth:
    """Enhanced text file-based authentication system with detailed login tracking"""
    
    def __init__(self):
        # Create a data directory if it doesn't exist
        self.data_dir = os.path.join(settings.BASE_DIR, 'data')
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        
        self.users_file = os.path.join(self.data_dir, 'users.txt')
        self.sessions_file = os.path.join(self.data_dir, 'sessions.txt')
        self.login_history_file = os.path.join(self.data_dir, 'login_history.txt')
        self.failed_attempts_file = os.path.join(self.data_dir, 'failed_attempts.txt')
        
        # Create files if they don't exist
        for file_path in [self.users_file, self.sessions_file, self.login_history_file, self.failed_attempts_file]:
            if not os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    f.write('')
    
    def hash_password(self, password):
        """Simple password hashing using SHA256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def get_client_info(self, request):
        """Extract client information from request"""
        # Get client IP
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR', 'Unknown')
        
        # Get user agent
        user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
        
        # Simple browser detection
        browser = 'Unknown'
        if 'Chrome' in user_agent:
            browser = 'Chrome'
        elif 'Firefox' in user_agent:
            browser = 'Firefox'
        elif 'Safari' in user_agent:
            browser = 'Safari'
        elif 'Edge' in user_agent:
            browser = 'Edge'
        
        # Simple OS detection
        os_name = 'Unknown'
        if 'Windows' in user_agent:
            os_name = 'Windows'
        elif 'Mac' in user_agent:
            os_name = 'macOS'
        elif 'Linux' in user_agent:
            os_name = 'Linux'
        elif 'Android' in user_agent:
            os_name = 'Android'
        elif 'iPhone' in user_agent:
            os_name = 'iOS'
        
        return {
            'ip_address': ip,
            'user_agent': user_agent,
            'browser': browser,
            'os': os_name
        }
    
    def log_login_attempt(self, email, success, request, failure_reason=None, attempted_password=None, attempted_pin=None):
        """Log detailed login attempt information including failed credentials"""
        client_info = self.get_client_info(request)
        
        login_data = {
            'login_id': str(uuid.uuid4()),
            'email': email,
            'success': success,
            'timestamp': datetime.now().isoformat(),
            'ip_address': client_info['ip_address'],
            'user_agent': client_info['user_agent'],
            'browser': client_info['browser'],
            'operating_system': client_info['os'],
            'failure_reason': failure_reason if not success else None,
            'attempted_password': attempted_password if not success else None,
            'attempted_pin': attempted_pin if not success else None,
            'session_duration': None  # Will be updated on logout
        }
        
        # Log to appropriate file
        if success:
            with open(self.login_history_file, 'a') as f:
                f.write(json.dumps(login_data) + '\n')
        else:
            with open(self.failed_attempts_file, 'a') as f:
                f.write(json.dumps(login_data) + '\n')
        
        return login_data['login_id']
    
    def register_user(self, email, password, pin, request):
        """Register a new user with registration tracking"""
        # Check if user already exists
        if self.get_user(email):
            return False, "User already exists"
        
        # Hash the password and PIN
        hashed_password = self.hash_password(password)
        hashed_pin = self.hash_password(pin)
        
        client_info = self.get_client_info(request)
        
        # Create user data
        user_data = {
            'user_id': str(uuid.uuid4()),
            'email': email,
            'password': hashed_password,
            'pin': hashed_pin,
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'total_logins': 0,
            'failed_attempts': 0,
            'registration_ip': client_info['ip_address'],
            'registration_browser': client_info['browser'],
            'registration_os': client_info['os'],
            'account_status': 'active'
        }
        
        # Append to users file
        with open(self.users_file, 'a') as f:
            f.write(json.dumps(user_data) + '\n')
        
        return True, "User registered successfully"
    
    def get_user(self, email):
        """Get user by email"""
        try:
            with open(self.users_file, 'r') as f:
                for line in f:
                    if line.strip():
                        user_data = json.loads(line.strip())
                        if user_data['email'] == email:
                            return user_data
        except FileNotFoundError:
            pass
        return None
    
    def authenticate(self, email, password, pin, request):
        """Authenticate user with detailed logging including failed credentials"""
        user = self.get_user(email)
        if not user:
            self.log_login_attempt(email, False, request, "User not found", password, pin)
            return False, "User not found"
        
        hashed_password = self.hash_password(password)
        hashed_pin = self.hash_password(pin)
        
        if user['password'] != hashed_password:
            self.log_login_attempt(email, False, request, "Invalid password", password, pin)
            self.increment_failed_attempts(email)
            return False, "Invalid password"
        
        if user['pin'] != hashed_pin:
            self.log_login_attempt(email, False, request, "Invalid PIN code", password, pin)
            self.increment_failed_attempts(email)
            return False, "Invalid PIN code"
        
        # Successful authentication - don't log credentials for successful attempts
        login_id = self.log_login_attempt(email, True, request)
        self.update_user_login_stats(email)
        
        return True, "Authentication successful", login_id
    
    def increment_failed_attempts(self, email):
        """Increment failed login attempts for a user"""
        users = []
        
        try:
            with open(self.users_file, 'r') as f:
                for line in f:
                    if line.strip():
                        user_data = json.loads(line.strip())
                        if user_data['email'] == email:
                            user_data['failed_attempts'] = user_data.get('failed_attempts', 0) + 1
                        users.append(user_data)
        except FileNotFoundError:
            return
        
        # Write back all users
        with open(self.users_file, 'w') as f:
            for user in users:
                f.write(json.dumps(user) + '\n')
    
    def update_user_login_stats(self, email):
        """Update user's login statistics"""
        users = []
        
        try:
            with open(self.users_file, 'r') as f:
                for line in f:
                    if line.strip():
                        user_data = json.loads(line.strip())
                        if user_data['email'] == email:
                            user_data['last_login'] = datetime.now().isoformat()
                            user_data['total_logins'] = user_data.get('total_logins', 0) + 1
                            user_data['failed_attempts'] = 0  # Reset failed attempts on successful login
                        users.append(user_data)
        except FileNotFoundError:
            return
        
        # Write back all users
        with open(self.users_file, 'w') as f:
            for user in users:
                f.write(json.dumps(user) + '\n')
    
    def create_session(self, email, login_id, request):
        """Create a detailed session with login tracking"""
        session_id = hashlib.md5(f"{email}{datetime.now()}{uuid.uuid4()}".encode()).hexdigest()
        client_info = self.get_client_info(request)
        
        session_data = {
            'session_id': session_id,
            'login_id': login_id,
            'email': email,
            'created_at': datetime.now().isoformat(),
            'last_activity': datetime.now().isoformat(),
            'ip_address': client_info['ip_address'],
            'browser': client_info['browser'],
            'os': client_info['os'],
            'is_active': True,
            'logout_time': None,
            'session_duration': None
        }
        
        with open(self.sessions_file, 'a') as f:
            f.write(json.dumps(session_data) + '\n')
        
        return session_id
    
    def update_session_activity(self, session_id):
        """Update last activity time for a session"""
        sessions = []
        
        try:
            with open(self.sessions_file, 'r') as f:
                for line in f:
                    if line.strip():
                        session_data = json.loads(line.strip())
                        if session_data['session_id'] == session_id and session_data['is_active']:
                            session_data['last_activity'] = datetime.now().isoformat()
                        sessions.append(session_data)
        except FileNotFoundError:
            return
        
        # Write back all sessions
        with open(self.sessions_file, 'w') as f:
            for session in sessions:
                f.write(json.dumps(session) + '\n')
    
    def end_session(self, session_id):
        """End a session and calculate duration"""
        sessions = []
        
        try:
            with open(self.sessions_file, 'r') as f:
                for line in f:
                    if line.strip():
                        session_data = json.loads(line.strip())
                        if session_data['session_id'] == session_id and session_data['is_active']:
                            # Calculate session duration
                            start_time = datetime.fromisoformat(session_data['created_at'])
                            end_time = datetime.now()
                            duration_seconds = (end_time - start_time).total_seconds()
                            
                            session_data['is_active'] = False
                            session_data['logout_time'] = end_time.isoformat()
                            session_data['session_duration'] = duration_seconds
                        sessions.append(session_data)
        except FileNotFoundError:
            return
        
        # Write back all sessions
        with open(self.sessions_file, 'w') as f:
            for session in sessions:
                f.write(json.dumps(session) + '\n')
    
    def get_session(self, session_id):
        """Get active session by ID"""
        try:
            with open(self.sessions_file, 'r') as f:
                for line in f:
                    if line.strip():
                        session_data = json.loads(line.strip())
                        if session_data['session_id'] == session_id and session_data['is_active']:
                            # Update last activity
                            self.update_session_activity(session_id)
                            return session_data
        except FileNotFoundError:
            pass
        return None
    
    def get_user_login_history(self, email, limit=10):
        """Get login history for a specific user"""
        history = []
        try:
            with open(self.login_history_file, 'r') as f:
                for line in f:
                    if line.strip():
                        login_data = json.loads(line.strip())
                        if login_data['email'] == email:
                            history.append(login_data)
        except FileNotFoundError:
            pass
        
        # Sort by timestamp (newest first) and limit results
        history.sort(key=lambda x: x['timestamp'], reverse=True)
        return history[:limit]
    
    def get_failed_attempts(self, email=None, limit=50):
        """Get failed login attempts"""
        attempts = []
        try:
            with open(self.failed_attempts_file, 'r') as f:
                for line in f:
                    if line.strip():
                        attempt_data = json.loads(line.strip())
                        if email is None or attempt_data['email'] == email:
                            attempts.append(attempt_data)
        except FileNotFoundError:
            pass
        
        # Sort by timestamp (newest first) and limit results
        attempts.sort(key=lambda x: x['timestamp'], reverse=True)
        return attempts[:limit]
    
    def get_active_sessions(self):
        """Get all active sessions"""
        active_sessions = []
        try:
            with open(self.sessions_file, 'r') as f:
                for line in f:
                    if line.strip():
                        session_data = json.loads(line.strip())
                        if session_data['is_active']:
                            active_sessions.append(session_data)
        except FileNotFoundError:
            pass
        
        return active_sessions
    
    def get_all_users(self):
        """Get all registered users with enhanced information"""
        users = []
        try:
            with open(self.users_file, 'r') as f:
                for line in f:
                    if line.strip():
                        user_data = json.loads(line.strip())
                        # Don't return sensitive data
                        safe_user = {
                            'user_id': user_data.get('user_id'),
                            'email': user_data['email'],
                            'created_at': user_data['created_at'],
                            'last_login': user_data.get('last_login'),
                            'total_logins': user_data.get('total_logins', 0),
                            'failed_attempts': user_data.get('failed_attempts', 0),
                            'registration_browser': user_data.get('registration_browser', 'Unknown'),
                            'registration_os': user_data.get('registration_os', 'Unknown'),
                            'account_status': user_data.get('account_status', 'active')
                        }
                        users.append(safe_user)
        except FileNotFoundError:
            pass
        return users
    
    def get_login_statistics(self):
        """Get overall login statistics"""
        total_logins = 0
        total_failed = 0
        unique_users = set()
        
        # Count successful logins
        try:
            with open(self.login_history_file, 'r') as f:
                for line in f:
                    if line.strip():
                        login_data = json.loads(line.strip())
                        total_logins += 1
                        unique_users.add(login_data['email'])
        except FileNotFoundError:
            pass
        
        # Count failed attempts
        try:
            with open(self.failed_attempts_file, 'r') as f:
                for line in f:
                    if line.strip():
                        total_failed += 1
        except FileNotFoundError:
            pass
        
        return {
            'total_successful_logins': total_logins,
            'total_failed_attempts': total_failed,
            'unique_active_users': len(unique_users),
            'success_rate': (total_logins / (total_logins + total_failed) * 100) if (total_logins + total_failed) > 0 else 0
        }

# Initialize the enhanced auth system
auth_system = TextFileAuth()

def login_view(request):
    """Handle login page and authentication with detailed logging"""
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        pin = request.POST.get('pin', '')
        remember = request.POST.get('remember')
        
        # Validate inputs
        if not all([email, password, pin]):
            messages.error(request, "All fields are required.")
            return render(request, 'login.html')
        
        if len(pin) != 6 or not pin.isdigit():
            messages.error(request, "PIN must be exactly 6 digits.")
            return render(request, 'login.html')
        
        # Authenticate user with detailed logging
        result = auth_system.authenticate(email, password, pin, request)
        
        if result[0]:  # Success
            success, message, login_id = result
            
            # Create session
            session_id = auth_system.create_session(email, login_id, request)
            
            # Store session in Django session
            request.session['user_email'] = email
            request.session['custom_session_id'] = session_id
            request.session['login_id'] = login_id
            
            if remember:
                request.session.set_expiry(30 * 24 * 60 * 60)  # 30 days
            else:
                request.session.set_expiry(0)  # Browser close
            
            messages.success(request, f"Welcome back, {email}!")
            return redirect('dashboard')
        else:
            success, message = result
            messages.error(request, message)
    
    return render(request, 'login.html')

def register_view(request):
    """Handle user registration with tracking"""
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        pin = request.POST.get('pin', '')
        
        # Validate inputs
        if not all([email, password, pin]):
            messages.error(request, "All fields are required.")
            return render(request, 'register.html')
        
        if len(pin) != 6 or not pin.isdigit():
            messages.error(request, "PIN must be exactly 6 digits.")
            return render(request, 'register.html')
        
        if len(password) < 6:
            messages.error(request, "Password must be at least 6 characters long.")
            return render(request, 'register.html')
        
        # Register user with tracking
        success, message = auth_system.register_user(email, password, pin, request)
        
        if success:
            messages.success(request, "Registration successful! You can now log in.")
            return redirect('login')
        else:
            messages.error(request, message)
    
    return render(request, 'register.html')

def dashboard_view(request):
    """Dashboard with user activity tracking"""
    # Check if user is authenticated
    if 'user_email' not in request.session:
        messages.error(request, "Please log in to access the dashboard.")
        return redirect('login')
    
    user_email = request.session['user_email']
    session_id = request.session.get('custom_session_id')
    
    # Update session activity
    if session_id:
        auth_system.update_session_activity(session_id)
    
    user_data = auth_system.get_user(user_email)
    login_history = auth_system.get_user_login_history(user_email, 5)
    
    context = {
        'user': user_data,
        'session_id': session_id,
        'recent_logins': login_history
    }
    
    return render(request, 'dashboard.html', context)

def logout_view(request):
    """Handle user logout with session tracking"""
    user_email = request.session.get('user_email')
    session_id = request.session.get('custom_session_id')
    
    # End the session
    if session_id:
        auth_system.end_session(session_id)
    
    # Clear Django session
    request.session.flush()
    
    if user_email:
        messages.success(request, f"Goodbye, {user_email}! You have been logged out.")
    
    return redirect('login')

def admin_users_view(request):
    """Enhanced admin view with detailed user information"""
    users = auth_system.get_all_users()
    active_sessions = auth_system.get_active_sessions()
    login_stats = auth_system.get_login_statistics()
    recent_failed_attempts = auth_system.get_failed_attempts(limit=10)
    
    context = {
        'users': users,
        'total_users': len(users),
        'active_sessions': len(active_sessions),
        'login_statistics': login_stats,
        'recent_failed_attempts': recent_failed_attempts,
        'sessions': active_sessions
    }
    
    return render(request, 'admin.html', context)

def admin_login_history_view(request):
    """View for detailed login history"""
    email_filter = request.GET.get('email', '')
    
    if email_filter:
        login_history = auth_system.get_user_login_history(email_filter, 100)
    else:
        # Get all login history (this could be large, consider pagination)
        login_history = []
        try:
            with open(auth_system.login_history_file, 'r') as f:
                for line in f:
                    if line.strip():
                        login_data = json.loads(line.strip())
                        login_history.append(login_data)
        except FileNotFoundError:
            pass
        
        login_history.sort(key=lambda x: x['timestamp'], reverse=True)
        login_history = login_history[:100]  # Limit to recent 100
    
    context = {
        'login_history': login_history,
        'email_filter': email_filter
    }
    
    return render(request, 'admin_login_history.html', context)

@csrf_exempt
def api_check_user(request):
    """API endpoint to check if user exists"""
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        user = auth_system.get_user(email)
        
        return JsonResponse({
            'exists': user is not None,
            'email': email
        })
    
    return JsonResponse({'error': 'POST method required'}, status=400)