import os
import json
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import threading
import schedule
import re
import random
import string
import queue
import datetime
import hashlib
import secrets
import shutil
import hmac
import subprocess
from collections import deque
from functools import wraps, lru_cache
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, make_response, send_from_directory

# Create a session with connection pooling and retry logic
def create_http_session():
    """Create an optimized HTTP session with connection pooling and retries"""
    sess = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(
        pool_connections=10,
        pool_maxsize=20,
        max_retries=retry_strategy
    )
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    return sess

# Global HTTP session for reuse
http_session = create_http_session()

# Security imports
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False

try:
    from flask_wtf.csrf import CSRFProtect
    CSRF_AVAILABLE = True
except ImportError:
    CSRF_AVAILABLE = False

# Notifications
try:
    import apprise
    APPRISE_AVAILABLE = True
except ImportError:
    APPRISE_AVAILABLE = False

CONFIG_FILE = '/config/looter_config.json'
CACHE_FILE = '/config/local_cache.json'
AUTH_FILE = '/config/auth.json'
LICENSE_FILE = '/config/license.json'
ENCRYPTION_KEY_FILE = '/config/.encryption_key'
PARTIAL_DOWNLOADS_FILE = '/config/partial_downloads.json'

VERSION = "3.0.0"

# --- Encryption for API Keys at Rest ---

def _get_encryption_key():
    """Get or create machine-specific encryption key"""
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as f:
            return f.read()
    # Generate new key
    key = secrets.token_bytes(32)
    os.makedirs(os.path.dirname(ENCRYPTION_KEY_FILE), exist_ok=True)
    with open(ENCRYPTION_KEY_FILE, 'wb') as f:
        f.write(key)
    os.chmod(ENCRYPTION_KEY_FILE, 0o600)  # Restrict permissions
    return key

def encrypt_sensitive(plaintext):
    """Encrypt sensitive data (API keys) for storage"""
    if not plaintext:
        return ''
    try:
        key = _get_encryption_key()
        # Use AES-like XOR cipher with key stretching
        pt_bytes = plaintext.encode('utf-8')
        iv = secrets.token_bytes(16)
        # Derive working key using HMAC
        working_key = hmac.new(key, iv, hashlib.sha256).digest()
        # XOR encryption with key stream
        encrypted = bytearray()
        for i, byte in enumerate(pt_bytes):
            key_byte = working_key[i % len(working_key)]
            encrypted.append(byte ^ key_byte)
        # Return as base64: iv + encrypted
        import base64
        result = base64.b64encode(iv + bytes(encrypted)).decode('ascii')
        return f"ENC:{result}"
    except Exception as e:
        log(f"Encryption error: {e}")
        return plaintext  # Fallback to plaintext

def decrypt_sensitive(ciphertext):
    """Decrypt sensitive data"""
    if not ciphertext:
        return ''
    if not ciphertext.startswith('ENC:'):
        return ciphertext  # Not encrypted, return as-is (migration)
    try:
        import base64
        key = _get_encryption_key()
        # Decode from base64
        data = base64.b64decode(ciphertext[4:])
        iv = data[:16]
        encrypted = data[16:]
        # Derive working key
        working_key = hmac.new(key, iv, hashlib.sha256).digest()
        # XOR decryption
        decrypted = bytearray()
        for i, byte in enumerate(encrypted):
            key_byte = working_key[i % len(working_key)]
            decrypted.append(byte ^ key_byte)
        return decrypted.decode('utf-8')
    except Exception as e:
        log(f"Decryption error: {e}")
        return ''  # Return empty on error

def is_encrypted(value):
    """Check if a value is encrypted"""
    return value and value.startswith('ENC:')

def mask_key(key):
    """Mask an API key for display (show first 4 and last 4 chars)"""
    if not key or len(key) < 12:
        return '****'
    # Handle encrypted keys
    if key.startswith('ENC:'):
        return '🔒 ****-****'
    return f"{key[:4]}...{key[-4:]}"

app = Flask(__name__, static_folder='static')

# Security: Limit request body size (16MB max - enough for config but prevents abuse)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Session security settings
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JS access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 hours default

# Security headers middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # Content Security Policy - allow inline styles/scripts for the app, but restrict sources
    # Note: 'unsafe-inline' needed for onclick handlers and inline styles
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https: blob:; "
        "connect-src 'self' https://api.gumroad.com; "
        "frame-ancestors 'self'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    response.headers['Content-Security-Policy'] = csp
    
    # Prevent caching of sensitive pages
    if request.endpoint in ['login', 'settings', 'config_api']:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    return response

# Rate limiting (if available) - only for login, not general API
if LIMITER_AVAILABLE:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[],  # No default limits - only apply to login
        storage_uri="memory://"
    )
else:
    limiter = None

# CSRF Protection (if available)
if CSRF_AVAILABLE:
    csrf = CSRFProtect()
else:
    csrf = None

# --- Licensing System ---

LICENSE_TIERS = {
    'free': {
        'max_remote_servers': 2,
        'max_local_servers': 1,
        'max_sync_mappings': 1,
        'max_items_per_page': 100,
        'max_concurrent_downloads': 2,
        'show_ads': True,
        'notifications': False,
        'custom_themes': False,
        'scheduling': False,
        'arr_integration': False,
        'analytics': False,
        'transcoding': False,
        'api_access': False
    },
    'trial': {
        'max_remote_servers': 999,
        'max_local_servers': 999,
        'max_sync_mappings': 999,
        'max_items_per_page': 999,
        'max_concurrent_downloads': 10,
        'show_ads': False,
        'notifications': True,
        'custom_themes': True,
        'scheduling': True,
        'arr_integration': True,
        'analytics': True,
        'transcoding': True,
        'api_access': True
    },
    'pro': {
        'max_remote_servers': 999,
        'max_local_servers': 999,
        'max_sync_mappings': 999,
        'max_items_per_page': 999,
        'max_concurrent_downloads': 10,
        'show_ads': False,
        'notifications': True,
        'custom_themes': True,
        'scheduling': True,
        'arr_integration': True,
        'analytics': True,
        'transcoding': True,
        'api_access': True
    }
}

TRIAL_DURATION_DAYS = 14
GUMROAD_PRODUCT_ID = "5jxZ3dk7Mc_egZqQ67FCCw=="

def load_license():
    """Load license information"""
    if not os.path.exists(LICENSE_FILE):
        return {'tier': 'free', 'key': None, 'trial_started': None}
    try:
        with open(LICENSE_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {'tier': 'free', 'key': None, 'trial_started': None}

def save_license(data):
    """Save license information"""
    os.makedirs(os.path.dirname(LICENSE_FILE), exist_ok=True)
    with open(LICENSE_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def _verify_license_integrity(license_data):
    """Verify license data hasn't been tampered with"""
    tier = license_data.get('tier', 'free')
    
    if tier == 'pro':
        # Verify pro license has valid hash
        key_hash = license_data.get('key_hash')
        encrypted_key = license_data.get('key', '')
        if not key_hash or not encrypted_key:
            return False
        # Decrypt and verify hash matches
        try:
            decrypted = decrypt_sensitive(encrypted_key)
            if decrypted:
                computed_hash = hashlib.sha256(decrypted.encode()).hexdigest()[:16]
                return computed_hash == key_hash
        except:
            pass
        return False
    
    elif tier == 'trial':
        # Verify trial hash
        trial_started = license_data.get('trial_started')
        trial_hash = license_data.get('trial_hash')
        if not trial_started or not trial_hash:
            return False
        expected_hash = hashlib.sha256(
            (trial_started + 'jl_trial').encode()
        ).hexdigest()[:16]
        return trial_hash == expected_hash
    
    return True  # Free tier always valid

def get_license_tier():
    """Get current license tier with integrity and expiration check"""
    license_data = load_license()
    tier = license_data.get('tier', 'free')
    
    # Verify integrity (primary + backup for pro)
    if tier == 'pro':
        if not _verify_license_integrity(license_data):
            log("Primary license integrity check failed, checking backup...")
            # Try to restore from backup
            restore_result = restore_from_backup()
            if restore_result.get('success'):
                return 'pro'
            log("License integrity check failed, reverting to free")
            license_data['tier'] = 'free'
            save_license(license_data)
            return 'free'
        
        # Dual verification - check backup matches
        if not verify_dual_license():
            log("⚠️ License mismatch detected between primary and backup")
            # Don't immediately revoke, but log warning
    
    elif tier == 'trial':
        if not _verify_license_integrity(license_data):
            log("License integrity check failed, reverting to free")
            license_data['tier'] = 'free'
            save_license(license_data)
            return 'free'
    
    # Check if trial has expired
    if tier == 'trial':
        trial_started = license_data.get('trial_started')
        if trial_started:
            start_date = datetime.datetime.fromisoformat(trial_started)
            days_elapsed = (datetime.datetime.now() - start_date).days
            if days_elapsed >= TRIAL_DURATION_DAYS:
                # Trial expired, revert to free
                license_data['tier'] = 'free'
                save_license(license_data)
                return 'free'
    
    return tier

def get_trial_days_remaining():
    """Get number of days remaining in trial"""
    license_data = load_license()
    if license_data.get('tier') != 'trial':
        return 0
    trial_started = license_data.get('trial_started')
    if not trial_started:
        return 0
    start_date = datetime.datetime.fromisoformat(trial_started)
    days_elapsed = (datetime.datetime.now() - start_date).days
    return max(0, TRIAL_DURATION_DAYS - days_elapsed)

def get_tier_limits():
    """Get limits for current tier"""
    tier = get_license_tier()
    return LICENSE_TIERS.get(tier, LICENSE_TIERS['free'])

def is_pro():
    """Check if user has Pro license"""
    return get_license_tier() == 'pro'

def is_trial():
    """Check if user is in trial"""
    return get_license_tier() == 'trial'

def is_feature_available(feature):
    """Check if a feature is available in current tier"""
    limits = get_tier_limits()
    return limits.get(feature, False)

def get_feature_limit(limit_name):
    """Get a numeric limit for current tier"""
    limits = get_tier_limits()
    return limits.get(limit_name, 0)

def _compute_key_checksum(key):
    """Compute checksum for license key validation"""
    # Split key and compute weighted checksum
    parts = key.upper().replace('-', '')
    if len(parts) != 20:
        return 0
    total = 0
    for i, c in enumerate(parts):
        val = ord(c) - (48 if c.isdigit() else 55)  # 0-9 or A-Z
        total += val * (i + 1)
    return total % 97

def validate_license_key_format(key):
    """Validate license key format - accepts multiple Gumroad formats"""
    if not key:
        return False
    
    # Clean up the key - remove whitespace, normalize dashes
    key = key.strip().upper()
    # Replace various dash characters with standard hyphen
    key = key.replace('–', '-').replace('—', '-').replace('−', '-')
    # Remove any spaces
    key = key.replace(' ', '')
    
    if len(key) < 16:
        log(f"License key too short: {len(key)} chars")
        return False
    
    # Gumroad format 1: XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX (8-8-8-8)
    pattern1 = r'^[A-Z0-9]{8}-[A-Z0-9]{8}-[A-Z0-9]{8}-[A-Z0-9]{8}$'
    
    # Gumroad format 2: XXXXX-XXXXX-XXXXX-XXXXX (5-5-5-5)
    pattern2 = r'^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$'
    
    # Gumroad format 3: Any alphanumeric with dashes, 20+ chars
    pattern3 = r'^[A-Z0-9\-]{20,}$'
    
    if re.match(pattern1, key) or re.match(pattern2, key) or re.match(pattern3, key):
        return True
    
    log(f"License key format invalid: {key[:8]}...")
    return False

def _obfuscated_verify(k, pid):
    """Internal verification (obfuscated)"""
    try:
        # Build request dynamically to avoid simple string replacement
        ep = ''.join([chr(x) for x in [104,116,116,112,115,58,47,47,97,112,105,46,103,117,109,114,111,97,100,46,99,111,109,47,118,50,47,108,105,99,101,110,115,101,115,47,118,101,114,105,102,121]])
        r = requests.post(ep, data={'product_id': pid, 'license_key': k}, timeout=10)
        d = r.json()
        return d.get('success', False), d.get('purchase', {}).get('email'), d.get('message')
    except:
        return None, None, None  # Network error

def verify_license_key(key):
    """Verify license key with Gumroad API (with offline fallback)"""
    # Clean up the key
    key = key.strip().upper()
    key = key.replace('–', '-').replace('—', '-').replace('−', '-').replace(' ', '')
    
    if not validate_license_key_format(key):
        return {'valid': False, 'error': 'Invalid key format'}
    
    # Try online verification
    success, email, msg = _obfuscated_verify(key, GUMROAD_PRODUCT_ID)
    
    if success is True:
        return {'valid': True, 'email': email}
    elif success is False:
        return {'valid': False, 'error': msg or 'Invalid key'}
    else:
        # Offline fallback - trust format if checksum passes
        log("License verification offline, using format validation")
        return {'valid': True, 'offline': True}

def activate_license(key):
    """Activate a Pro license"""
    result = verify_license_key(key)
    if result.get('valid'):
        license_data = load_license()
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        
        # Store encrypted key
        license_data['tier'] = 'pro'
        license_data['key'] = encrypt_sensitive(key)
        license_data['key_hash'] = key_hash
        license_data['activated_at'] = datetime.datetime.now().isoformat()
        save_license(license_data)
        
        # Save backup to library folders
        save_backup_license(key, key_hash)
        
        return {'success': True}
    return {'success': False, 'error': result.get('error', 'Invalid key')}

def activate_trial():
    """Activate 14-day trial"""
    license_data = load_license()
    
    # Check if trial was already used
    if license_data.get('trial_started'):
        return {'success': False, 'error': 'Trial already used'}
    
    license_data['tier'] = 'trial'
    license_data['trial_started'] = datetime.datetime.now().isoformat()
    # Add integrity check
    license_data['trial_hash'] = hashlib.sha256(
        (license_data['trial_started'] + 'jl_trial').encode()
    ).hexdigest()[:16]
    save_license(license_data)
    return {'success': True, 'days': TRIAL_DURATION_DAYS}


# --- Backup License System ---
# Obscure folder/file names to avoid detection
_BKP_FOLDER = '.jlsys'  # Hidden folder
_BKP_FILE = 'metadata.db'  # Looks like a database file
_BKP_SALT = 'jl_bkp_v3_'

def _get_backup_paths():
    """Get all potential backup paths from library mappings"""
    config = load_config()
    paths = []
    
    # Check library mappings
    for mapping in config.get('mappings', []):
        local_path = mapping.get('local_path', '')
        if local_path and os.path.isdir(local_path):
            paths.append(local_path)
    
    # Check download base path
    base_path = config.get('download_path', '/downloads')
    if base_path and os.path.isdir(base_path):
        paths.append(base_path)
    
    return list(set(paths))  # Unique paths

def _encode_backup_data(key, key_hash):
    """Encode backup data with obfuscation"""
    # Format: base64(encrypted_key)|hash|timestamp_hash
    ts = datetime.datetime.now().strftime('%Y%m')  # Monthly rotation indicator
    ts_hash = hashlib.sha256((_BKP_SALT + ts).encode()).hexdigest()[:8]
    
    # XOR encrypt the key with a derived key
    derived = hashlib.sha256((_BKP_SALT + key_hash).encode()).digest()
    encrypted = ''.join(chr(ord(c) ^ derived[i % len(derived)]) for i, c in enumerate(key))
    encoded = base64.b64encode(encrypted.encode('latin-1')).decode()
    
    return f"{encoded}|{key_hash}|{ts_hash}"

def _decode_backup_data(data):
    """Decode backup data and verify"""
    try:
        parts = data.strip().split('|')
        if len(parts) != 3:
            return None, None
        
        encoded, key_hash, ts_hash = parts
        
        # Derive decryption key from hash
        derived = hashlib.sha256((_BKP_SALT + key_hash).encode()).digest()
        encrypted = base64.b64decode(encoded).decode('latin-1')
        decrypted = ''.join(chr(ord(c) ^ derived[i % len(derived)]) for i, c in enumerate(encrypted))
        
        # Verify the decrypted key matches the hash
        computed_hash = hashlib.sha256(decrypted.encode()).hexdigest()[:16]
        if computed_hash == key_hash:
            return decrypted, key_hash
        
        return None, None
    except Exception:
        return None, None

def save_backup_license(key, key_hash):
    """Save encrypted license backup to library folders"""
    paths = _get_backup_paths()
    if not paths:
        return False
    
    backup_data = _encode_backup_data(key, key_hash)
    saved_count = 0
    
    for path in paths:
        try:
            backup_dir = os.path.join(path, _BKP_FOLDER)
            backup_file = os.path.join(backup_dir, _BKP_FILE)
            
            # Create hidden directory
            os.makedirs(backup_dir, exist_ok=True)
            
            # Write backup file
            with open(backup_file, 'w') as f:
                f.write(backup_data)
            
            # Set restrictive permissions
            try:
                os.chmod(backup_dir, 0o700)
                os.chmod(backup_file, 0o600)
            except:
                pass
            
            saved_count += 1
        except Exception as e:
            log(f"Could not save backup to {path}: {e}")
    
    return saved_count > 0

def check_backup_license():
    """Check for valid backup license in library folders"""
    paths = _get_backup_paths()
    
    for path in paths:
        try:
            backup_file = os.path.join(path, _BKP_FOLDER, _BKP_FILE)
            if os.path.exists(backup_file):
                with open(backup_file, 'r') as f:
                    data = f.read()
                
                key, key_hash = _decode_backup_data(data)
                if key and key_hash:
                    # Verify with Gumroad
                    result = verify_license_key(key)
                    if result.get('valid'):
                        return {'found': True, 'key': key, 'hash': key_hash}
        except Exception:
            pass
    
    return {'found': False}

def restore_from_backup():
    """Attempt to restore license from backup"""
    backup = check_backup_license()
    if backup.get('found'):
        key = backup['key']
        key_hash = backup['hash']
        
        # Activate the license
        license_data = load_license()
        license_data['tier'] = 'pro'
        license_data['key'] = encrypt_sensitive(key)
        license_data['key_hash'] = key_hash
        license_data['activated_at'] = datetime.datetime.now().isoformat()
        license_data['restored_from_backup'] = True
        save_license(license_data)
        
        log("✅ License restored from backup")
        return {'success': True, 'message': 'License restored from backup'}
    
    return {'success': False, 'message': 'No valid backup found'}

def verify_dual_license():
    """Verify license exists in both primary and backup locations"""
    license_data = load_license()
    tier = license_data.get('tier', 'free')
    
    if tier != 'pro':
        return True  # Only check for pro licenses
    
    # Check primary license
    if not _verify_license_integrity(license_data):
        return False
    
    # Check backup license
    backup = check_backup_license()
    if not backup.get('found'):
        # Backup missing - could be new install or tampering
        # Try to recreate backup
        encrypted_key = license_data.get('key', '')
        key_hash = license_data.get('key_hash', '')
        if encrypted_key and key_hash:
            try:
                decrypted = decrypt_sensitive(encrypted_key)
                if decrypted:
                    save_backup_license(decrypted, key_hash)
            except:
                pass
        return True  # Allow if primary is valid
    
    # Both exist - verify they match
    primary_hash = license_data.get('key_hash', '')
    backup_hash = backup.get('hash', '')
    
    return primary_hash == backup_hash


# Thread-safe state management
task_queue = queue.Queue()
active_downloads = {}
pending_display = []
cancelled_tasks = set()
download_lock = threading.Lock()
worker_lock = threading.Lock()
is_paused = False
log_buffer = deque(maxlen=500)  # Ring buffer for performance
download_history = deque(maxlen=1000)  # Limited history
local_id_cache = set()
cache_timestamp = "Never"
scan_progress = {
    "running": False,
    "percent": 0,
    "current": 0,
    "total": 0,
    "status": "Idle"
}

# Config cache for performance
_config_cache = None
_config_mtime = 0

# Worker management
active_workers = 0
target_workers = 2
worker_shutdown = threading.Event()

# Download history persistence
HISTORY_FILE = '/config/download_history.json'

def save_download_history():
    """Save download history to file"""
    try:
        with download_lock:
            history_list = list(download_history)
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history_list, f)
    except Exception as e:
        log(f"Failed to save download history: {e}")

def load_download_history():
    """Load download history from file"""
    global download_history
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                history_list = json.load(f)
            with download_lock:
                download_history = deque(history_list, maxlen=1000)
            log(f"Loaded {len(download_history)} items from download history")
    except Exception as e:
        log(f"Failed to load download history: {e}")

# --- Translations ---
TRANSLATIONS = {
    'en': {
        'app_name': 'JellyLooter',
        'sign_in': 'Sign In',
        'sign_out': 'Sign Out',
        'username': 'Username',
        'password': 'Password',
        'remember_me': 'Remember me',
        'settings': 'Settings',
        'browse': 'Browse',
        'downloads': 'Downloads',
        'help': 'Help',
        'changelog': 'Changelog',
        'remote_servers': 'Remote Servers',
        'local_server': 'Local Server',
        'add_server': 'Add Server',
        'remove': 'Remove',
        'save': 'Save',
        'cancel': 'Cancel',
        'download': 'Download',
        'pause': 'Pause',
        'resume': 'Resume',
        'cancel_all': 'Cancel All',
        'speed_limit': 'Speed Limit',
        'max_downloads': 'Max Downloads',
        'no_servers': 'No servers configured',
        'select_server': 'Select Server',
        'select_destination': 'Select Destination',
        'items_selected': 'items selected',
        'download_complete': 'Download complete',
        'download_failed': 'Download failed',
        'connection_error': 'Connection error',
        'invalid_credentials': 'Invalid credentials',
        'sync': 'Sync',
        'rebuild_cache': 'Rebuild Cache',
        'cache_info': 'Cache Info',
        'last_scan': 'Last Scan',
        'items_cached': 'Items Cached',
        'general': 'General',
        'advanced': 'Advanced',
        'authentication': 'Authentication',
        'enable_auth': 'Enable Authentication',
        'auth_description': 'Require login to access JellyLooter',
        'language': 'Language',
        'items_per_page': 'Items Per Page',
        'view_mode': 'View Mode',
        'grid_view': 'Grid',
        'list_view': 'List',
        'download_order': 'Download Order',
        'order_library': 'Library Order',
        'order_show_complete': 'Complete Shows First',
        'order_season_round': 'Season Round Robin',
        'order_episode_round': 'Episode Round Robin',
        'order_alphabetical': 'Alphabetical',
        'order_random': 'Random',
        'confirmed_working': 'Confirmed working on Unraid 7.2.0',
        'support_project': 'Support the Project',
        'buy_coffee': 'Support on Ko-fi',
        'loading': 'Loading...',
        'error': 'Error',
        'success': 'Success',
        'warning': 'Warning',
        'free_space': 'Free Space',
        'total_space': 'Total Space',
        'refresh': 'Refresh',
        'back': 'Back',
        'home': 'Home',
        'page': 'Page',
        'of': 'of',
        'previous': 'Previous',
        'next': 'Next',
        'search': 'Search',
        'filter': 'Filter',
        'all': 'All',
        'movies': 'Movies',
        'shows': 'Shows',
        'exists_locally': 'Exists Locally',
        'queued': 'Queued',
        'downloading': 'Downloading',
        'completed': 'Completed',
        'failed': 'Failed',
        'paused': 'Paused',
        'starting': 'Starting',
        'remote_browser': 'Remote Browser',
        'select_all': 'Select All',
        'deselect_all': 'Deselect All',
        'download_selected': 'Download Selected',
        'clear': 'Clear',
        'filter_items': '🔍 Filter items...',
        'activity_log': 'Activity Log',
        'history': 'History',
        'download_queue': 'Download Queue',
        'active': 'Active',
        'pending': 'Pending',
        'cached': 'Cached',
        'appearance': 'Appearance',
        'dark_theme': 'Dark Theme',
        'library_mappings': 'Library Mappings',
        'add_mapping': 'Add Mapping',
        'save_settings': 'Save Settings',
        'test_connection': 'Test Connection',
        'connection_successful': 'Connection successful',
        'no_mappings': 'No Mappings',
        'no_mappings_desc': 'Create a mapping to automatically sync content from remote libraries.',
        'sync_now': 'Sync Now',
        'auto_sync': 'Auto-Sync',
        'configuration': 'Configuration',
        'theme_hint': 'Switch between dark and light themes',
        'language_hint': 'Interface language (page will refresh)',
        'add_remote_server': 'Add Remote Server',
        'duplicate_detection': 'Duplicate Detection',
        'no_local_server': 'No local server configured. Add one to detect existing content.',
        'configure_local': 'Configure Local Server',
        'advanced_settings': 'Advanced Settings',
        'speed_limit_hint': 'Set to 0 for unlimited speed',
        'sync_time': 'Sync Time',
        'connection_timeout': 'Connection Timeout (s)',
        'chunk_size': 'Chunk Size (KB)',
        'confirm_downloads': 'Confirm before downloading',
        'show_notifications': 'Show notifications',
        'select_server': 'Select Server...',
        'no_active_downloads': 'No active downloads',
        'last_scan': 'Last Scan',
        'scanning': 'Scanning local library...',
        'select_a_server': 'Select a Server',
        'select_server_desc': 'Choose a remote server from the dropdown to browse its library.',
        # Changelog translations
        'support_btn': 'Support',
        'back': 'Back',
        'enjoying_jellylooter': 'Enjoying JellyLooter?',
        'support_message': 'If this project saves you time, consider supporting on Ko-fi!',
        'december': 'December',
        'latest': 'Latest',
        'fix': 'Fix',
        'new': 'New',
        'improve': 'Improve',
        'ch_mobile_view': 'Mobile view now works correctly with hamburger menu',
        'ch_download_error': 'Fixed download errors with username/password auth',
        'ch_poster_aspect': 'Fixed poster image aspect ratio',
        'ch_language_selector': 'Language selector in settings with full UI translations',
        'ch_title_downloads': 'Download count shown in browser tab title',
        'ch_select_all': 'Select All / Deselect All button for bulk selection',
        'ch_filter': 'Filter/search box to find items in current view',
        'ch_history': 'Download history panel with timestamps',
        'ch_eta': 'Estimated time remaining on active downloads',
        'ch_quick_paths': 'Quick path selection from library mappings when downloading',
        'ch_auth_optional': 'Authentication now optional (off by default)',
        'ch_tooltip': 'Tooltip z-index fixed',
        'ch_pagination': 'All items now display with server-side pagination',
        'ch_responsive': 'Mobile-friendly responsive design',
        'ch_grid_list': 'Grid/List view toggle',
        'ch_items_page': 'Pagination with configurable items per page',
        'ch_queue_order': 'Download queue ordering options',
        'ch_multilang': 'Multi-language support (English, Spanish, German)',
        'ch_syntax': 'Python syntax errors fixed',
        'ch_favicon': 'Added favicon',
        'ch_kofi': 'Ko-fi support links',
        'ch_userpw': 'Username/password authentication support',
        'ch_queue_visible': 'Download queue visibility improvements',
        'ch_ux': 'User experience improvements',
        # Help translations
        'help_support': 'Help & Support',
        'support_jellylooter': 'Support JellyLooter',
        'verified': 'VERIFIED',
        'confirmed_working': 'Confirmed working on',
        'quick_tips': 'Quick Tips',
        'tip_multiselect': 'Multi-Select Items',
        'tip_multiselect_desc': 'Hold Ctrl/Cmd and click to select multiple items, or just click non-folder items to toggle selection.',
        'tip_speed': 'Speed Limit Updates Live',
        'tip_speed_desc': 'Change speed limit in settings and it applies to active downloads within 10 seconds.',
        'tip_order': 'Download Order',
        'tip_order_desc': 'Choose how items are queued: complete shows first, round-robin by season/episode, or alphabetically.',
        'tip_mappings': 'Library Mappings',
        'tip_mappings_desc': 'Set up mappings to sync entire libraries automatically. Maps remote libraries to local folders.',
        'tip_language': 'Change Language',
        'tip_language_desc': 'Go to Settings > Appearance > Language to switch between English, Spanish, and German.',
        'troubleshooting': 'Troubleshooting',
        'issue_auth': 'Authentication Issues',
        'issue_auth_desc': 'If using username/password auth, try deleting and re-adding the server. The user_id must be stored correctly.',
        'issue_slow': 'Slow Downloads',
        'issue_slow_desc': 'Check your speed limit setting. Set to 0 for unlimited. Also check network connection to remote server.',
        'issue_error': 'Download Errors',
        'issue_error_desc': 'Check the Activity Log for details. Common issues: disk full, permissions, network timeout.',
        'no_remote_servers': 'No remote servers configured yet.',
        'confirm_remove_local': 'Remove local server?',
        'local_server_removed': 'Local server removed',
        'unknown': 'Unknown',
        'library': 'Library',
        'server_name': 'Server Name',
        'server_url': 'Server URL',
        'auth_method': 'Authentication Method',
        'api_key': 'API Key',
        'username_password': 'Username/Password',
        'test_before_adding': '⚠️ Test the connection before adding the server',
        'cancel': 'Cancel',
        'add_server': 'Add Server',
        'save_and_scan': 'Save & Scan',
        'select_download_location': 'Select Download Location',
        'or_browse': 'Or browse to a folder:',
        'download_here': 'Download Here',
        # v3.0.0 new translations
        'show_ratings': 'Show ratings on posters',
        'show_quality': 'Show quality badges (4K, HDR, etc)',
        'download_subtitles': 'Download subtitles automatically',
        'subtitle_languages': 'Subtitle Languages (ISO codes)',
        'subtitle_hint': 'Comma-separated language codes. Use "all" to download all available subtitles.',
        'security_settings': 'Security Settings',
        'enable_auth': 'Enable Authentication',
        'auth_hint': 'Require login to access JellyLooter',
        'session_timeout': 'Session Timeout (minutes)',
        'trust_proxy': 'Trust X-Forwarded headers',
        'trust_proxy_hint': 'Enable if using a reverse proxy (Nginx, Traefik, etc.) to get correct client IPs',
        'trusted_proxies': 'Trusted Proxy IPs',
        'trusted_proxies_hint': 'Comma-separated list of IP ranges allowed to set X-Forwarded headers',
        'save_security': 'Save Security Settings',
        'pro_features': 'Pro Features',
        'unlock_pro': 'Unlock Pro Features',
        'enter_license': 'Enter License Key',
        'go_pro': 'Go Pro',
        'trial_days': 'days left in trial',
        'thank_you_pro': 'Thank you for supporting JellyLooter!',
        'notifications': 'Notifications',
        'notification_urls': 'Notification URLs (Apprise)',
        'notification_hint': 'One URL per line. Supports Discord, Telegram, Email, and 80+ services.',
        'notify_complete': 'Notify on download complete',
        'notify_error': 'Notify on download error',
        'transcoding': 'Transcoding',
        'enable_transcoding': 'Enable transcoding',
        'transcode_preset': 'Preset',
        'encoder': 'Encoder',
        'scheduling': 'Scheduling',
        'enable_scheduling': 'Enable download scheduling',
        'schedule_start': 'Start time',
        'schedule_end': 'End time',
        'bandwidth_scheduling': 'Bandwidth Scheduling',
        'day_limit': 'Day limit (KB/s)',
        'night_limit': 'Night limit (KB/s)',
        'arr_integration': '*arr Integration',
        'arr_hint': 'Connect Sonarr/Radarr for automatic folder naming based on your *arr library.',
        'custom_themes': 'Custom Themes',
        'theme': 'Theme',
        'primary_color': 'Primary Color',
        'accent_color': 'Accent Color',
        'background': 'Background',
        'card_background': 'Card Background',
        'input_background': 'Input Background',
        'border_color': 'Border Color',
        'apply_theme': 'Apply Custom Theme',
        'multiple_servers': 'Multiple Local Servers',
        'multiple_servers_hint': 'Connect multiple local Jellyfin/Emby servers for unified duplicate detection across your network.',
        'add_local_server': 'Add Local Server',
        'save_pro': 'Save Pro Settings',
        'collapse_panel': 'Collapse',
        'expand_panel': 'Expand',
        'move_up': 'Move Up',
        'move_down': 'Move Down',
        'reset_layout': 'Reset Layout',
        'backup_restore': 'Backup & Restore',
        'export_config': 'Export Config',
        'import_config': 'Import Config',
        'export_hint': 'Export saves settings (API keys masked). Import restores settings while preserving existing API keys.',
    },
    'es': {
        'app_name': 'JellyLooter',
        'sign_in': 'Iniciar Sesión',
        'sign_out': 'Cerrar Sesión',
        'username': 'Usuario',
        'password': 'Contraseña',
        'remember_me': 'Recordarme',
        'settings': 'Configuración',
        'browse': 'Explorar',
        'downloads': 'Descargas',
        'help': 'Ayuda',
        'changelog': 'Cambios',
        'remote_servers': 'Servidores Remotos',
        'local_server': 'Servidor Local',
        'add_server': 'Agregar Servidor',
        'remove': 'Eliminar',
        'save': 'Guardar',
        'cancel': 'Cancelar',
        'download': 'Descargar',
        'pause': 'Pausar',
        'resume': 'Reanudar',
        'cancel_all': 'Cancelar Todo',
        'speed_limit': 'Límite de Velocidad',
        'max_downloads': 'Descargas Máximas',
        'no_servers': 'No hay servidores configurados',
        'select_server': 'Seleccionar Servidor',
        'select_destination': 'Seleccionar Destino',
        'items_selected': 'elementos seleccionados',
        'download_complete': 'Descarga completa',
        'download_failed': 'Descarga fallida',
        'connection_error': 'Error de conexión',
        'invalid_credentials': 'Credenciales inválidas',
        'sync': 'Sincronizar',
        'rebuild_cache': 'Reconstruir Caché',
        'cache_info': 'Info de Caché',
        'last_scan': 'Último Escaneo',
        'items_cached': 'Elementos en Caché',
        'general': 'General',
        'advanced': 'Avanzado',
        'authentication': 'Autenticación',
        'enable_auth': 'Habilitar Autenticación',
        'auth_description': 'Requerir inicio de sesión para acceder',
        'language': 'Idioma',
        'items_per_page': 'Elementos por Página',
        'view_mode': 'Modo de Vista',
        'grid_view': 'Cuadrícula',
        'list_view': 'Lista',
        'download_order': 'Orden de Descarga',
        'order_library': 'Orden de Biblioteca',
        'order_show_complete': 'Series Completas Primero',
        'order_season_round': 'Rotación por Temporada',
        'order_episode_round': 'Rotación por Episodio',
        'order_alphabetical': 'Alfabético',
        'order_random': 'Aleatorio',
        'confirmed_working': 'Confirmado funcionando en Unraid 7.2.0',
        'support_project': 'Apoya el Proyecto',
        'buy_coffee': 'Apoyar en Ko-fi',
        'loading': 'Cargando...',
        'error': 'Error',
        'success': 'Éxito',
        'warning': 'Advertencia',
        'free_space': 'Espacio Libre',
        'total_space': 'Espacio Total',
        'refresh': 'Actualizar',
        'back': 'Atrás',
        'home': 'Inicio',
        'page': 'Página',
        'of': 'de',
        'previous': 'Anterior',
        'next': 'Siguiente',
        'search': 'Buscar',
        'filter': 'Filtrar',
        'all': 'Todo',
        'movies': 'Películas',
        'shows': 'Series',
        'exists_locally': 'Existe Localmente',
        'queued': 'En Cola',
        'downloading': 'Descargando',
        'completed': 'Completado',
        'failed': 'Fallido',
        'paused': 'Pausado',
        'starting': 'Iniciando',
        'remote_browser': 'Explorador Remoto',
        'select_all': 'Seleccionar Todo',
        'deselect_all': 'Deseleccionar Todo',
        'download_selected': 'Descargar Seleccionados',
        'clear': 'Limpiar',
        'filter_items': '🔍 Filtrar elementos...',
        'activity_log': 'Registro de Actividad',
        'history': 'Historial',
        'download_queue': 'Cola de Descargas',
        'active': 'Activo',
        'pending': 'Pendiente',
        'cached': 'En Caché',
        'appearance': 'Apariencia',
        'dark_theme': 'Tema Oscuro',
        'library_mappings': 'Mapeo de Bibliotecas',
        'add_mapping': 'Agregar Mapeo',
        'save_settings': 'Guardar Configuración',
        'test_connection': 'Probar Conexión',
        'connection_successful': 'Conexión exitosa',
        'no_mappings': 'Sin Mapeos',
        'no_mappings_desc': 'Crea un mapeo para sincronizar contenido automáticamente.',
        'sync_now': 'Sincronizar Ahora',
        'auto_sync': 'Auto-Sincronización',
        'configuration': 'Configuración',
        'theme_hint': 'Cambiar entre tema oscuro y claro',
        'language_hint': 'Idioma de la interfaz (la página se recargará)',
        'add_remote_server': 'Agregar Servidor Remoto',
        'duplicate_detection': 'Detección de Duplicados',
        'no_local_server': 'No hay servidor local configurado. Agrega uno para detectar contenido existente.',
        'configure_local': 'Configurar Servidor Local',
        'advanced_settings': 'Configuración Avanzada',
        'speed_limit_hint': 'Establecer en 0 para velocidad ilimitada',
        'sync_time': 'Hora de Sincronización',
        'connection_timeout': 'Tiempo de Espera (s)',
        'chunk_size': 'Tamaño de Bloque (KB)',
        'confirm_downloads': 'Confirmar antes de descargar',
        'show_notifications': 'Mostrar notificaciones',
        'select_server': 'Seleccionar Servidor...',
        'no_active_downloads': 'No hay descargas activas',
        'last_scan': 'Último Escaneo',
        'scanning': 'Escaneando biblioteca local...',
        'select_a_server': 'Seleccionar un Servidor',
        'select_server_desc': 'Elige un servidor remoto del menú desplegable para explorar su biblioteca.',
        # Changelog translations
        'support_btn': 'Apoyar',
        'back': 'Volver',
        'enjoying_jellylooter': '¿Te gusta JellyLooter?',
        'support_message': '¡Si este proyecto te ahorra tiempo, considera apoyar en Ko-fi!',
        'december': 'Diciembre',
        'latest': 'Última',
        'fix': 'Corr',
        'new': 'Nuevo',
        'improve': 'Mejor',
        'ch_mobile_view': 'Vista móvil ahora funciona correctamente con menú hamburguesa',
        'ch_download_error': 'Corregidos errores de descarga con autenticación usuario/contraseña',
        'ch_poster_aspect': 'Corregida proporción de imágenes de póster',
        'ch_language_selector': 'Selector de idioma en configuración con traducciones completas',
        'ch_title_downloads': 'Contador de descargas en la pestaña del navegador',
        'ch_select_all': 'Botón Seleccionar Todo / Deseleccionar Todo',
        'ch_filter': 'Cuadro de filtro/búsqueda para encontrar elementos',
        'ch_history': 'Panel de historial de descargas con marcas de tiempo',
        'ch_eta': 'Tiempo estimado restante en descargas activas',
        'ch_quick_paths': 'Selección rápida de ruta desde mapeos de biblioteca',
        'ch_auth_optional': 'Autenticación ahora opcional (desactivada por defecto)',
        'ch_tooltip': 'Corregido z-index de tooltip',
        'ch_pagination': 'Todos los elementos ahora se muestran con paginación',
        'ch_responsive': 'Diseño responsive para móviles',
        'ch_grid_list': 'Cambio entre vista de cuadrícula/lista',
        'ch_items_page': 'Paginación con elementos por página configurables',
        'ch_queue_order': 'Opciones de orden de cola de descarga',
        'ch_multilang': 'Soporte multiidioma (inglés, español, alemán)',
        'ch_syntax': 'Errores de sintaxis Python corregidos',
        'ch_favicon': 'Añadido favicon',
        'ch_kofi': 'Enlaces de soporte Ko-fi',
        'ch_userpw': 'Soporte de autenticación usuario/contraseña',
        'ch_queue_visible': 'Mejoras de visibilidad de cola de descarga',
        'ch_ux': 'Mejoras de experiencia de usuario',
        # Help translations
        'help_support': 'Ayuda y Soporte',
        'support_jellylooter': 'Apoyar JellyLooter',
        'verified': 'VERIFICADO',
        'confirmed_working': 'Confirmado funcionando en',
        'quick_tips': 'Consejos Rápidos',
        'tip_multiselect': 'Selección Múltiple',
        'tip_multiselect_desc': 'Mantén Ctrl/Cmd y haz clic para seleccionar múltiples elementos, o simplemente haz clic en elementos que no sean carpetas.',
        'tip_speed': 'Límite de Velocidad en Vivo',
        'tip_speed_desc': 'Cambia el límite de velocidad en configuración y se aplica a las descargas activas en 10 segundos.',
        'tip_order': 'Orden de Descarga',
        'tip_order_desc': 'Elige cómo se ordenan los elementos: series completas primero, round-robin por temporada/episodio, o alfabéticamente.',
        'tip_mappings': 'Mapeos de Biblioteca',
        'tip_mappings_desc': 'Configura mapeos para sincronizar bibliotecas enteras automáticamente.',
        'tip_language': 'Cambiar Idioma',
        'tip_language_desc': 'Ve a Configuración > Apariencia > Idioma para cambiar entre inglés, español y alemán.',
        'troubleshooting': 'Solución de Problemas',
        'issue_auth': 'Problemas de Autenticación',
        'issue_auth_desc': 'Si usas autenticación usuario/contraseña, intenta eliminar y volver a agregar el servidor.',
        'issue_slow': 'Descargas Lentas',
        'issue_slow_desc': 'Revisa tu límite de velocidad. Establece en 0 para ilimitado. También verifica la conexión de red.',
        'issue_error': 'Errores de Descarga',
        'issue_error_desc': 'Revisa el Registro de Actividad para detalles. Problemas comunes: disco lleno, permisos, tiempo de espera.',
        'no_remote_servers': 'No hay servidores remotos configurados.',
        'confirm_remove_local': '¿Eliminar servidor local?',
        'local_server_removed': 'Servidor local eliminado',
        'unknown': 'Desconocido',
        'library': 'Biblioteca',
        'server_name': 'Nombre del Servidor',
        'server_url': 'URL del Servidor',
        'auth_method': 'Método de Autenticación',
        'api_key': 'Clave API',
        'username_password': 'Usuario/Contraseña',
        'test_before_adding': '⚠️ Prueba la conexión antes de agregar el servidor',
        'cancel': 'Cancelar',
        'add_server': 'Agregar Servidor',
        'save_and_scan': 'Guardar y Escanear',
        'select_download_location': 'Seleccionar Ubicación de Descarga',
        'or_browse': 'O navegar a una carpeta:',
        'download_here': 'Descargar Aquí',
        # v3.0.0 new translations
        'show_ratings': 'Mostrar calificaciones en pósters',
        'show_quality': 'Mostrar insignias de calidad (4K, HDR, etc)',
        'download_subtitles': 'Descargar subtítulos automáticamente',
        'subtitle_languages': 'Idiomas de Subtítulos (códigos ISO)',
        'subtitle_hint': 'Códigos de idioma separados por comas. Usa "all" para descargar todos los subtítulos.',
        'security_settings': 'Configuración de Seguridad',
        'enable_auth': 'Habilitar Autenticación',
        'auth_hint': 'Requerir inicio de sesión para acceder a JellyLooter',
        'session_timeout': 'Tiempo de Sesión (minutos)',
        'trust_proxy': 'Confiar en cabeceras X-Forwarded',
        'trust_proxy_hint': 'Habilitar si usas proxy inverso (Nginx, Traefik, etc.)',
        'trusted_proxies': 'IPs de Proxy Confiables',
        'trusted_proxies_hint': 'Lista de rangos IP separados por comas',
        'save_security': 'Guardar Configuración de Seguridad',
        'pro_features': 'Funciones Pro',
        'unlock_pro': 'Desbloquear Funciones Pro',
        'enter_license': 'Ingresar Clave de Licencia',
        'go_pro': 'Obtener Pro',
        'trial_days': 'días de prueba restantes',
        'thank_you_pro': '¡Gracias por apoyar JellyLooter!',
        'notifications': 'Notificaciones',
        'notification_urls': 'URLs de Notificación (Apprise)',
        'notification_hint': 'Una URL por línea. Soporta Discord, Telegram, Email y más de 80 servicios.',
        'notify_complete': 'Notificar al completar descarga',
        'notify_error': 'Notificar en error de descarga',
        'transcoding': 'Transcodificación',
        'enable_transcoding': 'Habilitar transcodificación',
        'transcode_preset': 'Preajuste',
        'encoder': 'Codificador',
        'scheduling': 'Programación',
        'enable_scheduling': 'Habilitar programación de descargas',
        'schedule_start': 'Hora de inicio',
        'schedule_end': 'Hora de fin',
        'bandwidth_scheduling': 'Programación de Ancho de Banda',
        'day_limit': 'Límite diurno (KB/s)',
        'night_limit': 'Límite nocturno (KB/s)',
        'arr_integration': 'Integración *arr',
        'arr_hint': 'Conecta Sonarr/Radarr para nombrado automático de carpetas.',
        'custom_themes': 'Temas Personalizados',
        'theme': 'Tema',
        'primary_color': 'Color Primario',
        'accent_color': 'Color de Acento',
        'background': 'Fondo',
        'card_background': 'Fondo de Tarjetas',
        'input_background': 'Fondo de Entradas',
        'border_color': 'Color de Borde',
        'apply_theme': 'Aplicar Tema Personalizado',
        'multiple_servers': 'Múltiples Servidores Locales',
        'multiple_servers_hint': 'Conecta múltiples servidores locales para detección unificada de duplicados.',
        'add_local_server': 'Agregar Servidor Local',
        'save_pro': 'Guardar Configuración Pro',
        'collapse_panel': 'Colapsar',
        'expand_panel': 'Expandir',
        'move_up': 'Mover Arriba',
        'move_down': 'Mover Abajo',
        'reset_layout': 'Restablecer Diseño',
        'backup_restore': 'Copia de Seguridad',
        'export_config': 'Exportar Config',
        'import_config': 'Importar Config',
        'export_hint': 'Exportar guarda configuración (claves API ocultas). Importar restaura preservando claves existentes.',
    },
    'de': {
        'app_name': 'JellyLooter',
        'sign_in': 'Anmelden',
        'sign_out': 'Abmelden',
        'username': 'Benutzername',
        'password': 'Passwort',
        'remember_me': 'Angemeldet bleiben',
        'settings': 'Einstellungen',
        'browse': 'Durchsuchen',
        'downloads': 'Downloads',
        'help': 'Hilfe',
        'changelog': 'Änderungen',
        'remote_servers': 'Remote-Server',
        'local_server': 'Lokaler Server',
        'add_server': 'Server hinzufügen',
        'remove': 'Entfernen',
        'save': 'Speichern',
        'cancel': 'Abbrechen',
        'download': 'Herunterladen',
        'pause': 'Pause',
        'resume': 'Fortsetzen',
        'cancel_all': 'Alle abbrechen',
        'speed_limit': 'Geschwindigkeitslimit',
        'max_downloads': 'Max. Downloads',
        'no_servers': 'Keine Server konfiguriert',
        'select_server': 'Server auswählen',
        'select_destination': 'Ziel auswählen',
        'items_selected': 'Elemente ausgewählt',
        'download_complete': 'Download abgeschlossen',
        'download_failed': 'Download fehlgeschlagen',
        'connection_error': 'Verbindungsfehler',
        'invalid_credentials': 'Ungültige Anmeldedaten',
        'sync': 'Synchronisieren',
        'rebuild_cache': 'Cache neu aufbauen',
        'cache_info': 'Cache-Info',
        'last_scan': 'Letzter Scan',
        'items_cached': 'Zwischengespeicherte Elemente',
        'general': 'Allgemein',
        'advanced': 'Erweitert',
        'authentication': 'Authentifizierung',
        'enable_auth': 'Authentifizierung aktivieren',
        'auth_description': 'Anmeldung für Zugriff erforderlich',
        'language': 'Sprache',
        'items_per_page': 'Elemente pro Seite',
        'view_mode': 'Ansichtsmodus',
        'grid_view': 'Raster',
        'list_view': 'Liste',
        'download_order': 'Download-Reihenfolge',
        'order_library': 'Bibliotheksreihenfolge',
        'order_show_complete': 'Komplette Serien zuerst',
        'order_season_round': 'Staffel-Rotation',
        'order_episode_round': 'Episoden-Rotation',
        'order_alphabetical': 'Alphabetisch',
        'order_random': 'Zufällig',
        'confirmed_working': 'Bestätigt funktionierend auf Unraid 7.2.0',
        'support_project': 'Projekt unterstützen',
        'buy_coffee': 'Auf Ko-fi unterstützen',
        'loading': 'Laden...',
        'error': 'Fehler',
        'success': 'Erfolg',
        'warning': 'Warnung',
        'free_space': 'Freier Speicher',
        'total_space': 'Gesamtspeicher',
        'refresh': 'Aktualisieren',
        'back': 'Zurück',
        'home': 'Start',
        'page': 'Seite',
        'of': 'von',
        'previous': 'Zurück',
        'next': 'Weiter',
        'search': 'Suchen',
        'filter': 'Filter',
        'all': 'Alle',
        'movies': 'Filme',
        'shows': 'Serien',
        'exists_locally': 'Lokal vorhanden',
        'queued': 'In Warteschlange',
        'downloading': 'Wird heruntergeladen',
        'completed': 'Abgeschlossen',
        'failed': 'Fehlgeschlagen',
        'paused': 'Pausiert',
        'starting': 'Startet',
        'remote_browser': 'Remote-Browser',
        'select_all': 'Alle auswählen',
        'deselect_all': 'Alle abwählen',
        'download_selected': 'Ausgewählte herunterladen',
        'clear': 'Leeren',
        'filter_items': '🔍 Elemente filtern...',
        'activity_log': 'Aktivitätsprotokoll',
        'history': 'Verlauf',
        'download_queue': 'Download-Warteschlange',
        'active': 'Aktiv',
        'pending': 'Ausstehend',
        'cached': 'Gecached',
        'appearance': 'Darstellung',
        'dark_theme': 'Dunkles Design',
        'library_mappings': 'Bibliothekszuordnungen',
        'add_mapping': 'Zuordnung hinzufügen',
        'save_settings': 'Einstellungen speichern',
        'test_connection': 'Verbindung testen',
        'connection_successful': 'Verbindung erfolgreich',
        'no_mappings': 'Keine Zuordnungen',
        'no_mappings_desc': 'Erstellen Sie eine Zuordnung, um Inhalte automatisch zu synchronisieren.',
        'sync_now': 'Jetzt synchronisieren',
        'auto_sync': 'Auto-Sync',
        'configuration': 'Konfiguration',
        'theme_hint': 'Zwischen hellem und dunklem Design wechseln',
        'language_hint': 'Schnittstellensprache (Seite wird neu geladen)',
        'add_remote_server': 'Remote-Server hinzufügen',
        'duplicate_detection': 'Duplikaterkennung',
        'no_local_server': 'Kein lokaler Server konfiguriert. Fügen Sie einen hinzu, um vorhandene Inhalte zu erkennen.',
        'configure_local': 'Lokalen Server konfigurieren',
        'advanced_settings': 'Erweiterte Einstellungen',
        'speed_limit_hint': 'Auf 0 setzen für unbegrenzte Geschwindigkeit',
        'sync_time': 'Sync-Zeit',
        'connection_timeout': 'Verbindungs-Timeout (s)',
        'chunk_size': 'Blockgröße (KB)',
        'confirm_downloads': 'Vor dem Download bestätigen',
        'show_notifications': 'Benachrichtigungen anzeigen',
        'select_server': 'Server auswählen...',
        'no_active_downloads': 'Keine aktiven Downloads',
        'last_scan': 'Letzter Scan',
        'scanning': 'Lokale Bibliothek wird gescannt...',
        'select_a_server': 'Server auswählen',
        'select_server_desc': 'Wählen Sie einen Remote-Server aus der Dropdown-Liste, um seine Bibliothek zu durchsuchen.',
        # Changelog translations
        'support_btn': 'Unterstützen',
        'back': 'Zurück',
        'enjoying_jellylooter': 'Gefällt Ihnen JellyLooter?',
        'support_message': 'Wenn dieses Projekt Ihnen Zeit spart, unterstützen Sie es auf Ko-fi!',
        'december': 'Dezember',
        'latest': 'Neueste',
        'fix': 'Fix',
        'new': 'Neu',
        'improve': 'Besser',
        'ch_mobile_view': 'Mobile Ansicht funktioniert jetzt korrekt mit Hamburger-Menü',
        'ch_download_error': 'Download-Fehler mit Benutzername/Passwort-Auth behoben',
        'ch_poster_aspect': 'Poster-Bildverhältnis korrigiert',
        'ch_language_selector': 'Sprachauswahl in Einstellungen mit vollständigen Übersetzungen',
        'ch_title_downloads': 'Download-Zähler im Browser-Tab-Titel',
        'ch_select_all': 'Alle auswählen / Abwählen Schaltfläche',
        'ch_filter': 'Filter-/Suchfeld zum Finden von Elementen',
        'ch_history': 'Download-Verlauf mit Zeitstempeln',
        'ch_eta': 'Geschätzte Restzeit bei aktiven Downloads',
        'ch_quick_paths': 'Schnelle Pfadauswahl aus Bibliothekszuordnungen',
        'ch_auth_optional': 'Authentifizierung jetzt optional (standardmäßig deaktiviert)',
        'ch_tooltip': 'Tooltip z-index behoben',
        'ch_pagination': 'Alle Elemente werden jetzt mit Paginierung angezeigt',
        'ch_responsive': 'Mobilfreundliches responsives Design',
        'ch_grid_list': 'Raster-/Listenansicht-Umschalter',
        'ch_items_page': 'Paginierung mit konfigurierbaren Elementen pro Seite',
        'ch_queue_order': 'Download-Warteschlangen-Sortieroptionen',
        'ch_multilang': 'Mehrsprachige Unterstützung (Englisch, Spanisch, Deutsch)',
        'ch_syntax': 'Python-Syntaxfehler behoben',
        'ch_favicon': 'Favicon hinzugefügt',
        'ch_kofi': 'Ko-fi Support-Links',
        'ch_userpw': 'Benutzername/Passwort-Authentifizierung',
        'ch_queue_visible': 'Verbesserungen der Download-Warteschlangen-Sichtbarkeit',
        'ch_ux': 'Verbesserungen der Benutzererfahrung',
        # Help translations
        'help_support': 'Hilfe & Support',
        'support_jellylooter': 'JellyLooter unterstützen',
        'verified': 'VERIFIZIERT',
        'confirmed_working': 'Bestätigt funktionierend auf',
        'quick_tips': 'Schnelle Tipps',
        'tip_multiselect': 'Mehrfachauswahl',
        'tip_multiselect_desc': 'Halten Sie Strg/Cmd und klicken Sie, um mehrere Elemente auszuwählen.',
        'tip_speed': 'Geschwindigkeitslimit Live',
        'tip_speed_desc': 'Ändern Sie das Geschwindigkeitslimit in den Einstellungen und es wird innerhalb von 10 Sekunden angewendet.',
        'tip_order': 'Download-Reihenfolge',
        'tip_order_desc': 'Wählen Sie, wie Elemente eingereiht werden: komplette Serien zuerst, Round-Robin, oder alphabetisch.',
        'tip_mappings': 'Bibliothekszuordnungen',
        'tip_mappings_desc': 'Richten Sie Zuordnungen ein, um ganze Bibliotheken automatisch zu synchronisieren.',
        'tip_language': 'Sprache ändern',
        'tip_language_desc': 'Gehen Sie zu Einstellungen > Darstellung > Sprache, um zwischen Englisch, Spanisch und Deutsch zu wechseln.',
        'troubleshooting': 'Fehlerbehebung',
        'issue_auth': 'Authentifizierungsprobleme',
        'issue_auth_desc': 'Bei Benutzername/Passwort-Auth versuchen Sie, den Server zu löschen und neu hinzuzufügen.',
        'issue_slow': 'Langsame Downloads',
        'issue_slow_desc': 'Überprüfen Sie Ihr Geschwindigkeitslimit. Setzen Sie es auf 0 für unbegrenzt.',
        'issue_error': 'Download-Fehler',
        'issue_error_desc': 'Überprüfen Sie das Aktivitätsprotokoll für Details. Häufige Probleme: Festplatte voll, Berechtigungen, Timeout.',
        'no_remote_servers': 'Keine Remote-Server konfiguriert.',
        'confirm_remove_local': 'Lokalen Server entfernen?',
        'local_server_removed': 'Lokaler Server entfernt',
        'unknown': 'Unbekannt',
        'library': 'Bibliothek',
        'server_name': 'Servername',
        'server_url': 'Server-URL',
        'auth_method': 'Authentifizierungsmethode',
        'api_key': 'API-Schlüssel',
        'username_password': 'Benutzername/Passwort',
        'test_before_adding': '⚠️ Testen Sie die Verbindung bevor Sie den Server hinzufügen',
        'cancel': 'Abbrechen',
        'add_server': 'Server hinzufügen',
        'save_and_scan': 'Speichern & Scannen',
        'select_download_location': 'Download-Speicherort auswählen',
        'or_browse': 'Oder zu einem Ordner navigieren:',
        'download_here': 'Hier herunterladen',
        # v3.0.0 new translations
        'show_ratings': 'Bewertungen auf Postern anzeigen',
        'show_quality': 'Qualitätsabzeichen anzeigen (4K, HDR, etc)',
        'download_subtitles': 'Untertitel automatisch herunterladen',
        'subtitle_languages': 'Untertitelsprachen (ISO-Codes)',
        'subtitle_hint': 'Kommagetrennte Sprachcodes. Verwenden Sie "all" für alle verfügbaren Untertitel.',
        'security_settings': 'Sicherheitseinstellungen',
        'enable_auth': 'Authentifizierung aktivieren',
        'auth_hint': 'Anmeldung für Zugriff auf JellyLooter erforderlich',
        'session_timeout': 'Sitzungs-Timeout (Minuten)',
        'trust_proxy': 'X-Forwarded-Header vertrauen',
        'trust_proxy_hint': 'Aktivieren bei Verwendung eines Reverse-Proxys (Nginx, Traefik, etc.)',
        'trusted_proxies': 'Vertrauenswürdige Proxy-IPs',
        'trusted_proxies_hint': 'Kommagetrennte Liste von IP-Bereichen',
        'save_security': 'Sicherheitseinstellungen speichern',
        'pro_features': 'Pro-Funktionen',
        'unlock_pro': 'Pro-Funktionen freischalten',
        'enter_license': 'Lizenzschlüssel eingeben',
        'go_pro': 'Pro kaufen',
        'trial_days': 'Testtage verbleibend',
        'thank_you_pro': 'Vielen Dank für Ihre Unterstützung von JellyLooter!',
        'notifications': 'Benachrichtigungen',
        'notification_urls': 'Benachrichtigungs-URLs (Apprise)',
        'notification_hint': 'Eine URL pro Zeile. Unterstützt Discord, Telegram, E-Mail und 80+ Dienste.',
        'notify_complete': 'Bei Download-Abschluss benachrichtigen',
        'notify_error': 'Bei Download-Fehler benachrichtigen',
        'transcoding': 'Transkodierung',
        'enable_transcoding': 'Transkodierung aktivieren',
        'transcode_preset': 'Voreinstellung',
        'encoder': 'Encoder',
        'scheduling': 'Zeitplanung',
        'enable_scheduling': 'Download-Zeitplanung aktivieren',
        'schedule_start': 'Startzeit',
        'schedule_end': 'Endzeit',
        'bandwidth_scheduling': 'Bandbreiten-Zeitplanung',
        'day_limit': 'Tageslimit (KB/s)',
        'night_limit': 'Nachtlimit (KB/s)',
        'arr_integration': '*arr-Integration',
        'arr_hint': 'Verbinden Sie Sonarr/Radarr für automatische Ordnerbenennung.',
        'custom_themes': 'Benutzerdefinierte Designs',
        'theme': 'Design',
        'primary_color': 'Primärfarbe',
        'accent_color': 'Akzentfarbe',
        'background': 'Hintergrund',
        'card_background': 'Karten-Hintergrund',
        'input_background': 'Eingabe-Hintergrund',
        'border_color': 'Randfarbe',
        'apply_theme': 'Design anwenden',
        'multiple_servers': 'Mehrere lokale Server',
        'multiple_servers_hint': 'Verbinden Sie mehrere lokale Server für einheitliche Duplikaterkennung.',
        'add_local_server': 'Lokalen Server hinzufügen',
        'save_pro': 'Pro-Einstellungen speichern',
        'collapse_panel': 'Einklappen',
        'expand_panel': 'Ausklappen',
        'move_up': 'Nach oben',
        'move_down': 'Nach unten',
        'reset_layout': 'Layout zurücksetzen',
        'backup_restore': 'Sichern & Wiederherstellen',
        'export_config': 'Config exportieren',
        'import_config': 'Config importieren',
        'export_hint': 'Export speichert Einstellungen (API-Schlüssel maskiert). Import stellt wieder her und behält vorhandene Schlüssel.',
    }
}


def get_translation(key, lang='en'):
    """Get translation for a key"""
    return TRANSLATIONS.get(lang, TRANSLATIONS['en']).get(key, TRANSLATIONS['en'].get(key, key))


@lru_cache(maxsize=8)
def get_all_translations(lang='en'):
    """Get all translations for a language (cached)"""
    return TRANSLATIONS.get(lang, TRANSLATIONS['en'])


# --- Authentication Helpers ---

def init_secret_key():
    """Initialize or load secret key for Flask sessions"""
    auth = load_auth()
    if auth and 'secret_key' in auth:
        return auth['secret_key']
    
    # Generate new secret key
    secret = secrets.token_hex(32)
    
    # Save it if auth is enabled
    if auth:
        auth['secret_key'] = secret
        save_auth(auth)
    
    return secret


def hash_password(password, salt=None):
    """Hash password using bcrypt (preferred) or SHA-256 fallback"""
    if BCRYPT_AVAILABLE:
        # Use bcrypt for secure password hashing
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    else:
        # Fallback to SHA-256 with salt
        if salt is None:
            salt = secrets.token_hex(16)
        hashed = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"sha256:{salt}:{hashed}"


def verify_password(password, stored_hash):
    """Verify password against stored hash"""
    try:
        if BCRYPT_AVAILABLE and stored_hash.startswith('$2'):
            # bcrypt hash
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
        elif stored_hash.startswith('sha256:'):
            # SHA-256 fallback format
            _, salt, hashed = stored_hash.split(':')
            return hash_password(password, salt) == stored_hash
        else:
            # Legacy format (old SHA-256)
            salt, hashed = stored_hash.split(':')
            check_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            return f"{salt}:{check_hash}" == stored_hash
    except (ValueError, Exception):
        return False


def load_auth():
    """Load authentication data"""
    if not os.path.exists(AUTH_FILE):
        return None
    try:
        with open(AUTH_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return None


def save_auth(auth_data):
    """Save authentication data"""
    os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
    with open(AUTH_FILE, 'w') as f:
        json.dump(auth_data, f, indent=4)


def is_auth_enabled():
    """Check if authentication is enabled"""
    cfg = load_config()
    return cfg.get('auth_enabled', False)


def is_setup_complete():
    """Check if initial setup has been completed (only matters if auth is enabled)"""
    if not is_auth_enabled():
        return True
    auth = load_auth()
    return auth is not None and 'users' in auth and len(auth['users']) > 0


def login_required(f):
    """Decorator to require authentication (only if auth is enabled)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If auth is disabled, allow access
        if not is_auth_enabled():
            return f(*args, **kwargs)
        
        if 'user' not in session:
            remember_token = request.cookies.get('remember_token')
            if remember_token:
                auth = load_auth()
                if auth and 'tokens' in auth:
                    for username, token in auth['tokens'].items():
                        if token == remember_token:
                            session['user'] = username
                            break
            
            if 'user' not in session:
                if request.path.startswith('/api/'):
                    return jsonify({"status": "error", "message": "Unauthorized"}), 401
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# --- Utility Functions ---

def log(msg):
    """Thread-safe logging with timestamp"""
    print(msg)
    with download_lock:
        log_buffer.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
        # deque handles max size automatically via maxlen


def clean_name(name):
    """Remove invalid filesystem characters"""
    return re.sub(r'[\\/*?:"<>|]', "", name)


def generate_id():
    """Generate random task ID"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))


def format_bytes(size):
    """Format bytes to human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def get_auth_header(token=None):
    """Generate Jellyfin/Emby auth header"""
    headers = {
        'X-Emby-Authorization': f'MediaBrowser Client="JellyLooter", Device="Unraid", DeviceId="JellyLooterId", Version="{VERSION}"'
    }
    if token:
        headers['X-Emby-Authorization'] += f', Token="{token}"'
        headers['X-Emby-Token'] = token
        headers['X-MediaBrowser-Token'] = token
        headers['Authorization'] = f'MediaBrowser Token="{token}"'
    return headers


def check_disk_space(path, required_bytes=0):
    """Check if there's enough disk space at the given path"""
    try:
        stat = shutil.disk_usage(path)
        free_bytes = stat.free
        
        if required_bytes > 0 and free_bytes < required_bytes:
            return False, f"Not enough space. Free: {format_bytes(free_bytes)}, Need: {format_bytes(required_bytes)}"
        
        if free_bytes < 1024 * 1024 * 1024:
            log(f"⚠️ Warning: Low disk space on {path} - {format_bytes(free_bytes)} free")
        
        return True, f"Free: {format_bytes(free_bytes)}"
    except Exception as e:
        return False, f"Cannot check disk space: {e}"


# --- Input Validation ---

def validate_url(url):
    """Validate URL format"""
    if not url:
        return False, "URL is required"
    
    url = url.strip()
    
    # Length check to prevent DoS
    if len(url) > 2048:
        return False, "URL is too long"
    
    # Check for valid protocol
    if not url.startswith(('http://', 'https://')):
        return False, "URL must start with http:// or https://"
    
    # Basic URL pattern check
    pattern = r'^https?://[a-zA-Z0-9\-\.]+(:[0-9]+)?(/.*)?$'
    if not re.match(pattern, url):
        return False, "Invalid URL format"
    
    # Block potentially dangerous URLs
    dangerous_patterns = ['localhost:22', '127.0.0.1:22', '/etc/', '/proc/', '..', 
                         'file://', 'ftp://', 'gopher://', 'javascript:']
    for dangerous in dangerous_patterns:
        if dangerous in url.lower():
            return False, "Invalid URL"
    
    return True, "Valid"


def validate_api_key(key):
    """Validate API key format"""
    if not key:
        return False, "API key is required"
    
    key = key.strip()
    
    # Jellyfin API keys are typically 32 hex characters
    if len(key) < 16:
        return False, "API key is too short"
    
    if len(key) > 128:
        return False, "API key is too long"
    
    # Check for valid characters
    if not re.match(r'^[a-zA-Z0-9\-_]+$', key):
        return False, "API key contains invalid characters"
    
    return True, "Valid"


def validate_server_input(url, api_key=None, username=None, password=None):
    """Validate server connection inputs"""
    url_valid, url_msg = validate_url(url)
    if not url_valid:
        return False, url_msg
    
    if api_key:
        key_valid, key_msg = validate_api_key(api_key)
        if not key_valid:
            return False, key_msg
    elif username and password:
        if len(username) < 1:
            return False, "Username is required"
        if len(password) < 1:
            return False, "Password is required"
    else:
        return False, "API key or username/password required"
    
    return True, "Valid"


# --- Partial Downloads Management (Pro Feature) ---

def load_partial_downloads():
    """Load partial downloads manifest"""
    try:
        if os.path.exists(PARTIAL_DOWNLOADS_FILE):
            with open(PARTIAL_DOWNLOADS_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}


def save_partial_downloads(partials):
    """Save partial downloads manifest"""
    try:
        with open(PARTIAL_DOWNLOADS_FILE, 'w') as f:
            json.dump(partials, f, indent=2)
    except Exception as e:
        log(f"Error saving partial downloads: {e}")


def save_partial_state(task_id, task, downloaded_bytes, total_bytes):
    """Save state for a partial download (Pro feature)"""
    if not is_feature_available('transcoding'):  # Use transcoding as proxy for Pro
        return
    
    partials = load_partial_downloads()
    partials[task_id] = {
        'task_id': task_id,
        'url': task.get('url', ''),
        'filepath': task.get('filepath', ''),
        'filename': os.path.basename(task.get('filepath', '')),
        'headers': task.get('headers', {}),
        'server': task.get('server', {}),
        'item_id': task.get('item_id', ''),
        'downloaded': downloaded_bytes,
        'total': total_bytes,
        'timestamp': datetime.datetime.now().isoformat(),
        'partial_file': task.get('filepath', '') + '.partial'
    }
    save_partial_downloads(partials)


def clear_partial_state(task_id):
    """Remove a partial download entry"""
    partials = load_partial_downloads()
    if task_id in partials:
        del partials[task_id]
        save_partial_downloads(partials)


def get_resumable_downloads():
    """Get list of downloads that can be resumed"""
    partials = load_partial_downloads()
    resumable = []
    
    for task_id, info in partials.items():
        partial_file = info.get('partial_file', '')
        if partial_file and os.path.exists(partial_file):
            actual_size = os.path.getsize(partial_file)
            resumable.append({
                'task_id': task_id,
                'filename': info.get('filename', 'Unknown'),
                'filepath': info.get('filepath', ''),
                'downloaded': actual_size,
                'downloaded_human': format_bytes(actual_size),
                'total': info.get('total', 0),
                'total_human': format_bytes(info.get('total', 0)),
                'percent': int((actual_size / info['total']) * 100) if info.get('total', 0) > 0 else 0,
                'timestamp': info.get('timestamp', ''),
                'age': _get_age_string(info.get('timestamp', ''))
            })
    
    return resumable


def _get_age_string(timestamp_str):
    """Get human-readable age from timestamp"""
    try:
        ts = datetime.datetime.fromisoformat(timestamp_str)
        age = datetime.datetime.now() - ts
        if age.days > 0:
            return f"{age.days}d ago"
        hours = age.seconds // 3600
        if hours > 0:
            return f"{hours}h ago"
        minutes = age.seconds // 60
        return f"{minutes}m ago"
    except:
        return "Unknown"


def cleanup_old_partials(max_age_days=7):
    """Remove partial downloads older than max_age_days"""
    partials = load_partial_downloads()
    now = datetime.datetime.now()
    removed = 0
    
    for task_id in list(partials.keys()):
        info = partials[task_id]
        try:
            ts = datetime.datetime.fromisoformat(info.get('timestamp', ''))
            if (now - ts).days > max_age_days:
                partial_file = info.get('partial_file', '')
                if partial_file and os.path.exists(partial_file):
                    os.remove(partial_file)
                del partials[task_id]
                removed += 1
        except:
            pass
    
    if removed > 0:
        save_partial_downloads(partials)
        log(f"Cleaned up {removed} old partial downloads")


# --- Config Management ---

def get_default_config():
    """Return default configuration"""
    return {
        "servers": [],
        "local_servers": [],  # New: multiple local servers (Pro)
        "mappings": [],
        "sync_time": "04:00",
        "speed_limit_kbs": 0,
        "local_server_url": "",
        "local_server_key": "",
        "auto_sync_enabled": True,
        "theme": "dark",
        "custom_theme": {},  # Pro: custom colors
        "max_concurrent_downloads": 2,
        "retry_attempts": 3,
        "advanced_mode": False,
        "show_notifications": True,
        "confirm_downloads": False,
        "auto_start_downloads": True,
        "log_retention_days": 7,
        "connection_timeout": 30,
        "chunk_size_kb": 64,
        "auth_enabled": False,
        "language": "en",
        "items_per_page": 50,
        "view_mode": "grid",
        "download_order": "library",
        # Display settings
        "show_ratings": True,
        "show_quality": True,
        # Subtitle settings (Free feature)
        "download_subtitles": True,
        "subtitle_languages": ["eng", "spa", "ger"],  # ISO 639-2 codes
        # New v3.0.0 settings
        "session_timeout_minutes": 30,
        "force_https": False,
        "trust_proxy_headers": False,
        "trusted_proxy_ips": "",
        # Scheduling (Pro)
        "download_schedule_enabled": False,
        "download_schedule_start": "02:00",
        "download_schedule_end": "06:00",
        "bandwidth_schedule_enabled": False,
        "bandwidth_day_limit_kbs": 1000,
        "bandwidth_night_limit_kbs": 0,
        "bandwidth_night_start": "22:00",
        "bandwidth_night_end": "06:00",
        # Notifications (Pro)
        "notification_urls": [],  # Apprise URLs
        "notify_on_complete": True,
        "notify_on_error": True,
        # *arr integration (Pro)
        "sonarr_url": "",
        "sonarr_api_key": "",
        "radarr_url": "",
        "radarr_api_key": "",
        "lidarr_url": "",
        "lidarr_api_key": "",
        # Transcoding (Pro)
        "transcode_enabled": False,
        "transcode_preset": "original",  # original, h265, mobile, custom
        "transcode_encoder": "software",  # software, nvenc, qsv, vaapi
        "transcode_custom_args": "",
        # Analytics (Pro)
        "track_analytics": True,
        # Last visited locations per server
        "last_locations": {},
        # What's new tracking
        "last_seen_items": {}
    }


def _decrypt_config_keys(config):
    """Decrypt all API keys in config"""
    result = config.copy()
    
    # Decrypt server API keys
    if 'servers' in result:
        decrypted_servers = []
        for server in result['servers']:
            s = server.copy()
            if s.get('key') and is_encrypted(s['key']):
                s['key'] = decrypt_sensitive(s['key'])
            decrypted_servers.append(s)
        result['servers'] = decrypted_servers
    
    # Decrypt local server key
    if result.get('local_server_key') and is_encrypted(result['local_server_key']):
        result['local_server_key'] = decrypt_sensitive(result['local_server_key'])
    
    # Decrypt local_servers list
    if 'local_servers' in result:
        decrypted_local = []
        for server in result['local_servers']:
            s = server.copy()
            if s.get('key') and is_encrypted(s['key']):
                s['key'] = decrypt_sensitive(s['key'])
            decrypted_local.append(s)
        result['local_servers'] = decrypted_local
    
    # Decrypt *arr API keys
    for arr_key in ['sonarr_api_key', 'radarr_api_key', 'lidarr_api_key']:
        if result.get(arr_key) and is_encrypted(result[arr_key]):
            result[arr_key] = decrypt_sensitive(result[arr_key])
    
    return result


def load_config(force_reload=False):
    """Load config with caching and automatic decryption"""
    global _config_cache, _config_mtime
    
    # Check if we can use cached config
    if not force_reload and _config_cache is not None:
        try:
            current_mtime = os.path.getmtime(CONFIG_FILE) if os.path.exists(CONFIG_FILE) else 0
            if current_mtime == _config_mtime:
                return _config_cache.copy()
        except Exception:
            pass
    
    default = get_default_config()
    if not os.path.exists(CONFIG_FILE):
        return default
    try:
        with open(CONFIG_FILE, 'r') as f:
            loaded = json.load(f)
            merged = {**default, **loaded}
            # Decrypt API keys for use
            _config_cache = _decrypt_config_keys(merged)
            _config_mtime = os.path.getmtime(CONFIG_FILE)
            return _config_cache.copy()
    except Exception:
        return default


def save_config(data):
    """Save config with encrypted API keys, invalidate cache, and refresh schedule"""
    global _config_cache, _config_mtime
    
    # Apply tier limits before saving
    limits = get_tier_limits()
    
    # Limit servers if over quota
    if len(data.get('servers', [])) > limits['max_remote_servers']:
        data['servers'] = data['servers'][:limits['max_remote_servers']]
        log(f"Server limit reached ({limits['max_remote_servers']} max for your tier)")
    
    if len(data.get('mappings', [])) > limits['max_sync_mappings']:
        data['mappings'] = data['mappings'][:limits['max_sync_mappings']]
        log(f"Mapping limit reached ({limits['max_sync_mappings']} max for your tier)")
    
    # Enforce max concurrent downloads limit
    max_downloads = data.get('max_concurrent_downloads', 2)
    max_allowed = limits.get('max_concurrent_downloads', 2)
    if max_downloads > max_allowed:
        data['max_concurrent_downloads'] = max_allowed
        log(f"Concurrent downloads limited to {max_allowed} for your tier")
    
    # Encrypt sensitive API keys before saving
    data_to_save = data.copy()
    
    # Encrypt server API keys
    if 'servers' in data_to_save:
        encrypted_servers = []
        for server in data_to_save['servers']:
            s = server.copy()
            if s.get('key') and not is_encrypted(s['key']):
                s['key'] = encrypt_sensitive(s['key'])
            encrypted_servers.append(s)
        data_to_save['servers'] = encrypted_servers
    
    # Encrypt local server key
    if data_to_save.get('local_server_key') and not is_encrypted(data_to_save['local_server_key']):
        data_to_save['local_server_key'] = encrypt_sensitive(data_to_save['local_server_key'])
    
    # Encrypt local_servers list
    if 'local_servers' in data_to_save:
        encrypted_local = []
        for server in data_to_save['local_servers']:
            s = server.copy()
            if s.get('key') and not is_encrypted(s['key']):
                s['key'] = encrypt_sensitive(s['key'])
            encrypted_local.append(s)
        data_to_save['local_servers'] = encrypted_local
    
    # Encrypt *arr API keys
    for arr_key in ['sonarr_api_key', 'radarr_api_key', 'lidarr_api_key']:
        if data_to_save.get(arr_key) and not is_encrypted(data_to_save[arr_key]):
            data_to_save[arr_key] = encrypt_sensitive(data_to_save[arr_key])
    
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data_to_save, f, indent=4)
    
    # Invalidate cache
    _config_cache = None
    _config_mtime = 0
    
    setup_schedule()
    adjust_workers(data.get('max_concurrent_downloads', 2))
    
    # Handle auth state changes
    if data.get('auth_enabled', False):
        auth = load_auth()
        if not auth:
            # Initialize auth file with secret key
            auth = {'secret_key': secrets.token_hex(32), 'users': {}, 'tokens': {}}
            save_auth(auth)
        elif 'secret_key' not in auth:
            auth['secret_key'] = secrets.token_hex(32)
            save_auth(auth)
        app.secret_key = auth['secret_key']


# --- Cache Management ---

def load_cache_from_disk():
    """Load local ID cache from disk"""
    global local_id_cache, cache_timestamp
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                data = json.load(f)
                local_id_cache = set(data.get('ids', []))
                cache_timestamp = data.get('timestamp', 'Unknown')
        except Exception:
            pass


def cache_worker():
    """Scan local server and build ID cache"""
    global local_id_cache, cache_timestamp, scan_progress
    
    cfg = load_config()
    url = cfg.get('local_server_url')
    key = cfg.get('local_server_key')
    
    if not url or not key:
        log("Scan Skipped: No Local Server configured")
        return
    
    if scan_progress['running']:
        log("Scan already in progress")
        return

    log("Starting Local Library Scan...")
    scan_progress = {
        "running": True,
        "percent": 0,
        "current": 0,
        "total": 0,
        "status": "Connecting..."
    }

    try:
        headers = get_auth_header(key)
        timeout = cfg.get('connection_timeout', 30)
        
        u_res = requests.get(f"{url}/Users", headers=headers, timeout=timeout)
        if not u_res.ok:
            raise Exception("Authentication Failed")
        uid = u_res.json()[0]['Id']

        params = {
            'Recursive': 'true',
            'IncludeItemTypes': 'Movie,Series',
            'Fields': 'ProviderIds',
            'Limit': 0
        }
        total_res = requests.get(
            f"{url}/Users/{uid}/Items",
            headers=headers,
            params=params
        ).json()
        total_count = total_res.get('TotalRecordCount', 0)

        scan_progress.update({
            'total': total_count,
            'status': f"Found {total_count} items. Fetching..."
        })

        new_cache = set()
        limit = 100
        offset = 0

        while offset < total_count:
            params.update({'StartIndex': offset, 'Limit': limit})
            items = requests.get(
                f"{url}/Users/{uid}/Items",
                headers=headers,
                params=params
            ).json().get('Items', [])

            for item in items:
                providers = item.get('ProviderIds', {})
                if 'Imdb' in providers:
                    new_cache.add(f"imdb_{providers['Imdb']}")
                if 'Tmdb' in providers:
                    new_cache.add(f"tmdb_{providers['Tmdb']}")
                if 'Tvdb' in providers:
                    new_cache.add(f"tvdb_{providers['Tvdb']}")

            offset += len(items)
            scan_progress.update({
                'current': offset,
                'percent': int((offset / total_count) * 100) if total_count > 0 else 0
            })

        local_id_cache = new_cache
        cache_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, 'w') as f:
            json.dump({
                'timestamp': cache_timestamp,
                'ids': list(local_id_cache)
            }, f)

        log(f"Scan Complete. Cached {len(local_id_cache)} provider IDs.")
        scan_progress = {
            "running": False,
            "percent": 100,
            "current": total_count,
            "total": total_count,
            "status": "Complete"
        }

    except Exception as e:
        log(f"Scan Failed: {e}")
        scan_progress = {
            "running": False,
            "percent": 0,
            "current": 0,
            "total": 0,
            "status": f"Error: {str(e)}"
        }


def get_existing_ids():
    """Get cached local IDs, loading from disk if needed"""
    if not local_id_cache:
        load_cache_from_disk()
    return local_id_cache


# --- Schedule Management ---

def setup_schedule():
    """Configure scheduled tasks"""
    schedule.clear()
    cfg = load_config()
    
    schedule.every().day.at("03:00").do(
        lambda: threading.Thread(target=cache_worker, daemon=True).start()
    )
    
    if cfg.get('auto_sync_enabled', True):
        sync_time = cfg.get('sync_time', "04:00")
        try:
            schedule.every().day.at(sync_time).do(sync_job)
            log(f"Scheduled: Cache rebuild 03:00, Sync {sync_time}")
        except Exception:
            schedule.every().day.at("04:00").do(sync_job)
            log("Scheduled: Cache rebuild 03:00, Sync 04:00 (default)")


def schedule_runner():
    """Background thread for running scheduled tasks"""
    while True:
        schedule.run_pending()
        time.sleep(60)


# --- Worker Management ---

def adjust_workers(new_count):
    """Dynamically adjust the number of worker threads, respecting tier limits"""
    global active_workers, target_workers
    
    # Enforce tier limit
    limits = get_tier_limits()
    max_allowed = limits.get('max_concurrent_downloads', 2)
    
    with worker_lock:
        # User can't exceed their tier limit
        target_workers = max(1, min(new_count, max_allowed))
        
        while active_workers < target_workers:
            threading.Thread(target=worker, daemon=True).start()
            active_workers += 1
            log(f"Started worker (total: {active_workers})")


def worker():
    """Download worker thread"""
    global active_workers, pending_display, stop_after_current
    
    while True:
        with worker_lock:
            if active_workers > target_workers:
                active_workers -= 1
                log(f"Stopped worker (total: {active_workers})")
                return
        
        # Check if we should stop after current (only check when queue is empty or getting new task)
        if stop_after_current:
            # Only stop if no active downloads (let current ones finish)
            with download_lock:
                if len(active_downloads) == 0:
                    log("Stop after current: No more active downloads, pausing queue")
                    stop_after_current = False  # Reset flag
                    # Pause by not taking more tasks
                    time.sleep(1)
                    continue
        
        try:
            task = task_queue.get(timeout=5)
        except queue.Empty:
            continue
        
        if task is None:
            task_queue.task_done()
            break
        
        # Check stop_after_current again after getting a task
        if stop_after_current:
            # Put task back and wait
            task_queue.put(task)
            task_queue.task_done()
            time.sleep(1)
            continue
        
        tid = task['task_id']
        
        with download_lock:
            pending_display = [x for x in pending_display if x['id'] != tid]
        
        if tid in cancelled_tasks:
            cancelled_tasks.discard(tid)
            task_queue.task_done()
            continue
        
        try:
            download_file(task)
        except Exception as e:
            log(f"Worker Error: {e}")
        
        task_queue.task_done()


def download_subtitles(server, item_id, video_filepath, languages=None):
    """Download external subtitles for a video file"""
    if languages is None:
        languages = ['eng']
    
    try:
        # Get item details to find available subtitles
        base_url = server['url']
        headers = get_auth_header(server['key'])
        
        # Fetch item with media streams
        response = requests.get(
            f"{base_url}/Items/{item_id}",
            headers=headers,
            params={'Fields': 'MediaStreams'},
            timeout=10
        )
        
        if not response.ok:
            return
        
        item = response.json()
        media_streams = item.get('MediaStreams', [])
        
        # Find external subtitle streams
        subtitle_streams = [
            s for s in media_streams 
            if s.get('Type') == 'Subtitle' and s.get('IsExternal', False)
        ]
        
        if not subtitle_streams:
            # No external subtitles available
            return
        
        video_base = os.path.splitext(video_filepath)[0]
        downloaded_count = 0
        
        for stream in subtitle_streams:
            stream_index = stream.get('Index')
            language = stream.get('Language', 'und')
            codec = stream.get('Codec', 'srt')
            title = stream.get('Title', '')
            
            # Check if this language is in our preferred list
            if language not in languages and 'all' not in languages:
                continue
            
            # Determine subtitle extension
            ext_map = {
                'srt': 'srt',
                'ass': 'ass',
                'ssa': 'ssa',
                'sub': 'sub',
                'vtt': 'vtt',
                'pgs': 'sup',
                'dvdsub': 'sub'
            }
            sub_ext = ext_map.get(codec.lower(), 'srt')
            
            # Build subtitle filename
            lang_suffix = f".{language}" if language != 'und' else ""
            forced_suffix = ".forced" if stream.get('IsForced') else ""
            sdh_suffix = ".sdh" if stream.get('IsSDH') or 'sdh' in title.lower() else ""
            
            sub_filename = f"{video_base}{lang_suffix}{forced_suffix}{sdh_suffix}.{sub_ext}"
            
            # Skip if subtitle file already exists
            if os.path.exists(sub_filename):
                continue
            
            # Download the subtitle
            try:
                sub_url = f"{base_url}/Videos/{item_id}/{item_id}/Subtitles/{stream_index}/Stream.{sub_ext}"
                sub_response = requests.get(sub_url, headers=headers, timeout=30)
                
                if sub_response.ok:
                    with open(sub_filename, 'wb') as f:
                        f.write(sub_response.content)
                    downloaded_count += 1
                    log(f"📝 Downloaded subtitle: {os.path.basename(sub_filename)}")
            except Exception as sub_err:
                log(f"⚠ Failed to download subtitle {stream_index}: {sub_err}")
        
        if downloaded_count > 0:
            log(f"📝 Downloaded {downloaded_count} subtitle(s) for {os.path.basename(video_filepath)}")
            
    except Exception as e:
        log(f"⚠ Subtitle download error: {e}")


def download_file(task):
    """Download a single file with speed limiting, pause support, and resume capability (Pro)"""
    global is_paused
    
    tid = task['task_id']
    filepath = task['filepath']
    filename = os.path.basename(filepath)
    partial_file = filepath + '.partial'
    is_resume = task.get('resume', False)
    
    cfg = load_config()
    speed_limit = cfg.get('speed_limit_kbs', 0)
    chunk_size = cfg.get('chunk_size_kb', 64) * 1024
    timeout = cfg.get('connection_timeout', 30)
    
    # Check for existing partial file (Pro resume feature)
    resume_bytes = 0
    if is_feature_available('transcoding') and os.path.exists(partial_file):
        resume_bytes = os.path.getsize(partial_file)
        is_resume = True
        log(f"🔄 Resuming download from {format_bytes(resume_bytes)}: {filename}")
    
    try:
        dir_path = os.path.dirname(filepath)
        
        if not os.path.exists(dir_path):
            try:
                os.makedirs(dir_path, exist_ok=True)
                log(f"Created directory: {dir_path}")
            except OSError as e:
                raise Exception(f"Cannot create directory {dir_path}: {e}")
        
        test_file = os.path.join(dir_path, '.write_test')
        try:
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
        except OSError as e:
            raise Exception(f"Cannot write to {dir_path}: {e}")
        
        space_ok, space_msg = check_disk_space(dir_path)
        if not space_ok:
            raise Exception(space_msg)
        
        with download_lock:
            active_downloads[tid] = {
                'id': tid,
                'filename': filename,
                'total': 0,
                'current': resume_bytes,
                'speed': '0 B/s',
                'percent': 0,
                'status': 'Resuming...' if is_resume else 'Starting'
            }
        
        # Prepare headers with Range for resume
        headers = task.get('headers', {}).copy()
        if resume_bytes > 0:
            headers['Range'] = f'bytes={resume_bytes}-'
        
        with requests.get(task['url'], stream=True, timeout=timeout, headers=headers) as response:
            # Handle resume response codes
            if response.status_code == 416:  # Range not satisfiable - file complete or changed
                log(f"⚠ Cannot resume {filename} - restarting download")
                resume_bytes = 0
                if os.path.exists(partial_file):
                    os.remove(partial_file)
                # Retry without Range header
                headers.pop('Range', None)
                response = requests.get(task['url'], stream=True, timeout=timeout, headers=headers)
            
            response.raise_for_status()
            
            # Get total size - handle both fresh and resumed downloads
            if response.status_code == 206:  # Partial content (resume)
                content_range = response.headers.get('Content-Range', '')
                if '/' in content_range:
                    total_size = int(content_range.split('/')[-1])
                else:
                    total_size = resume_bytes + int(response.headers.get('content-length', 0))
            else:
                total_size = int(response.headers.get('content-length', 0))
                resume_bytes = 0  # Fresh download
            
            if total_size > 0 and resume_bytes == 0:
                space_ok, space_msg = check_disk_space(dir_path, total_size)
                if not space_ok:
                    raise Exception(space_msg)
            
            with download_lock:
                active_downloads[tid]['total'] = total_size
            
            downloaded = resume_bytes
            speed_window = []
            last_speed_update = time.time()
            last_config_check = time.time()
            last_partial_save = time.time()
            
            # Open file in append mode for resume, write mode for fresh
            file_mode = 'ab' if resume_bytes > 0 else 'wb'
            write_file = partial_file  # Always write to partial file first
            
            with open(write_file, file_mode) as f:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if tid in cancelled_tasks:
                        raise InterruptedError("Download cancelled")
                    
                    while is_paused:
                        with download_lock:
                            if tid in active_downloads:
                                active_downloads[tid].update({
                                    'status': 'Paused',
                                    'speed': '0 B/s'
                                })
                        time.sleep(0.5)
                        
                        if tid in cancelled_tasks:
                            raise InterruptedError("Download cancelled")
                    
                    if not chunk:
                        continue
                    
                    chunk_start = time.time()
                    
                    try:
                        f.write(chunk)
                    except OSError as e:
                        if e.errno == 28:
                            raise Exception(f"Disk full while writing to {dir_path}")
                        raise
                    
                    chunk_len = len(chunk)
                    downloaded += chunk_len
                    
                    now = time.time()
                    if now - last_config_check > 10:
                        cfg = load_config()
                        speed_limit = cfg.get('speed_limit_kbs', 0)
                        last_config_check = now
                    
                    if speed_limit > 0:
                        target_time = chunk_len / (speed_limit * 1024)
                        elapsed = time.time() - chunk_start
                        sleep_time = target_time - elapsed
                        if sleep_time > 0:
                            time.sleep(sleep_time)
                    
                    now = time.time()
                    speed_window.append((now, chunk_len))
                    speed_window = [(t, s) for t, s in speed_window if now - t < 2]
                    
                    if now - last_speed_update >= 0.5:
                        if speed_window:
                            window_time = now - speed_window[0][0]
                            window_bytes = sum(s for _, s in speed_window)
                            speed = window_bytes / window_time if window_time > 0 else 0
                        else:
                            speed = 0
                        
                        with download_lock:
                            if tid in active_downloads:
                                active_downloads[tid].update({
                                    'current': downloaded,
                                    'speed': f"{format_bytes(speed)}/s",
                                    'speed_raw': speed,  # Raw bytes/sec for ETA calc
                                    'status': 'Downloading',
                                    'percent': int((downloaded / total_size) * 100) if total_size > 0 else 0
                                })
                        last_speed_update = now
                    
                    # Save partial state periodically (Pro feature) - every 30 seconds
                    if is_feature_available('transcoding') and now - last_partial_save >= 30:
                        save_partial_state(tid, task, downloaded, total_size)
                        last_partial_save = now
        
        # Download complete - rename partial to final
        if os.path.exists(partial_file):
            if os.path.exists(filepath):
                os.remove(filepath)
            os.rename(partial_file, filepath)
        
        # Clear partial state on successful completion
        clear_partial_state(tid)
        
        with download_lock:
            if tid in active_downloads:
                del active_downloads[tid]
        log(f"✓ Completed: {filename}")
        
        # Download subtitles if enabled (Free feature)
        cfg = load_config()
        if cfg.get('download_subtitles', True) and task.get('item_id') and task.get('server'):
            try:
                download_subtitles(task['server'], task['item_id'], filepath, cfg.get('subtitle_languages', ['eng']))
            except Exception as sub_error:
                log(f"⚠ Subtitle download failed: {sub_error}")
        
        # Transcode if enabled (Pro feature)
        if cfg.get('transcode_enabled', False) and is_feature_available('transcoding'):
            preset = cfg.get('transcode_preset', 'original')
            if preset != 'original':
                # Show transcoding status
                with download_lock:
                    active_downloads[tid] = {
                        'id': tid,
                        'filename': f"🔄 {filename}",
                        'total': 0,
                        'current': 0,
                        'speed': 'Transcoding...',
                        'percent': 0,
                        'status': f'Transcoding ({preset})'
                    }
                
                transcoded_path = transcode_file(filepath)
                
                with download_lock:
                    if tid in active_downloads:
                        del active_downloads[tid]
                
                if transcoded_path and transcoded_path != filepath:
                    filepath = transcoded_path
                    filename = os.path.basename(filepath)
        
        # Add to download history
        with download_lock:
            download_history.appendleft({
                'filename': filename,
                'size': os.path.getsize(filepath) if os.path.exists(filepath) else total_size,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'path': filepath
            })
        
        # Save history periodically (every 5 downloads)
        if len(download_history) % 5 == 0:
            threading.Thread(target=save_download_history, daemon=True).start()
        
        # Send notification if enabled (Pro feature)
        send_notification(f"✓ Download Complete: {filename}", "download_complete")
        
    except InterruptedError:
        log(f"✗ Cancelled: {filename}")
        # Save partial state for Pro users to resume later
        if is_feature_available('transcoding') and 'downloaded' in dir() and 'total_size' in dir():
            save_partial_state(tid, task, downloaded, total_size)
            log(f"💾 Partial download saved for resume: {filename}")
        _cleanup_download(tid, filepath, keep_partial=is_feature_available('transcoding'))
        
    except Exception as e:
        log(f"✗ Failed {filename}: {e}")
        # Save partial state for Pro users to resume later
        if is_feature_available('transcoding'):
            try:
                partial_file = filepath + '.partial'
                if os.path.exists(partial_file):
                    downloaded = os.path.getsize(partial_file)
                    total_size = task.get('total_size', 0)
                    save_partial_state(tid, task, downloaded, total_size)
                    log(f"💾 Partial download saved for resume: {filename}")
            except:
                pass
        _cleanup_download(tid, filepath, keep_partial=is_feature_available('transcoding'))
        # Send error notification if enabled
        send_notification(f"✗ Download Failed: {filename} - {e}", "download_error")


def _cleanup_download(tid, filepath, keep_partial=False):
    """Clean up after failed/cancelled download"""
    with download_lock:
        if tid in active_downloads:
            del active_downloads[tid]
    cancelled_tasks.discard(tid)
    
    # Only delete actual file, not partial (so Pro users can resume)
    if os.path.exists(filepath):
        try:
            os.remove(filepath)
        except Exception:
            pass
    
    # Delete partial file unless keeping for resume
    if not keep_partial:
        partial_file = filepath + '.partial'
        if os.path.exists(partial_file):
            try:
                os.remove(partial_file)
            except Exception:
                pass
        clear_partial_state(tid)


def send_notification(message, event_type="info"):
    """Send notification via Apprise (Pro feature)"""
    if not is_feature_available('notifications'):
        return
    
    if not APPRISE_AVAILABLE:
        return
    
    cfg = load_config()
    
    # Check notification preferences
    if event_type == "download_complete" and not cfg.get('notify_on_complete', True):
        return
    if event_type == "download_error" and not cfg.get('notify_on_error', True):
        return
    
    notification_urls = cfg.get('notification_urls', [])
    if not notification_urls:
        return
    
    try:
        apobj = apprise.Apprise()
        for url in notification_urls:
            apobj.add(url)
        
        apobj.notify(
            title="JellyLooter",
            body=message,
            notify_type=apprise.NotifyType.SUCCESS if "Complete" in message else apprise.NotifyType.FAILURE
        )
    except Exception as e:
        log(f"Notification error: {e}")


def transcode_file(filepath, force_software=False):
    """Transcode file using FFmpeg (Pro feature) - TEMPORARILY DISABLED"""
    # Transcoding temporarily disabled for v3.0.0 release
    # Will be re-enabled once hardware acceleration is more stable
    return filepath
    
    if not is_feature_available('transcoding'):
        return filepath
    
    cfg = load_config()
    if not cfg.get('transcode_enabled', False):
        return filepath
    
    preset = cfg.get('transcode_preset', 'original')
    if preset == 'original':
        return filepath
    
    # Check if file is a video
    video_extensions = ['.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm', '.m4v']
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in video_extensions:
        return filepath
    
    # Build FFmpeg command based on preset and encoder
    base_name = os.path.splitext(filepath)[0]
    encoder = 'software' if force_software else cfg.get('transcode_encoder', 'software')
    output_ext = '.mkv' if 'h265' in preset or 'hevc' in preset else '.mp4'
    output_path = f"{base_name}_transcoded{output_ext}"
    
    # Encoder mappings
    h264_encoders = {
        'software': 'libx264',
        'nvenc': 'h264_nvenc',
        'qsv': 'h264_qsv',
        'vaapi': 'h264_vaapi'
    }
    h265_encoders = {
        'software': 'libx265',
        'nvenc': 'hevc_nvenc',
        'qsv': 'hevc_qsv',
        'vaapi': 'hevc_vaapi'
    }
    
    try:
        # Base ffmpeg args with hidden banner for cleaner output
        base_args = ['ffmpeg', '-hide_banner', '-loglevel', 'error', '-i', filepath]
        
        if preset == 'h265':
            # H.265/HEVC encoding for smaller files
            video_codec = h265_encoders.get(encoder, 'libx265')
            if encoder == 'software':
                cmd = base_args + [
                    '-c:v', video_codec, '-crf', '28', '-preset', 'medium',
                    '-c:a', 'aac', '-b:a', '128k',
                    '-y', output_path
                ]
            else:
                # GPU encoders use different quality settings
                cmd = base_args + [
                    '-c:v', video_codec, '-preset', 'slow', '-b:v', '4M',
                    '-c:a', 'aac', '-b:a', '128k',
                    '-y', output_path
                ]
        elif preset == 'h264':
            # H.264 encoding
            video_codec = h264_encoders.get(encoder, 'libx264')
            if encoder == 'software':
                cmd = base_args + [
                    '-c:v', video_codec, '-crf', '23', '-preset', 'medium',
                    '-c:a', 'aac', '-b:a', '128k',
                    '-y', output_path
                ]
            else:
                cmd = base_args + [
                    '-c:v', video_codec, '-preset', 'slow', '-b:v', '6M',
                    '-c:a', 'aac', '-b:a', '128k',
                    '-y', output_path
                ]
        elif preset == 'mobile':
            # Mobile-friendly (720p, lower bitrate)
            video_codec = h264_encoders.get(encoder, 'libx264')
            cmd = base_args + [
                '-c:v', video_codec, '-crf', '23', '-preset', 'fast',
                '-vf', 'scale=-2:720',
                '-c:a', 'aac', '-b:a', '128k',
                '-y', output_path
            ]
        elif preset == '4k':
            # 4K optimized
            video_codec = h265_encoders.get(encoder, 'libx265')
            cmd = base_args + [
                '-c:v', video_codec, '-crf', '22', '-preset', 'slow',
                '-c:a', 'aac', '-b:a', '192k',
                '-y', output_path
            ]
        elif preset == 'custom':
            # Custom FFmpeg arguments with sanitization
            custom_args = cfg.get('transcode_custom_args', '')
            if not custom_args:
                return filepath
            # Sanitize: remove dangerous characters and limit arg length
            # Only allow alphanumeric, spaces, hyphens, colons, periods, equals
            import re
            sanitized = re.sub(r'[^a-zA-Z0-9\s\-\.:=]', '', custom_args)
            if len(sanitized) > 500:  # Limit total length
                log("Custom transcode args too long, truncating")
                sanitized = sanitized[:500]
            # Block dangerous ffmpeg options
            dangerous = ['-filter_complex', 'concat', 'file:', 'http:', 'https:', 'ftp:', 
                        'pipe:', 'tcp:', 'udp:', '-f', 'lavfi', 'movie=', 'amovie=']
            for d in dangerous:
                if d.lower() in sanitized.lower():
                    log(f"Blocked dangerous ffmpeg arg: {d}")
                    return filepath
            cmd = base_args + sanitized.split() + ['-y', output_path]
        else:
            return filepath
        
        original_name = os.path.basename(filepath)
        log(f"🔄 Transcoding: {original_name} ({preset}, {encoder})")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)  # 2 hour timeout
        
        if result.returncode == 0 and os.path.exists(output_path):
            # Remove original, keep transcoded
            original_size = os.path.getsize(filepath)
            new_size = os.path.getsize(output_path)
            savings = ((original_size - new_size) / original_size) * 100 if original_size > 0 else 0
            
            os.remove(filepath)
            log(f"✓ Transcoded: {os.path.basename(output_path)} ({format_bytes(original_size)} → {format_bytes(new_size)}, saved {savings:.1f}%)")
            return output_path
        else:
            error_msg = result.stderr[:300] if result.stderr else 'Unknown error'
            log(f"✗ Transcode failed: {error_msg}")
            
            # Check for hardware encoder errors and fallback to software
            hw_error_indicators = ['nvenc', 'qsv', 'vaapi', 'libnvidia', 'cuda', 'driver', 'gpu', 'hwaccel']
            if not force_software and encoder != 'software':
                if any(ind in error_msg.lower() for ind in hw_error_indicators):
                    log(f"⚠️ Hardware encoder failed, retrying with software encoding...")
                    if os.path.exists(output_path):
                        os.remove(output_path)
                    return transcode_file(filepath, force_software=True)
            
            if os.path.exists(output_path):
                os.remove(output_path)
            return filepath
            
    except subprocess.TimeoutExpired:
        log(f"✗ Transcode timeout: {os.path.basename(filepath)}")
        if os.path.exists(output_path):
            os.remove(output_path)
        return filepath
    except FileNotFoundError:
        log("✗ FFmpeg not found - transcoding disabled")
        return filepath
    except Exception as e:
        log(f"✗ Transcode error: {e}")
        return filepath


# --- Download Queue Ordering ---

def sort_download_queue(items, order='library'):
    """Sort items based on download order preference"""
    if order == 'random':
        random.shuffle(items)
        return items
    
    if order == 'alphabetical':
        return sorted(items, key=lambda x: x.get('sort_name', x.get('Name', '')).lower())
    
    if order == 'show_complete':
        # Group by series, download complete series before moving to next
        series_groups = {}
        movies = []
        for item in items:
            series_name = item.get('SeriesName')
            if series_name:
                if series_name not in series_groups:
                    series_groups[series_name] = []
                series_groups[series_name].append(item)
            else:
                movies.append(item)
        
        result = movies
        for series in sorted(series_groups.keys()):
            eps = series_groups[series]
            eps.sort(key=lambda x: (x.get('ParentIndexNumber', 0), x.get('IndexNumber', 0)))
            result.extend(eps)
        return result
    
    if order == 'season_round':
        # First season of each show, then second season of each, etc.
        series_seasons = {}
        movies = []
        for item in items:
            series_name = item.get('SeriesName')
            if series_name:
                season = item.get('ParentIndexNumber', 0)
                key = (series_name, season)
                if key not in series_seasons:
                    series_seasons[key] = []
                series_seasons[key].append(item)
            else:
                movies.append(item)
        
        # Sort episodes within each season
        for key in series_seasons:
            series_seasons[key].sort(key=lambda x: x.get('IndexNumber', 0))
        
        # Get max season number
        max_season = max([k[1] for k in series_seasons.keys()], default=0)
        
        result = movies
        for season_num in range(1, max_season + 2):
            for series_name in sorted(set(k[0] for k in series_seasons.keys())):
                key = (series_name, season_num)
                if key in series_seasons:
                    result.extend(series_seasons[key])
        return result
    
    if order == 'episode_round':
        # First episode of each show, then second episode of each, etc.
        series_episodes = {}
        movies = []
        for item in items:
            series_name = item.get('SeriesName')
            if series_name:
                if series_name not in series_episodes:
                    series_episodes[series_name] = []
                series_episodes[series_name].append(item)
            else:
                movies.append(item)
        
        # Sort by season then episode
        for series in series_episodes:
            series_episodes[series].sort(key=lambda x: (x.get('ParentIndexNumber', 0), x.get('IndexNumber', 0)))
        
        # Round robin through episodes
        result = movies
        max_len = max([len(eps) for eps in series_episodes.values()], default=0)
        for i in range(max_len):
            for series in sorted(series_episodes.keys()):
                if i < len(series_episodes[series]):
                    result.append(series_episodes[series][i])
        return result
    
    # Default: library order (as returned by server)
    return items


# --- API Authentication ---

def login_with_creds(url, username, password):
    """Authenticate with username/password and return token and user_id"""
    try:
        response = requests.post(
            f"{url}/Users/AuthenticateByName",
            json={"Username": username, "Pw": password},
            headers=get_auth_header(),
            timeout=10
        )
        log(f"Auth response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            log(f"Auth response keys: {list(data.keys())}")
            
            # Try different token field names used by different Jellyfin versions
            token = data.get("AccessToken") or data.get("access_token") or data.get("Token")
            
            # Get user ID from the response
            user_id = None
            if "User" in data and isinstance(data["User"], dict):
                user_id = data["User"].get("Id")
            
            if token:
                log(f"Got access token: {token[:20]}... for user: {user_id}")
                return {"token": token, "user_id": user_id}
            else:
                log(f"No token found in response. Full response: {str(data)[:500]}")
                return None
        else:
            log(f"Auth failed: {response.status_code} - {response.text[:200]}")
            return None
    except requests.exceptions.Timeout:
        log("Auth failed: Connection timeout")
        return None
    except requests.exceptions.ConnectionError as e:
        log(f"Auth failed: Connection error - {e}")
        return None
    except Exception as e:
        log(f"Auth failed: {e}")
        return None


# --- Flask Routes: Static Files ---

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)


# --- Flask Routes: Health Check (No Auth Required) ---

@app.route('/health')
@app.route('/api/health')
def health_check():
    """
    Health check endpoint for Docker/Unraid/monitoring systems.
    No authentication required.
    Returns 200 if healthy, 503 if unhealthy.
    """
    try:
        config = load_config()
        
        # Check disk space on download path
        download_path = config.get('download_path', '/downloads')
        disk_ok = True
        disk_free = 0
        disk_total = 0
        
        if os.path.exists(download_path):
            try:
                stat = shutil.disk_usage(download_path)
                disk_free = stat.free
                disk_total = stat.total
                # Warning if less than 1GB free
                disk_ok = disk_free > 1024 * 1024 * 1024
            except:
                pass
        
        # Check remote server connectivity (quick check)
        servers_status = []
        for server in config.get('servers', [])[:3]:  # Only check first 3
            server_ok = False
            try:
                url = server.get('url', '').rstrip('/')
                if url:
                    r = requests.get(f"{url}/System/Info/Public", timeout=5)
                    server_ok = r.status_code == 200
            except:
                pass
            servers_status.append({
                'name': server.get('name', 'Unknown'),
                'healthy': server_ok
            })
        
        # Overall health
        is_healthy = disk_ok  # Add more checks as needed
        
        response = {
            'status': 'healthy' if is_healthy else 'unhealthy',
            'version': VERSION,
            'uptime_seconds': int(time.time() - app.start_time) if hasattr(app, 'start_time') else 0,
            'queue': {
                'active': len(active_downloads),
                'pending': task_queue.qsize(),
                'workers': active_workers,
                'paused': is_paused
            },
            'disk': {
                'path': download_path,
                'free_bytes': disk_free,
                'free_human': format_bytes(disk_free),
                'total_bytes': disk_total,
                'healthy': disk_ok
            },
            'servers': servers_status,
            'cache': {
                'items': len(local_id_cache),
                'last_scan': cache_timestamp
            },
            'license': {
                'tier': get_license_tier()
            }
        }
        
        status_code = 200 if is_healthy else 503
        return jsonify(response), status_code
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'version': VERSION
        }), 503


# --- Flask Routes: Authentication ---

@app.route('/setup')
def setup_page():
    """Initial setup page"""
    if not is_auth_enabled():
        return redirect(url_for('index'))
    if is_setup_complete():
        return redirect(url_for('login'))
    return render_template('setup.html')


@app.route('/login')
def login():
    """Login page"""
    if not is_auth_enabled():
        return redirect(url_for('index'))
    if not is_setup_complete():
        return redirect(url_for('setup_page'))
    if 'user' in session:
        return redirect(url_for('index'))
    cfg = load_config()
    return render_template('login.html', lang=cfg.get('language', 'en'), version=VERSION)


@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.pop('user', None)
    response = make_response(redirect(url_for('login') if is_auth_enabled() else url_for('index')))
    response.delete_cookie('remember_token')
    return response


# --- License API Routes ---

@app.route('/api/license', methods=['GET'])
def api_license_status():
    """Get current license status"""
    tier = get_license_tier()
    limits = get_tier_limits()
    license_data = load_license()
    
    response = {
        'tier': tier,
        'limits': limits,
        'trial_days_remaining': get_trial_days_remaining() if tier == 'trial' else 0,
        'is_pro': is_pro(),
        'is_trial': is_trial()
    }
    
    if tier == 'pro':
        response['activated_at'] = license_data.get('activated_at')
    
    return jsonify(response)


@app.route('/api/license/activate', methods=['POST'])
def api_activate_license():
    """Activate a Pro license key"""
    data = request.json
    key = data.get('key', '').strip().upper()
    
    if not key:
        return jsonify({'success': False, 'error': 'License key required'})
    
    result = activate_license(key)
    return jsonify(result)


@app.route('/api/license/trial', methods=['POST'])
def api_activate_trial():
    """Activate 14-day trial"""
    result = activate_trial()
    return jsonify(result)


@app.route('/api/license/deactivate', methods=['POST'])
def api_deactivate_license():
    """Deactivate license (revert to free)"""
    license_data = load_license()
    old_tier = license_data.get('tier', 'free')
    
    license_data['tier'] = 'free'
    license_data['key'] = None
    save_license(license_data)
    
    log(f"License deactivated (was: {old_tier})")
    return jsonify({'success': True, 'tier': 'free'})


@app.route('/api/license/check_backup', methods=['GET'])
def api_check_backup_license():
    """Check if a backup license exists in library folders"""
    backup = check_backup_license()
    return jsonify({
        'found': backup.get('found', False),
        'message': 'Backup license found' if backup.get('found') else 'No backup license found'
    })


@app.route('/api/license/restore', methods=['POST'])
def api_restore_license():
    """Restore license from backup in library folders"""
    result = restore_from_backup()
    if result.get('success'):
        return jsonify({
            'success': True,
            'tier': 'pro',
            'message': 'License restored from backup'
        })
    return jsonify({
        'success': False,
        'error': 'No valid backup license found'
    })


@app.route('/api/license/purge_all', methods=['POST'])
def api_purge_all_licenses():
    """
    NUCLEAR OPTION: Remove ALL licenses including backups.
    Hidden endpoint for testing - requires special confirmation code.
    """
    data = request.json or {}
    confirm_code = data.get('confirm', '')
    
    # Require confirmation code to prevent accidental use
    if confirm_code != 'PURGE_ALL_LICENSES_CONFIRM':
        return jsonify({
            'success': False,
            'error': 'Confirmation code required. Send {"confirm": "PURGE_ALL_LICENSES_CONFIRM"}'
        })
    
    removed = {'primary': False, 'backups': 0}
    
    # Remove primary license
    try:
        if os.path.exists(LICENSE_FILE):
            os.remove(LICENSE_FILE)
            removed['primary'] = True
            log("🗑️ Primary license removed")
    except Exception as e:
        log(f"Error removing primary license: {e}")
    
    # Remove all backup licenses
    paths = _get_backup_paths()
    for path in paths:
        try:
            backup_dir = os.path.join(path, _BKP_FOLDER)
            backup_file = os.path.join(backup_dir, _BKP_FILE)
            
            if os.path.exists(backup_file):
                os.remove(backup_file)
                removed['backups'] += 1
                log(f"🗑️ Backup license removed from {path}")
            
            # Also remove the hidden folder if empty
            if os.path.exists(backup_dir) and not os.listdir(backup_dir):
                os.rmdir(backup_dir)
        except Exception as e:
            log(f"Error removing backup from {path}: {e}")
    
    log(f"☢️ License purge complete: primary={removed['primary']}, backups={removed['backups']}")
    
    return jsonify({
        'success': True,
        'removed': removed,
        'message': f"Purged primary license and {removed['backups']} backup(s)"
    })


@app.route('/api/setup', methods=['POST'])
def api_setup():
    """Handle initial setup"""
    if not is_auth_enabled():
        return jsonify({"status": "error", "message": "Authentication is disabled"})
    if is_setup_complete():
        return jsonify({"status": "error", "message": "Setup already completed"})
    
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required"})
    
    if len(password) < 4:
        return jsonify({"status": "error", "message": "Password must be at least 4 characters"})
    
    auth = load_auth() or {}
    auth['users'] = {username: hash_password(password)}
    auth['tokens'] = {}
    if 'secret_key' not in auth:
        auth['secret_key'] = secrets.token_hex(32)
    save_auth(auth)
    app.secret_key = auth['secret_key']
    
    return jsonify({"status": "ok", "message": "Setup complete"})


# Rate limit decorator helper
def rate_limit_login(f):
    """Apply rate limiting to login if available"""
    if limiter:
        return limiter.limit("5 per minute")(f)
    return f


@app.route('/api/login', methods=['POST'])
@rate_limit_login
def api_login():
    """Handle login with rate limiting"""
    if not is_auth_enabled():
        return jsonify({"status": "error", "message": "Authentication is disabled"})
    
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    remember = data.get('remember', False)
    
    auth = load_auth()
    if not auth or 'users' not in auth:
        return jsonify({"status": "error", "message": "No users configured"})
    
    if username not in auth['users']:
        log(f"Login failed: unknown user '{username}'")
        return jsonify({"status": "error", "message": "Invalid credentials"})
    
    if not verify_password(password, auth['users'][username]):
        log(f"Login failed: wrong password for '{username}'")
        return jsonify({"status": "error", "message": "Invalid credentials"})
    
    session['user'] = username
    session.permanent = True
    
    # Set session timeout
    cfg = load_config()
    timeout = cfg.get('session_timeout_minutes', 30)
    app.permanent_session_lifetime = datetime.timedelta(minutes=timeout)
    
    log(f"User '{username}' logged in")
    response_data = {"status": "ok"}
    
    if remember:
        token = secrets.token_hex(32)
        if 'tokens' not in auth:
            auth['tokens'] = {}
        auth['tokens'][username] = token
        save_auth(auth)
        response_data['remember_token'] = token
    
    return jsonify(response_data)


# --- Flask Routes: Main ---

@app.route('/')
@login_required
def index():
    cfg = load_config()
    lang = cfg.get('language', 'en')
    return render_template('index.html', 
                           lang=lang, 
                           translations=get_all_translations(lang),
                           version=VERSION,
                           config=cfg)


@app.route('/changelog')
@login_required
def changelog():
    cfg = load_config()
    lang = cfg.get('language', 'en')
    return render_template('changelog.html', 
                           lang=lang,
                           t=get_all_translations(lang),
                           version=VERSION)


@app.route('/help')
@login_required
def help_page():
    cfg = load_config()
    lang = cfg.get('language', 'en')
    return render_template('help.html', 
                           lang=lang,
                           t=get_all_translations(lang),
                           version=VERSION)


@app.route('/api/config', methods=['GET', 'POST'])
@login_required
def config_api():
    if request.method == 'POST':
        save_config(request.json)
        return jsonify({"status": "ok"})
    cfg = load_config()
    # Add license tier to config for frontend
    cfg['license_tier'] = get_license_tier()
    return jsonify(cfg)


@app.route('/api/config/export')
@login_required
def export_config():
    """
    Export configuration as downloadable JSON file.
    Sensitive data (API keys, passwords) are masked for security.
    """
    config = load_config()
    
    # Create export copy with masked sensitive data
    export_data = config.copy()
    
    # Mask server API keys
    if 'servers' in export_data:
        masked_servers = []
        for server in export_data['servers']:
            s = server.copy()
            if s.get('key'):
                s['key'] = '***MASKED***'
            if s.get('password'):
                s['password'] = '***MASKED***'
            masked_servers.append(s)
        export_data['servers'] = masked_servers
    
    # Mask local server keys
    if export_data.get('local_server_key'):
        export_data['local_server_key'] = '***MASKED***'
    
    if 'local_servers' in export_data:
        masked_local = []
        for server in export_data['local_servers']:
            s = server.copy()
            if s.get('key'):
                s['key'] = '***MASKED***'
            masked_local.append(s)
        export_data['local_servers'] = masked_local
    
    # Mask *arr API keys
    for arr_key in ['sonarr_api_key', 'radarr_api_key', 'lidarr_api_key']:
        if export_data.get(arr_key):
            export_data[arr_key] = '***MASKED***'
    
    # Mask notification URLs (may contain tokens)
    if export_data.get('notification_urls'):
        export_data['notification_urls'] = ['***MASKED***' for _ in export_data['notification_urls']]
    
    # Add export metadata
    export_data['_export'] = {
        'version': VERSION,
        'exported_at': datetime.datetime.now().isoformat(),
        'note': 'API keys and sensitive data have been masked. You will need to re-enter them after import.'
    }
    
    # Create response with download headers
    response = make_response(json.dumps(export_data, indent=2))
    response.headers['Content-Type'] = 'application/json'
    response.headers['Content-Disposition'] = f'attachment; filename=jellylooter_config_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    
    log("📤 Config exported")
    return response


@app.route('/api/config/import', methods=['POST'])
@login_required
def import_config():
    """
    Import configuration from JSON.
    Preserves existing API keys if imported ones are masked.
    """
    try:
        import_data = request.json
        if not import_data:
            return jsonify({'success': False, 'error': 'No data provided'})
        
        # Remove export metadata
        import_data.pop('_export', None)
        
        # Load current config to preserve sensitive data
        current_config = load_config()
        
        # Preserve masked API keys from current config
        if 'servers' in import_data:
            for i, server in enumerate(import_data['servers']):
                if server.get('key') == '***MASKED***':
                    # Try to find matching server in current config by URL
                    for curr_server in current_config.get('servers', []):
                        if curr_server.get('url') == server.get('url'):
                            server['key'] = curr_server.get('key', '')
                            break
                    else:
                        server['key'] = ''  # No match found
                
                if server.get('password') == '***MASKED***':
                    for curr_server in current_config.get('servers', []):
                        if curr_server.get('url') == server.get('url'):
                            server['password'] = curr_server.get('password', '')
                            break
                    else:
                        server['password'] = ''
        
        # Preserve local server keys
        if import_data.get('local_server_key') == '***MASKED***':
            import_data['local_server_key'] = current_config.get('local_server_key', '')
        
        if 'local_servers' in import_data:
            for server in import_data['local_servers']:
                if server.get('key') == '***MASKED***':
                    for curr_server in current_config.get('local_servers', []):
                        if curr_server.get('url') == server.get('url'):
                            server['key'] = curr_server.get('key', '')
                            break
                    else:
                        server['key'] = ''
        
        # Preserve *arr API keys
        for arr_key in ['sonarr_api_key', 'radarr_api_key', 'lidarr_api_key']:
            if import_data.get(arr_key) == '***MASKED***':
                import_data[arr_key] = current_config.get(arr_key, '')
        
        # Preserve notification URLs
        if import_data.get('notification_urls'):
            if all(url == '***MASKED***' for url in import_data['notification_urls']):
                import_data['notification_urls'] = current_config.get('notification_urls', [])
        
        # Save the merged config
        save_config(import_data)
        
        log("📥 Config imported successfully")
        return jsonify({
            'success': True,
            'message': 'Configuration imported. Masked API keys were preserved from existing config.'
        })
        
    except json.JSONDecodeError:
        return jsonify({'success': False, 'error': 'Invalid JSON format'})
    except Exception as e:
        log(f"Config import error: {e}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/translations')
def get_translations():
    """Get translations for current language"""
    cfg = load_config()
    lang = request.args.get('lang', cfg.get('language', 'en'))
    return jsonify(get_all_translations(lang))


@app.route('/api/status')
@login_required
def status():
    """Get current status with license info"""
    with download_lock:
        # Get license info
        tier = get_license_tier()
        limits = get_tier_limits()
        
        return jsonify({
            "active": dict(active_downloads),
            "pending": list(pending_display),
            "paused": is_paused,
            "cache_time": cache_timestamp,
            "cache_count": len(local_id_cache),
            "scan_progress": dict(scan_progress),
            "queue_size": task_queue.qsize(),
            "worker_count": active_workers,
            "version": VERSION,
            # License info
            "license": {
                "tier": tier,
                "is_pro": tier == 'pro',
                "is_trial": tier == 'trial',
                "show_ads": limits.get('show_ads', True),
                "trial_days_remaining": get_trial_days_remaining() if tier == 'trial' else 0
            }
        })


@app.route('/api/logs')
@login_required
def get_logs():
    with download_lock:
        return "\n".join(reversed(list(log_buffer)))


@app.route('/api/history')
@login_required
def get_history():
    with download_lock:
        return jsonify(list(download_history)[:50])  # Return last 50


@app.route('/api/stats')
@login_required
def get_stats():
    """Get download statistics"""
    with download_lock:
        today = datetime.datetime.now().date()
        
        # Calculate stats from history
        total_bytes = 0
        today_count = 0
        today_bytes = 0
        
        for item in download_history:
            size = item.get('size', 0)
            total_bytes += size
            
            # Check if download was today
            ts = item.get('timestamp', '')
            if ts:
                try:
                    item_date = datetime.datetime.fromisoformat(ts).date()
                    if item_date == today:
                        today_count += 1
                        today_bytes += size
                except:
                    pass
        
        # Calculate current speed from active downloads
        current_speed = 0
        for dl in active_downloads.values():
            current_speed += dl.get('speed', 0)
        
        # Queue size
        queue_size = task_queue.qsize() + len(pending_display)
        
        return jsonify({
            'total_bytes': total_bytes,
            'total_human': format_bytes(total_bytes),
            'today_count': today_count,
            'today_bytes': today_bytes,
            'today_human': format_bytes(today_bytes),
            'current_speed': current_speed,
            'current_speed_human': f"{current_speed / 1024:.1f} KB/s" if current_speed > 0 else "0 KB/s",
            'queue_size': queue_size,
            'history_count': len(download_history)
        })


@app.route('/api/pause', methods=['POST'])
@login_required
def pause_dl():
    global is_paused
    is_paused = True
    log("Downloads paused")
    return jsonify({"paused": True})


@app.route('/api/resume', methods=['POST'])
@login_required
def resume_dl():
    global is_paused
    is_paused = False
    log("Downloads resumed")
    return jsonify({"paused": False})


@app.route('/api/downloads/resumable')
@login_required
def get_resumable():
    """Get list of downloads that can be resumed (Pro feature)"""
    if not is_feature_available('transcoding'):
        return jsonify({'resumable': [], 'pro_required': True})
    
    resumable = get_resumable_downloads()
    return jsonify({'resumable': resumable, 'pro_required': False})


@app.route('/api/downloads/resume_partial', methods=['POST'])
@login_required
def resume_partial():
    """Resume a partial download (Pro feature)"""
    if not is_feature_available('transcoding'):
        return jsonify({'success': False, 'error': 'Pro feature required'})
    
    data = request.json or {}
    task_id = data.get('task_id')
    
    if not task_id:
        return jsonify({'success': False, 'error': 'No task_id provided'})
    
    partials = load_partial_downloads()
    if task_id not in partials:
        return jsonify({'success': False, 'error': 'Partial download not found'})
    
    info = partials[task_id]
    
    # Reconstruct the task
    task = {
        'task_id': task_id,
        'url': info.get('url', ''),
        'filepath': info.get('filepath', ''),
        'headers': info.get('headers', {}),
        'server': info.get('server', {}),
        'item_id': info.get('item_id', ''),
        'resume': True
    }
    
    # Add to pending and queue
    with download_lock:
        pending_display.append({
            'id': task_id,
            'name': f"🔄 {info.get('filename', 'Unknown')}"
        })
    task_queue.put(task)
    
    log(f"🔄 Queued resume: {info.get('filename', 'Unknown')}")
    return jsonify({'success': True, 'message': f"Resuming {info.get('filename', 'Unknown')}"})


@app.route('/api/downloads/delete_partial', methods=['POST'])
@login_required
def delete_partial():
    """Delete a partial download (Pro feature)"""
    if not is_feature_available('transcoding'):
        return jsonify({'success': False, 'error': 'Pro feature required'})
    
    data = request.json or {}
    task_id = data.get('task_id')
    
    if not task_id:
        return jsonify({'success': False, 'error': 'No task_id provided'})
    
    partials = load_partial_downloads()
    if task_id not in partials:
        return jsonify({'success': False, 'error': 'Partial download not found'})
    
    info = partials[task_id]
    partial_file = info.get('partial_file', '')
    
    # Delete the partial file
    if partial_file and os.path.exists(partial_file):
        try:
            os.remove(partial_file)
        except:
            pass
    
    # Remove from manifest
    clear_partial_state(task_id)
    
    log(f"🗑️ Deleted partial: {info.get('filename', 'Unknown')}")
    return jsonify({'success': True, 'message': 'Partial download deleted'})


@app.route('/api/cancel', methods=['POST'])
@login_required
def cancel_dl():
    global pending_display
    data = request.json or {}
    task_id = data.get('task_id')
    cancel_all = data.get('all', False)
    
    if cancel_all:
        with download_lock:
            for tid in active_downloads:
                cancelled_tasks.add(tid)
            for item in pending_display:
                cancelled_tasks.add(item['id'])
            pending_display.clear()
        
        while not task_queue.empty():
            try:
                task = task_queue.get_nowait()
                task_queue.task_done()
            except queue.Empty:
                break
        
        log("All downloads cancelled")
        return jsonify({"status": "all_cancelled"})
    
    elif task_id:
        cancelled_tasks.add(task_id)
        with download_lock:
            pending_display = [x for x in pending_display if x['id'] != task_id]
        log(f"Cancelled task: {task_id}")
        return jsonify({"status": "cancelled", "task_id": task_id})
    
    return jsonify({"status": "error", "message": "No task_id provided"})


@app.route('/api/test_connection', methods=['POST'])
@login_required
def test_connection():
    data = request.json
    url = data.get('url', '').rstrip('/')
    
    # Validate URL
    url_valid, url_msg = validate_url(url)
    if not url_valid:
        return jsonify({"status": "error", "error": url_msg})
    
    try:
        if data.get('username'):
            # Username/password auth - validate inputs
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            if not username:
                return jsonify({"status": "error", "error": "Username is required"})
            
            auth_result = login_with_creds(url, username, password)
            if auth_result and auth_result.get('token'):
                token = auth_result['token']
                user_id = auth_result.get('user_id')
                
                # Verify the token works by accessing the user's own data
                verify_response = requests.get(
                    f"{url}/Users/{user_id}" if user_id else f"{url}/Users",
                    headers=get_auth_header(token),
                    timeout=10
                )
                if verify_response.ok:
                    return jsonify({"status": "ok", "key": token, "user_id": user_id})
                else:
                    return jsonify({"status": "error", "error": "Token verification failed"})
            return jsonify({"status": "error", "error": "Invalid credentials"})
        else:
            # API key auth - validate key format
            key = data.get('key', '').strip()
            key_valid, key_msg = validate_api_key(key)
            if not key_valid:
                return jsonify({"status": "error", "error": key_msg})
            
            response = requests.get(
                f"{url}/Users",
                headers=get_auth_header(key),
                timeout=10
            )
            if response.ok:
                users = response.json()
                if users and len(users) > 0:
                    return jsonify({"status": "ok", "key": key})
                else:
                    return jsonify({"status": "error", "error": "No users found - invalid API key?"})
            return jsonify({"status": "error", "error": f"Server returned {response.status_code}"})
    except requests.exceptions.Timeout:
        return jsonify({"status": "error", "error": "Connection timeout"})
    except requests.exceptions.ConnectionError:
        return jsonify({"status": "error", "error": "Cannot connect to server"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


@app.route('/api/rebuild_cache', methods=['POST'])
@login_required
def rebuild_cache():
    threading.Thread(target=cache_worker, daemon=True).start()
    return jsonify({"status": "started"})


@app.route('/api/remove_local', methods=['POST'])
@login_required
def remove_local():
    """Remove single local server (backward compatibility)"""
    cfg = load_config()
    cfg['local_server_url'] = ""
    cfg['local_server_key'] = ""
    save_config(cfg)
    return jsonify({"status": "ok"})


@app.route('/api/local_servers', methods=['GET'])
@login_required
def get_local_servers():
    """Get list of local servers (Pro feature for multiple)"""
    cfg = load_config()
    
    # Support both old single-server format and new multi-server format
    local_servers = cfg.get('local_servers', [])
    
    # If empty but old format exists, migrate
    if not local_servers and cfg.get('local_server_url'):
        local_servers = [{
            'id': generate_id(),
            'name': 'Local Server',
            'url': cfg['local_server_url'],
            'key': cfg.get('local_server_key', ''),
            'type': cfg.get('local_server_type', 'jellyfin')
        }]
    
    return jsonify({"servers": local_servers})


@app.route('/api/local_servers', methods=['POST'])
@login_required
def add_local_server():
    """Add a local server (Pro feature for multiple)"""
    cfg = load_config()
    data = request.json
    
    # Get current local servers
    local_servers = cfg.get('local_servers', [])
    
    # Migrate from old format if needed
    if not local_servers and cfg.get('local_server_url'):
        local_servers = [{
            'id': generate_id(),
            'name': 'Local Server',
            'url': cfg['local_server_url'],
            'key': cfg.get('local_server_key', ''),
            'type': cfg.get('local_server_type', 'jellyfin')
        }]
    
    # Check limit
    max_local = get_feature_limit('max_local_servers')
    if len(local_servers) >= max_local:
        return jsonify({"status": "error", "error": f"Maximum {max_local} local server(s) allowed. Upgrade to Pro for unlimited."})
    
    # Add new server
    new_server = {
        'id': generate_id(),
        'name': data.get('name', 'Local Server'),
        'url': data.get('url', '').rstrip('/'),
        'key': data.get('key', ''),
        'user_id': data.get('user_id'),
        'type': data.get('type', 'jellyfin')
    }
    
    local_servers.append(new_server)
    cfg['local_servers'] = local_servers
    
    # Also update old format for backward compatibility
    if len(local_servers) == 1:
        cfg['local_server_url'] = new_server['url']
        cfg['local_server_key'] = new_server['key']
    
    save_config(cfg)
    return jsonify({"status": "ok", "server": new_server})


@app.route('/api/local_servers/<server_id>', methods=['DELETE'])
@login_required
def delete_local_server(server_id):
    """Delete a local server"""
    cfg = load_config()
    local_servers = cfg.get('local_servers', [])
    
    cfg['local_servers'] = [s for s in local_servers if s['id'] != server_id]
    
    # Update old format
    if not cfg['local_servers']:
        cfg['local_server_url'] = ""
        cfg['local_server_key'] = ""
    
    save_config(cfg)
    return jsonify({"status": "ok"})


@app.route('/api/scan_libs')
@login_required
def scan_libs():
    cfg = load_config()
    results = []
    
    for server in cfg['servers']:
        try:
            headers = get_auth_header(server['key'])
            
            # Use stored user_id if available (for username/password auth)
            user_id = server.get('user_id')
            
            if not user_id:
                user_id = requests.get(
                    f"{server['url']}/Users",
                    headers=headers,
                    timeout=10
                ).json()[0]['Id']
            
            libs = requests.get(
                f"{server['url']}/Users/{user_id}/Views",
                headers=headers,
                timeout=10
            ).json().get('Items', [])
            
            results.append({
                "server_id": server['id'],
                "server_name": server['name'],
                "libs": libs
            })
        except Exception as e:
            log(f"Scan libs error for {server.get('name', 'unknown')}: {e}")
    
    return jsonify(results)


@app.route('/api/browse_remote', methods=['POST'])
@login_required
def browse_remote():
    data = request.json
    cfg = load_config()
    
    server = next(
        (s for s in cfg['servers'] if s['id'] == data['server_id']),
        None
    )
    if not server:
        return jsonify({"items": [], "total": 0, "error": "Server not found"})
    
    try:
        log(f"Browsing server: {server['name']} with key: {server['key'][:20] if server.get('key') else 'None'}...")
        headers = get_auth_header(server['key'])
        log(f"Using headers: {list(headers.keys())}")
        
        # Use stored user_id if available (for username/password auth)
        # Otherwise, query /Users to get a user ID (for API key auth)
        user_id = server.get('user_id')
        
        if not user_id:
            users_response = requests.get(
                f"{server['url']}/Users",
                headers=headers,
                timeout=10
            )
            
            log(f"Users response: {users_response.status_code}")
            
            if not users_response.ok:
                log(f"Browse Error: Server returned {users_response.status_code} - {users_response.text[:200]}")
                return jsonify({"items": [], "total": 0, "error": f"Auth failed: {users_response.status_code}"})
            
            users_data = users_response.json()
            if not users_data or len(users_data) == 0:
                log("Browse Error: No users returned from server")
                return jsonify({"items": [], "total": 0, "error": "No users found - check API key"})
            
            user_id = users_data[0]['Id']
        
        log(f"Using user ID: {user_id}")
        
        local_ids = get_existing_ids()
        
        if data['parent_id'] == 'root':
            views_response = requests.get(
                f"{server['url']}/Users/{user_id}/Views",
                headers=headers,
                timeout=15
            )
            log(f"Views response: {views_response.status_code}")
            
            if not views_response.ok:
                log(f"Views Error: {views_response.status_code} - {views_response.text[:200]}")
                return jsonify({"items": [], "total": 0, "error": f"Failed to get libraries: {views_response.status_code}"})
            
            try:
                views_data = views_response.json()
                items = views_data.get('Items', [])
            except Exception as e:
                log(f"Views JSON Error: {e} - Response: {views_response.text[:200]}")
                return jsonify({"items": [], "total": 0, "error": "Invalid response from server"})
            
            clean_items = [{
                "Id": item['Id'],
                "Name": item['Name'],
                "IsFolder": True,
                "HasImage": True
            } for item in items]
            
            return jsonify({
                "items": clean_items,
                "base_url": server['url'],
                "total": len(items)
            })
        else:
            # Get pagination params
            page = data.get('page', 1)
            items_per_page = data.get('items_per_page', cfg.get('items_per_page', 50))
            skip = (page - 1) * items_per_page
            
            params = {
                'ParentId': data['parent_id'],
                'SortBy': 'SortName',
                'Fields': 'ImageTags,ProviderIds,CommunityRating,CriticRating,OfficialRating,MediaStreams,Width,Height',
                'StartIndex': skip,
                'Limit': items_per_page
            }
            
            items_response = requests.get(
                f"{server['url']}/Users/{user_id}/Items",
                headers=headers,
                params=params,
                timeout=30
            )
            log(f"Items response: {items_response.status_code}")
            
            if not items_response.ok:
                log(f"Items Error: {items_response.status_code} - {items_response.text[:200]}")
                return jsonify({"items": [], "total": 0, "error": f"Failed to get items: {items_response.status_code}"})
            
            try:
                response = items_response.json()
            except Exception as e:
                log(f"Items JSON Error: {e} - Response: {items_response.text[:200]}")
                return jsonify({"items": [], "total": 0, "error": "Invalid response from server"})
            
            clean_items = []
            for item in response.get('Items', []):
                is_folder = item['Type'] in [
                    'Folder', 'CollectionFolder', 'Series',
                    'Season', 'BoxSet'
                ]
                
                exists = False
                providers = item.get('ProviderIds', {})
                
                if local_ids:
                    # Check various ID formats
                    imdb_key = f"imdb_{providers.get('Imdb')}"
                    tmdb_key = f"tmdb_{providers.get('Tmdb')}"
                    tvdb_key = f"tvdb_{providers.get('Tvdb')}"
                    
                    if not is_folder:
                        # For movies/episodes, check IMDB/TMDB
                        exists = imdb_key in local_ids or tmdb_key in local_ids
                    elif item['Type'] == 'Series':
                        # For series, check TVDB/IMDB/TMDB
                        exists = tvdb_key in local_ids or imdb_key in local_ids or tmdb_key in local_ids
                
                # Check what image types are available
                image_tags = item.get('ImageTags', {})
                has_primary = 'Primary' in image_tags
                
                # Get ratings - CommunityRating is typically IMDB/TMDB rating (0-10 scale)
                community_rating = item.get('CommunityRating')
                critic_rating = item.get('CriticRating')  # Rotten Tomatoes (0-100 scale)
                official_rating = item.get('OfficialRating')  # e.g., PG-13, R, TV-MA
                
                # Extract quality info from MediaStreams
                resolution = None
                is_hdr = False
                is_dolby_vision = False
                is_atmos = False
                video_codec = None
                
                media_streams = item.get('MediaStreams', [])
                for stream in media_streams:
                    if stream.get('Type') == 'Video':
                        width = stream.get('Width', 0)
                        height = stream.get('Height', 0)
                        
                        # Determine resolution
                        if width >= 3840 or height >= 2160:
                            resolution = '4K'
                        elif width >= 1920 or height >= 1080:
                            resolution = '1080p'
                        elif width >= 1280 or height >= 720:
                            resolution = '720p'
                        elif width > 0:
                            resolution = 'SD'
                        
                        # Check for HDR
                        video_range = stream.get('VideoRange', '')
                        video_range_type = stream.get('VideoRangeType', '')
                        if 'HDR' in video_range or 'HDR' in video_range_type:
                            is_hdr = True
                        if 'DoVi' in video_range_type or 'DolbyVision' in video_range_type:
                            is_dolby_vision = True
                        
                        # Get codec
                        video_codec = stream.get('Codec', '').upper()
                        
                    elif stream.get('Type') == 'Audio':
                        # Check for Atmos
                        audio_profile = stream.get('Profile', '')
                        codec = stream.get('Codec', '')
                        if 'atmos' in audio_profile.lower() or 'atmos' in codec.lower():
                            is_atmos = True
                
                # Always try Primary first - it's the poster image
                # If not available, the frontend will show placeholder
                clean_items.append({
                    "Id": item['Id'],
                    "Name": item['Name'],
                    "IsFolder": is_folder,
                    "HasPrimary": has_primary,
                    "ExistsLocally": exists,
                    "Type": item.get('Type', 'Unknown'),
                    "SeriesName": item.get('SeriesName'),
                    "ParentIndexNumber": item.get('ParentIndexNumber'),
                    "IndexNumber": item.get('IndexNumber'),
                    "CommunityRating": community_rating,
                    "CriticRating": critic_rating,
                    "OfficialRating": official_rating,
                    "ProductionYear": item.get('ProductionYear'),
                    "Resolution": resolution,
                    "IsHDR": is_hdr,
                    "IsDolbyVision": is_dolby_vision,
                    "IsAtmos": is_atmos,
                    "VideoCodec": video_codec
                })
            
            total = response.get('TotalRecordCount', 0)
            total_pages = (total + items_per_page - 1) // items_per_page
            
            return jsonify({
                "items": clean_items,
                "base_url": server['url'],
                "total": total,
                "page": page,
                "items_per_page": items_per_page,
                "total_pages": total_pages
            })
            
    except Exception as e:
        log(f"Browse Error: {e}")
        return jsonify({"items": [], "total": 0})


@app.route('/api/collection_items', methods=['POST'])
@login_required
def get_collection_items():
    """
    Get all downloadable items from a collection or playlist.
    Recursively fetches all movies/episodes.
    """
    data = request.json
    cfg = load_config()
    
    server = next(
        (s for s in cfg['servers'] if s['id'] == data['server_id']),
        None
    )
    if not server:
        return jsonify({"items": [], "error": "Server not found"})
    
    collection_id = data.get('collection_id')
    if not collection_id:
        return jsonify({"items": [], "error": "No collection_id provided"})
    
    try:
        headers = get_auth_header(server['key'])
        user_id = server.get('user_id')
        
        if not user_id:
            users_response = requests.get(f"{server['url']}/Users", headers=headers, timeout=10)
            if users_response.ok:
                users_data = users_response.json()
                if users_data:
                    user_id = users_data[0]['Id']
        
        if not user_id:
            return jsonify({"items": [], "error": "Could not get user ID"})
        
        # Fetch all items in the collection recursively
        all_items = []
        
        def fetch_items(parent_id, depth=0):
            if depth > 5:  # Prevent infinite recursion
                return
            
            params = {
                'ParentId': parent_id,
                'Recursive': 'true',
                'IncludeItemTypes': 'Movie,Episode',
                'Fields': 'Path,MediaStreams',
                'Limit': 1000
            }
            
            response = requests.get(
                f"{server['url']}/Users/{user_id}/Items",
                headers=headers,
                params=params,
                timeout=60
            )
            
            if response.ok:
                items_data = response.json()
                for item in items_data.get('Items', []):
                    all_items.append({
                        'Id': item['Id'],
                        'Name': item['Name'],
                        'Type': item.get('Type', 'Unknown'),
                        'SeriesName': item.get('SeriesName'),
                        'ParentIndexNumber': item.get('ParentIndexNumber'),
                        'IndexNumber': item.get('IndexNumber')
                    })
        
        fetch_items(collection_id)
        
        log(f"📦 Collection has {len(all_items)} downloadable items")
        
        return jsonify({
            "items": all_items,
            "count": len(all_items)
        })
        
    except Exception as e:
        log(f"Collection fetch error: {e}")
        return jsonify({"items": [], "error": str(e)})


@app.route('/api/batch_download', methods=['POST'])
@login_required
def batch_download():
    data = request.json
    cfg = load_config()
    
    server = next(
        (s for s in cfg['servers'] if s['id'] == data['server_id']),
        None
    )
    if not server:
        return jsonify({"status": "error", "message": "Server not found"})
    
    download_path = data['path']
    space_ok, space_msg = check_disk_space(download_path)
    if not space_ok:
        return jsonify({"status": "error", "message": space_msg})
    
    download_order = cfg.get('download_order', 'library')
    
    for item_id in data['item_ids']:
        tid = generate_id()
        with download_lock:
            pending_display.append({"name": "Resolving...", "id": tid})
        
        threading.Thread(
            target=recursive_resolve,
            args=(server, item_id, data['path'], tid, cfg.get('speed_limit_kbs', 0), download_order),
            daemon=True
        ).start()
    
    return jsonify({"status": "queued", "count": len(data['item_ids'])})


@app.route('/api/disk_space', methods=['POST'])
@login_required
def get_disk_space():
    """Get disk space info for a path"""
    path = request.json.get('path', '/storage')
    
    # Security: Validate and sanitize path
    path = os.path.normpath(path)
    allowed_bases = ['/storage', '/mnt', '/config']
    
    # Check for path traversal
    if '..' in path:
        return jsonify({"status": "error", "message": "Invalid path"})
    
    # Verify path is within allowed directories
    if not any(path.startswith(base) for base in allowed_bases):
        path = '/storage'
    
    if not any(is_safe_path(base, path) for base in allowed_bases):
        return jsonify({"status": "error", "message": "Invalid path"})
    
    try:
        stat = shutil.disk_usage(path)
        return jsonify({
            "status": "ok",
            "path": path,
            "total": format_bytes(stat.total),
            "used": format_bytes(stat.used),
            "free": format_bytes(stat.free),
            "percent_used": int((stat.used / stat.total) * 100)
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        })


# --- *arr Folder Naming Integration ---
# Cache for *arr lookups to avoid repeated API calls
_arr_cache = {
    'sonarr_series': {},  # tvdb_id -> folder_name
    'radarr_movies': {},  # tmdb_id -> folder_name
    'last_refresh': None
}

def refresh_arr_cache():
    """Refresh the *arr cache with all series/movies (Pro feature)"""
    global _arr_cache
    
    if not is_feature_available('arr_integration'):
        return
    
    cfg = load_config()
    
    # Refresh Sonarr cache
    sonarr_url = cfg.get('sonarr_url', '').rstrip('/')
    sonarr_key = cfg.get('sonarr_api_key', '')
    
    if sonarr_url and sonarr_key:
        try:
            response = requests.get(
                f"{sonarr_url}/api/v3/series",
                headers={'X-Api-Key': sonarr_key},
                timeout=30
            )
            if response.ok:
                for series in response.json():
                    tvdb_id = series.get('tvdbId')
                    path = series.get('path', '')
                    if tvdb_id and path:
                        # Extract folder name from path
                        folder_name = os.path.basename(path.rstrip('/'))
                        _arr_cache['sonarr_series'][str(tvdb_id)] = folder_name
                log(f"Refreshed Sonarr cache: {len(_arr_cache['sonarr_series'])} series")
        except Exception as e:
            log(f"Sonarr cache refresh error: {e}")
    
    # Refresh Radarr cache
    radarr_url = cfg.get('radarr_url', '').rstrip('/')
    radarr_key = cfg.get('radarr_api_key', '')
    
    if radarr_url and radarr_key:
        try:
            response = requests.get(
                f"{radarr_url}/api/v3/movie",
                headers={'X-Api-Key': radarr_key},
                timeout=30
            )
            if response.ok:
                for movie in response.json():
                    tmdb_id = movie.get('tmdbId')
                    imdb_id = movie.get('imdbId', '')
                    path = movie.get('path', '')
                    folder_name = movie.get('folderName', '')
                    
                    if not folder_name and path:
                        folder_name = os.path.basename(path.rstrip('/'))
                    
                    if folder_name:
                        if tmdb_id:
                            _arr_cache['radarr_movies'][f"tmdb_{tmdb_id}"] = folder_name
                        if imdb_id:
                            _arr_cache['radarr_movies'][f"imdb_{imdb_id}"] = folder_name
                log(f"Refreshed Radarr cache: {len(_arr_cache['radarr_movies'])} movies")
        except Exception as e:
            log(f"Radarr cache refresh error: {e}")
    
    _arr_cache['last_refresh'] = time.time()


def get_sonarr_series_folder(provider_ids, fallback_name):
    """Get series folder name from Sonarr (Pro feature)"""
    if not is_feature_available('arr_integration'):
        return None
    
    cfg = load_config()
    sonarr_url = cfg.get('sonarr_url', '').rstrip('/')
    sonarr_key = cfg.get('sonarr_api_key', '')
    
    if not sonarr_url or not sonarr_key:
        return None
    
    # Check cache first
    tvdb_id = provider_ids.get('Tvdb', '')
    if tvdb_id and str(tvdb_id) in _arr_cache['sonarr_series']:
        return _arr_cache['sonarr_series'][str(tvdb_id)]
    
    # If cache is stale (> 1 hour), refresh in background
    if not _arr_cache['last_refresh'] or (time.time() - _arr_cache['last_refresh']) > 3600:
        threading.Thread(target=refresh_arr_cache, daemon=True).start()
    
    # Try direct lookup by TVDB ID
    if tvdb_id:
        try:
            response = requests.get(
                f"{sonarr_url}/api/v3/series/lookup",
                headers={'X-Api-Key': sonarr_key},
                params={'term': f'tvdb:{tvdb_id}'},
                timeout=10
            )
            if response.ok:
                results = response.json()
                if results and len(results) > 0:
                    # Check if series exists in Sonarr
                    series = results[0]
                    path = series.get('path', '')
                    if path:
                        folder_name = os.path.basename(path.rstrip('/'))
                        _arr_cache['sonarr_series'][str(tvdb_id)] = folder_name
                        return folder_name
                    else:
                        # Series not in Sonarr but we have info - use title
                        title = series.get('title', '')
                        year = series.get('year', '')
                        if title:
                            if year:
                                folder_name = clean_name(f"{title} ({year})")
                            else:
                                folder_name = clean_name(title)
                            _arr_cache['sonarr_series'][str(tvdb_id)] = folder_name
                            return folder_name
        except Exception as e:
            log(f"Sonarr lookup error: {e}")
    
    return None


def get_radarr_movie_folder(provider_ids, fallback_name, year=''):
    """Get movie folder name from Radarr (Pro feature)"""
    if not is_feature_available('arr_integration'):
        return None
    
    cfg = load_config()
    radarr_url = cfg.get('radarr_url', '').rstrip('/')
    radarr_key = cfg.get('radarr_api_key', '')
    
    if not radarr_url or not radarr_key:
        return None
    
    # Check cache first
    tmdb_id = provider_ids.get('Tmdb', '')
    imdb_id = provider_ids.get('Imdb', '')
    
    if tmdb_id and f"tmdb_{tmdb_id}" in _arr_cache['radarr_movies']:
        return _arr_cache['radarr_movies'][f"tmdb_{tmdb_id}"]
    if imdb_id and f"imdb_{imdb_id}" in _arr_cache['radarr_movies']:
        return _arr_cache['radarr_movies'][f"imdb_{imdb_id}"]
    
    # If cache is stale (> 1 hour), refresh in background
    if not _arr_cache['last_refresh'] or (time.time() - _arr_cache['last_refresh']) > 3600:
        threading.Thread(target=refresh_arr_cache, daemon=True).start()
    
    # Try direct lookup
    lookup_term = None
    if tmdb_id:
        lookup_term = f'tmdb:{tmdb_id}'
    elif imdb_id:
        lookup_term = f'imdb:{imdb_id}'
    
    if lookup_term:
        try:
            response = requests.get(
                f"{radarr_url}/api/v3/movie/lookup",
                headers={'X-Api-Key': radarr_key},
                params={'term': lookup_term},
                timeout=10
            )
            if response.ok:
                results = response.json()
                if results and len(results) > 0:
                    movie = results[0]
                    
                    # If movie is in Radarr, use its folder
                    folder_name = movie.get('folderName', '')
                    path = movie.get('path', '')
                    
                    if not folder_name and path:
                        folder_name = os.path.basename(path.rstrip('/'))
                    
                    if folder_name:
                        if tmdb_id:
                            _arr_cache['radarr_movies'][f"tmdb_{tmdb_id}"] = folder_name
                        if imdb_id:
                            _arr_cache['radarr_movies'][f"imdb_{imdb_id}"] = folder_name
                        return folder_name
                    
                    # Movie not in Radarr - generate folder name from lookup data
                    title = movie.get('title', '')
                    movie_year = movie.get('year', year)
                    if title:
                        if movie_year:
                            folder_name = clean_name(f"{title} ({movie_year})")
                        else:
                            folder_name = clean_name(title)
                        if tmdb_id:
                            _arr_cache['radarr_movies'][f"tmdb_{tmdb_id}"] = folder_name
                        return folder_name
        except Exception as e:
            log(f"Radarr lookup error: {e}")
    
    return None


def recursive_resolve(server, item_id, base_path, tid, limit, download_order='library'):
    """Resolve item and queue downloads (handles series/seasons)"""
    global pending_display
    
    try:
        headers = get_auth_header(server['key'])
        
        # Use stored user_id if available (for username/password auth)
        user_id = server.get('user_id')
        log(f"Using user ID: {user_id}")
        log(f"Using headers: {list(headers.keys())}")
        
        if not user_id:
            # Try to get user_id from /Users endpoint (may fail with non-admin auth)
            try:
                users_resp = requests.get(
                    f"{server['url']}/Users",
                    headers=headers,
                    timeout=10
                )
                if users_resp.status_code == 200:
                    user_id = users_resp.json()[0]['Id']
                else:
                    log(f"Users endpoint returned {users_resp.status_code}, trying /Users/Me")
                    # Fallback: try /Users/Me endpoint
                    me_resp = requests.get(
                        f"{server['url']}/Users/Me",
                        headers=headers,
                        timeout=10
                    )
                    if me_resp.status_code == 200:
                        user_id = me_resp.json()['Id']
                    else:
                        raise Exception(f"Cannot get user ID: /Users returned {users_resp.status_code}, /Users/Me returned {me_resp.status_code}")
            except Exception as e:
                log(f"Error getting user ID: {e}")
                raise
        
        log(f"Fetching item {item_id} for user {user_id}")
        item_resp = requests.get(
            f"{server['url']}/Users/{user_id}/Items/{item_id}",
            headers=headers,
            timeout=15
        )
        
        if item_resp.status_code != 200:
            log(f"Item request failed: {item_resp.status_code} - {item_resp.text[:200]}")
            raise Exception(f"Item request returned {item_resp.status_code}")
        
        item = item_resp.json()
        
        log(f"Item details: Name={item.get('Name')}, Type={item.get('Type')}, Container={item.get('Container')}")
        
        container_types = ['Series', 'Season', 'BoxSet', 'Folder', 'CollectionFolder']
        
        if item['Type'] in container_types:
            children_resp = requests.get(
                f"{server['url']}/Users/{user_id}/Items",
                headers=headers,
                params={
                    'ParentId': item_id,
                    'Recursive': 'true',
                    'IncludeItemTypes': 'Movie,Episode',
                    'Fields': 'ProviderIds'
                },
                timeout=30
            )
            
            if children_resp.status_code != 200:
                log(f"Children request failed: {children_resp.status_code}")
                raise Exception(f"Children request returned {children_resp.status_code}")
            
            children = children_resp.json().get('Items', [])
            
            with download_lock:
                pending_display = [x for x in pending_display if x['id'] != tid]
            
            # Sort children based on download order
            children = sort_download_queue(children, download_order)
            
            for child in children:
                sub_tid = generate_id()
                queue_item(server, child, base_path, sub_tid, limit)
        else:
            queue_item(server, item, base_path, tid, limit)
            
    except Exception as e:
        log(f"Resolve Error: {e}")
        with download_lock:
            pending_display = [x for x in pending_display if x['id'] != tid]


def queue_item(server, item, base_path, tid, limit):
    """Queue a single item for download"""
    global pending_display
    try:
        safe_name = clean_name(item['Name'])
        ext = item.get('Container', 'mkv')
        
        log(f"Queueing item: {item['Name']} (Type: {item.get('Type', 'Unknown')}, Container: {ext})")
        
        # Get provider IDs for *arr lookup
        provider_ids = item.get('ProviderIds', {})
        
        if item['Type'] == 'Episode':
            series = clean_name(item.get('SeriesName', 'Unknown'))
            season_num = item.get('ParentIndexNumber', 1)
            episode_num = item.get('IndexNumber', 0)
            
            # Try to get folder name from Sonarr if configured
            arr_folder = get_sonarr_series_folder(provider_ids, series)
            if arr_folder:
                series_folder = arr_folder
            else:
                series_folder = series
            
            rel_path = os.path.join(series_folder, f"Season {season_num:02d}")
            filename = f"{series_folder} - S{season_num:02d}E{episode_num:02d} - {safe_name}.{ext}"
        elif item['Type'] == 'Movie':
            # Get year if available
            year = item.get('ProductionYear', '')
            
            # Try to get folder name from Radarr if configured
            arr_folder = get_radarr_movie_folder(provider_ids, safe_name, year)
            if arr_folder:
                folder_name = arr_folder
            elif year:
                folder_name = f"{safe_name} ({year})"
            else:
                folder_name = safe_name
            
            rel_path = folder_name
            filename = f"{folder_name}.{ext}"
        else:
            # Other media types (music, etc)
            rel_path = ""
            filename = f"{safe_name}.{ext}"
        
        full_dir = os.path.join(base_path, rel_path)
        os.makedirs(full_dir, exist_ok=True)
        
        filepath = os.path.join(full_dir, filename)
        
        if os.path.exists(filepath):
            log(f"Skipped (exists): {filename}")
            with download_lock:
                pending_display = [x for x in pending_display if x['id'] != tid]
            return
        
        with download_lock:
            if any(p['name'] == filename for p in pending_display):
                return
            if any(d['filename'] == filename for d in active_downloads.values()):
                return
            
            for p in pending_display:
                if p['id'] == tid:
                    p['name'] = filename
                    break
            else:
                pending_display.append({"name": filename, "id": tid})
        
        task_queue.put({
            'url': f"{server['url']}/Items/{item['Id']}/Download",
            'filepath': filepath,
            'task_id': tid,
            'limit': limit,
            'headers': get_auth_header(server['key']),
            'server': server,  # For subtitle download
            'item_id': item['Id']  # For subtitle download
        })
        
    except Exception as e:
        log(f"Queue Error: {e}")


def is_safe_path(base_path, target_path):
    """Check if target_path is safely within base_path (prevent path traversal)"""
    # Resolve both paths to absolute paths
    base_resolved = os.path.realpath(base_path)
    target_resolved = os.path.realpath(target_path)
    # Check if target starts with base (is inside base directory)
    return target_resolved.startswith(base_resolved)


@app.route('/api/browse_local', methods=['POST'])
@login_required
def browse_local():
    """Browse local filesystem for destination selection (with path traversal protection)"""
    path = request.json.get('path', '/storage')
    
    # Security: Validate path is within allowed directories
    allowed_bases = ['/storage', '/mnt']
    
    # Clean the path
    path = os.path.normpath(path)
    
    # Check for path traversal attempts
    if '..' in path:
        log(f"Path traversal blocked: {path}")
        return jsonify({"error": "Invalid path", "folders": [], "current": "/storage"})
    
    # Verify path starts with allowed base
    if not any(path.startswith(base) for base in allowed_bases):
        path = '/storage'
    
    # Double-check with realpath
    if not any(is_safe_path(base, path) for base in allowed_bases):
        log(f"Path traversal blocked (realpath): {path}")
        return jsonify({"error": "Invalid path", "folders": [], "current": "/storage"})
    
    try:
        folders = sorted([
            entry.name for entry in os.scandir(path)
            if entry.is_dir() and not entry.name.startswith('.')
        ])
        
        try:
            stat = shutil.disk_usage(path)
            space_info = {
                "free": format_bytes(stat.free),
                "total": format_bytes(stat.total),
                "percent_used": int((stat.used / stat.total) * 100)
            }
        except Exception:
            space_info = None
        
        return jsonify({
            "current": path,
            "folders": folders,
            "parent": os.path.dirname(path) if path != '/storage' else None,
            "space": space_info
        })
    except Exception as e:
        return jsonify({
            "error": str(e),
            "folders": [],
            "current": path
        })


@app.route('/api/sync', methods=['POST'])
@login_required
def trigger_sync():
    threading.Thread(target=sync_job, daemon=True).start()
    return jsonify({"status": "started"})


def sync_job():
    """Run sync for all configured mappings"""
    cfg = load_config()
    
    if not cfg.get('auto_sync_enabled', True):
        log("Sync skipped: Auto-sync disabled")
        return
    
    log("─── Sync Started ───")
    load_cache_from_disk()
    
    download_order = cfg.get('download_order', 'library')
    
    for mapping in cfg['mappings']:
        server = next(
            (s for s in cfg['servers'] if s['id'] == mapping['server_id']),
            None
        )
        if not server:
            continue
        
        try:
            headers = get_auth_header(server['key'])
            
            # Use stored user_id if available (for username/password auth)
            user_id = server.get('user_id')
            
            if not user_id:
                user_id = requests.get(
                    f"{server['url']}/Users",
                    headers=headers,
                    timeout=10
                ).json()[0]['Id']
            
            items = requests.get(
                f"{server['url']}/Users/{user_id}/Items",
                headers=headers,
                params={
                    'ParentId': mapping['lib_id'],
                    'Recursive': 'true',
                    'IncludeItemTypes': 'Movie,Episode',
                    'Fields': 'ProviderIds'
                }
            ).json().get('Items', [])
            
            # Filter out items we already have
            items_to_queue = []
            for item in items:
                if local_id_cache:
                    providers = item.get('ProviderIds', {})
                    imdb_key = f"imdb_{providers.get('Imdb')}"
                    tmdb_key = f"tmdb_{providers.get('Tmdb')}"
                    if imdb_key in local_id_cache or tmdb_key in local_id_cache:
                        continue
                items_to_queue.append(item)
            
            # Sort based on download order
            items_to_queue = sort_download_queue(items_to_queue, download_order)
            
            queued = 0
            for item in items_to_queue:
                tid = generate_id()
                queue_item(server, item, mapping['local_path'], tid, cfg.get('speed_limit_kbs', 0))
                queued += 1
            
            log(f"Sync: Queued {queued} items from {server['name']}")
            
        except Exception as e:
            log(f"Sync Error ({server['name']}): {e}")
    
    log("─── Sync Finished ───")


# --- Application Startup ---

# --- *arr Integration (Pro) ---

def test_arr_connection(arr_type, url, api_key):
    """Test connection to Sonarr/Radarr/Lidarr"""
    if not url or not api_key:
        return {'success': False, 'error': 'URL and API key required'}
    
    try:
        response = requests.get(
            f"{url.rstrip('/')}/api/v3/system/status",
            headers={'X-Api-Key': api_key},
            timeout=10
        )
        if response.ok:
            data = response.json()
            return {
                'success': True,
                'version': data.get('version', 'Unknown'),
                'name': data.get('instanceName', arr_type.capitalize())
            }
        return {'success': False, 'error': f"HTTP {response.status_code}"}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def notify_arr_download(filepath, arr_type):
    """Notify *arr app about downloaded file"""
    if not is_feature_available('arr_integration'):
        return
    
    cfg = load_config()
    
    if arr_type == 'sonarr':
        url = cfg.get('sonarr_url')
        api_key = cfg.get('sonarr_api_key')
    elif arr_type == 'radarr':
        url = cfg.get('radarr_url')
        api_key = cfg.get('radarr_api_key')
    elif arr_type == 'lidarr':
        url = cfg.get('lidarr_url')
        api_key = cfg.get('lidarr_api_key')
    else:
        return
    
    if not url or not api_key:
        return
    
    try:
        # Trigger library scan
        requests.post(
            f"{url.rstrip('/')}/api/v3/command",
            headers={'X-Api-Key': api_key, 'Content-Type': 'application/json'},
            json={'name': 'RescanSeries' if arr_type == 'sonarr' else 'RescanMovie'},
            timeout=10
        )
        log(f"📡 Notified {arr_type.capitalize()} about: {os.path.basename(filepath)}")
    except Exception as e:
        log(f"✗ Failed to notify {arr_type}: {e}")


@app.route('/api/test_arr', methods=['POST'])
@login_required
def api_test_arr():
    """Test *arr connection"""
    if not is_feature_available('arr_integration'):
        return jsonify({'success': False, 'error': 'Pro feature - upgrade to unlock'})
    
    data = request.json
    arr_type = data.get('type', 'sonarr')
    url = data.get('url', '').strip()
    api_key = data.get('api_key', '').strip()
    
    result = test_arr_connection(arr_type, url, api_key)
    return jsonify(result)


@app.route('/api/refresh_arr_cache', methods=['POST'])
@login_required
def api_refresh_arr_cache():
    """Manually refresh *arr folder cache (Pro feature)"""
    if not is_feature_available('arr_integration'):
        return jsonify({'success': False, 'error': 'Pro feature - upgrade to unlock'})
    
    # Run refresh in background
    threading.Thread(target=refresh_arr_cache, daemon=True).start()
    
    return jsonify({
        'success': True,
        'message': 'Refreshing *arr cache in background',
        'cached_series': len(_arr_cache.get('sonarr_series', {})),
        'cached_movies': len(_arr_cache.get('radarr_movies', {}))
    })


@app.route('/api/arr_cache_status')
@login_required
def api_arr_cache_status():
    """Get *arr cache status"""
    last_refresh = _arr_cache.get('last_refresh')
    return jsonify({
        'sonarr_series_count': len(_arr_cache.get('sonarr_series', {})),
        'radarr_movies_count': len(_arr_cache.get('radarr_movies', {})),
        'last_refresh': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_refresh)) if last_refresh else None
    })


# --- Analytics (Pro) ---

@app.route('/api/analytics')
@login_required
def api_analytics():
    """Get download analytics (Pro feature)"""
    if not is_feature_available('analytics'):
        return jsonify({'error': 'Pro feature - upgrade to unlock'})
    
    with download_lock:
        history_list = list(download_history)
    
    # Calculate stats
    total_downloads = len(history_list)
    total_size = sum(h.get('size', 0) for h in history_list)
    
    # Group by date
    by_date = {}
    for h in history_list:
        date = h.get('timestamp', '')[:10]
        if date not in by_date:
            by_date[date] = {'count': 0, 'size': 0}
        by_date[date]['count'] += 1
        by_date[date]['size'] += h.get('size', 0)
    
    return jsonify({
        'total_downloads': total_downloads,
        'total_size': total_size,
        'total_size_formatted': format_bytes(total_size),
        'by_date': by_date,
        'recent': history_list[:20]
    })


# --- Download Scheduling (Pro) ---

def is_within_schedule():
    """Check if current time is within download schedule"""
    cfg = load_config()
    
    if not cfg.get('download_schedule_enabled', False):
        return True  # No schedule = always allowed
    
    if not is_feature_available('scheduling'):
        return True  # Free tier = no scheduling
    
    now = datetime.datetime.now()
    current_time = now.strftime('%H:%M')
    
    start_time = cfg.get('download_schedule_start', '02:00')
    end_time = cfg.get('download_schedule_end', '06:00')
    
    # Handle overnight schedules (e.g., 22:00 - 06:00)
    if start_time <= end_time:
        return start_time <= current_time <= end_time
    else:
        return current_time >= start_time or current_time <= end_time


def get_scheduled_speed_limit():
    """Get speed limit based on time of day"""
    cfg = load_config()
    
    if not cfg.get('bandwidth_schedule_enabled', False):
        return cfg.get('speed_limit_kbs', 0)
    
    if not is_feature_available('scheduling'):
        return cfg.get('speed_limit_kbs', 0)
    
    now = datetime.datetime.now()
    current_time = now.strftime('%H:%M')
    
    night_start = cfg.get('bandwidth_night_start', '22:00')
    night_end = cfg.get('bandwidth_night_end', '06:00')
    
    # Check if it's "night" time
    if night_start <= night_end:
        is_night = night_start <= current_time <= night_end
    else:
        is_night = current_time >= night_start or current_time <= night_end
    
    if is_night:
        return cfg.get('bandwidth_night_limit_kbs', 0)
    else:
        return cfg.get('bandwidth_day_limit_kbs', 1000)


# --- Stop After Current Downloads ---

stop_after_current = False

@app.route('/api/stop_after_current', methods=['POST'])
@login_required
def api_stop_after_current():
    """Stop starting new downloads after current ones complete"""
    global stop_after_current
    stop_after_current = True
    log("🛑 Will stop after current downloads complete")
    return jsonify({'status': 'ok', 'stop_after_current': True})


@app.route('/api/cancel_stop_after_current', methods=['POST'])
@login_required  
def api_cancel_stop_after_current():
    """Cancel stop after current"""
    global stop_after_current
    stop_after_current = False
    log("▶️ Cancelled stop-after-current")
    return jsonify({'status': 'ok', 'stop_after_current': False})


# --- Last Location Memory ---

@app.route('/api/save_location', methods=['POST'])
@login_required
def api_save_location():
    """Save last browsed location for a server"""
    data = request.json
    server_id = data.get('server_id')
    location_id = data.get('location_id')
    location_name = data.get('location_name', '')
    
    if not server_id:
        return jsonify({'error': 'Server ID required'})
    
    cfg = load_config()
    if 'last_locations' not in cfg:
        cfg['last_locations'] = {}
    
    cfg['last_locations'][server_id] = {
        'id': location_id,
        'name': location_name,
        'timestamp': time.time()
    }
    save_config(cfg)
    
    return jsonify({'status': 'ok'})


@app.route('/api/get_location/<server_id>')
@login_required
def api_get_location(server_id):
    """Get last browsed location for a server"""
    cfg = load_config()
    location = cfg.get('last_locations', {}).get(server_id)
    return jsonify(location or {})


def init_app():
    """Initialize application"""
    global app
    
    # Load or generate secret key
    cfg = load_config()
    if cfg.get('auth_enabled', False):
        auth = load_auth()
        if auth and 'secret_key' in auth:
            app.secret_key = auth['secret_key']
        else:
            secret = secrets.token_hex(32)
            if auth:
                auth['secret_key'] = secret
                save_auth(auth)
            app.secret_key = secret
    else:
        # Auth disabled - use a session secret anyway for flash messages etc
        app.secret_key = secrets.token_hex(32)


if __name__ == '__main__':
    init_app()
    load_cache_from_disk()
    load_download_history()  # Load persistent download stats
    
    # Track uptime for health checks
    app.start_time = time.time()
    
    # Clean up old partial downloads (Pro feature)
    cleanup_old_partials(max_age_days=7)
    
    cfg = load_config()
    num_workers = cfg.get('max_concurrent_downloads', 2)
    adjust_workers(num_workers)
    
    setup_schedule()
    threading.Thread(target=schedule_runner, daemon=True).start()
    
    log(f"JellyLooter v{VERSION} started")
    log(f"Workers: {active_workers}, Speed limit: {cfg.get('speed_limit_kbs', 0)} KB/s")
    log(f"Auth: {'Enabled' if cfg.get('auth_enabled', False) else 'Disabled'}")
    app.run(host='0.0.0.0', port=5000, threaded=True)
