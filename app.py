import os
import sqlite3
import secrets
from flask import Flask, render_template_string, request, redirect, url_for, jsonify, session, send_from_directory
from datetime import datetime
from flask_socketio import SocketIO, emit, join_room, leave_room
import re
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import uuid
from werkzeug.utils import secure_filename
import threading
import time
from functools import wraps
import logging

# Performance optimization
logging.basicConfig(level=logging.WARNING)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'exomnia-fixed-secret-key-2024')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
VOICE_UPLOAD_FOLDER = os.path.join('uploads', 'voice')
os.makedirs(VOICE_UPLOAD_FOLDER, exist_ok=True)
ALLOWED_AUDIO_EXTENSIONS = {'webm', 'ogg', 'wav', 'mp3', 'm4a', 'aac'}
MAX_VOICE_FILE_SIZE = 10 * 1024 * 1024

# Performance optimizations for SocketIO
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='eventlet',
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=16 * 1024 * 1024,
    logger=False,
    engineio_logger=False,
    allow_upgrades=True,
    transports=['polling', 'websocket'],
)

DB_NAME = "chat.db"

# Connection pool for database
def _configure_conn(conn):
    """Apply performance PRAGMAs to a new SQLite connection."""
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-16000")       # 16 MB page cache
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA mmap_size=134217728")     # 128 MB memory-mapped I/O
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

class ConnectionPool:
    def __init__(self, max_connections=20):
        self.max_connections = max_connections
        self.connections = []
        self.lock = threading.Lock()
    
    def get_connection(self):
        with self.lock:
            if self.connections:
                return self.connections.pop()
            else:
                return _configure_conn(
                    sqlite3.connect(DB_NAME, timeout=20, check_same_thread=False)
                )
    
    def return_connection(self, conn):
        with self.lock:
            if len(self.connections) < self.max_connections:
                self.connections.append(conn)
            else:
                conn.close()

connection_pool = ConnectionPool()

def get_db_connection():
    return connection_pool.get_connection()

def return_db_connection(conn):
    connection_pool.return_connection(conn)

# Rate limiting
from collections import defaultdict

rate_limits = defaultdict(list)

def rate_limit(limit=10, window=60):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            now = time.time()
            user_id = request.remote_addr
            rate_limits[user_id] = [t for t in rate_limits[user_id] if now - t < window]
            if len(rate_limits[user_id]) >= limit:
                return jsonify({'error': 'Rate limit exceeded'}), 429
            rate_limits[user_id].append(now)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'image': ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'],
    'video': ['mp4', 'mov', 'avi', 'mkv', 'webm'],
    'document': ['pdf', 'doc', 'docx', 'txt', 'ppt', 'pptx', 'xls', 'xlsx']
}

def allowed_file(filename, file_type='image'):
    """Check if file extension is allowed"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS.get(file_type, [])

def get_file_type(filename):
    """Determine file type from extension"""
    if '.' not in filename:
        return 'document'
    ext = filename.rsplit('.', 1)[1].lower()
    
    for file_type, extensions in ALLOWED_EXTENSIONS.items():
        if ext in extensions:
            return file_type
    return 'document'

# ----------------- Enhanced Cache System -----------------
class EnhancedCache:
    def __init__(self, ttl=300):
        self.cache = {}
        self.ttl = ttl
        self.lock = threading.Lock()
    
    def get(self, key):
        with self.lock:
            if key in self.cache:
                data, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl:
                    return data
                else:
                    del self.cache[key]
        return None
    
    def set(self, key, value):
        with self.lock:
            self.cache[key] = (value, time.time())
    
    def delete(self, key):
        with self.lock:
            if key in self.cache:
                del self.cache[key]
    
    def clear_pattern(self, pattern):
        """Clear all keys matching pattern"""
        with self.lock:
            keys_to_delete = [key for key in self.cache if pattern in key]
            for key in keys_to_delete:
                del self.cache[key]
    
    def clear_for_users(self, user1, user2):
        """Clear all cache for two users"""
        with self.lock:
            keys_to_delete = []
            for key in self.cache:
                if (user1 in key) or (user2 in key):
                    keys_to_delete.append(key)
            for key in keys_to_delete:
                del self.cache[key]

cache = EnhancedCache(ttl=60)  # 60-second cache — safe since we invalidate on every write

# ----------------- Encryption Setup -----------------
class MessageEncryptor:
    def __init__(self):
        self.master_key = self._derive_master_key()
        self._key_cache = {}  # cache derived keys — PBKDF2 is slow

    def _derive_master_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'exomnia_salt_2024',
            iterations=100000,
        )
        return kdf.derive(app.config['SECRET_KEY'].encode())

    def generate_user_key(self, phone_number):
        if phone_number in self._key_cache:
            return self._key_cache[phone_number]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=phone_number.encode(),
            iterations=100000,
        )
        key = kdf.derive(self.master_key)
        self._key_cache[phone_number] = key
        return key

    def _conversation_key(self, phone_a, phone_b):
        """Always produce the same key regardless of who is sender/receiver."""
        p1, p2 = sorted([phone_a, phone_b])
        k1 = self.generate_user_key(p1)
        k2 = self.generate_user_key(p2)
        return hashlib.sha256(k1 + k2).digest()

    def encrypt_message(self, message, sender_phone, receiver_phone):
        try:
            conversation_key = self._conversation_key(sender_phone, receiver_phone)
            nonce = os.urandom(12)
            aesgcm = AESGCM(conversation_key)
            encrypted_data = aesgcm.encrypt(nonce, message.encode(), None)
            return base64.b64encode(nonce + encrypted_data).decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def decrypt_message(self, encrypted_message, sender_phone, receiver_phone):
        # Attempt 1: current sorted key (correct method)
        try:
            conversation_key = self._conversation_key(sender_phone, receiver_phone)
            raw = base64.b64decode(encrypted_message.encode('utf-8'))
            nonce, ciphertext = raw[:12], raw[12:]
            return AESGCM(conversation_key).decrypt(nonce, ciphertext, None).decode('utf-8')
        except Exception:
            pass
        # Attempt 2: old key order — sender first (pre-fix messages)
        try:
            k1 = self.generate_user_key(sender_phone)
            k2 = self.generate_user_key(receiver_phone)
            old_key = hashlib.sha256(k1 + k2).digest()
            raw = base64.b64decode(encrypted_message.encode('utf-8'))
            nonce, ciphertext = raw[:12], raw[12:]
            return AESGCM(old_key).decrypt(nonce, ciphertext, None).decode('utf-8')
        except Exception:
            pass
        # Attempt 3: old key order — receiver first (pre-fix messages, flipped)
        try:
            k1 = self.generate_user_key(receiver_phone)
            k2 = self.generate_user_key(sender_phone)
            old_key = hashlib.sha256(k1 + k2).digest()
            raw = base64.b64decode(encrypted_message.encode('utf-8'))
            nonce, ciphertext = raw[:12], raw[12:]
            return AESGCM(old_key).decrypt(nonce, ciphertext, None).decode('utf-8')
        except Exception:
            pass
        # All attempts failed — return None so caller can fall back to stored plaintext
        return None

# Initialize encryptor
encryptor = MessageEncryptor()

# ----------------- Database Setup -----------------
def init_db():
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                phone TEXT PRIMARY KEY,
                last_online TEXT,
                public_key TEXT,
                encryption_version INTEGER DEFAULT 1
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                user_phone TEXT,
                contact_phone TEXT,
                contact_name TEXT,
                last_message TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(user_phone, contact_phone)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                receiver TEXT,
                message TEXT,
                encrypted_message TEXT,
                status TEXT DEFAULT 'sent',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                encryption_version INTEGER DEFAULT 1,
                message_type TEXT DEFAULT 'text',
                file_path TEXT,
                file_name TEXT,
                file_size INTEGER,
                thumbnail_path TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_users ON messages(sender, receiver)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_contacts_user ON contacts(user_phone)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(message_type)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(sender, receiver, timestamp)")
        c.execute("""
            CREATE TABLE IF NOT EXISTS message_reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER,
                user_phone TEXT,
                emoji TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(message_id, user_phone)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_by TEXT NOT NULL,
                avatar_letter TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER,
                user_phone TEXT,
                role TEXT DEFAULT 'member',
                joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(group_id, user_phone),
                FOREIGN KEY(group_id) REFERENCES groups(id)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS group_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER,
                sender TEXT,
                message TEXT,
                message_type TEXT DEFAULT 'text',
                file_path TEXT,
                file_name TEXT,
                file_size INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(group_id) REFERENCES groups(id)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_group_messages ON group_messages(group_id, timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_group_members ON group_members(user_phone)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_reactions_msg ON message_reactions(message_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_contacts_timestamp ON contacts(user_phone, timestamp DESC)")
        c.execute("""
            CREATE TABLE IF NOT EXISTS voice_messages (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                sender        TEXT    NOT NULL,
                receiver      TEXT,
                group_id      INTEGER,
                file_path     TEXT    NOT NULL,
                file_name     TEXT    NOT NULL,
                file_size     INTEGER NOT NULL,
                duration_ms   INTEGER DEFAULT 0,
                waveform_data TEXT,
                status        TEXT    DEFAULT 'sent',
                timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP,
                listened_at   DATETIME,
                FOREIGN KEY(group_id) REFERENCES groups(id)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_voice_dm ON voice_messages(sender, receiver, timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_voice_group ON voice_messages(group_id, timestamp)")
        conn.commit()
    finally:
        return_db_connection(conn)

def validate_phone(phone):
    pattern = r'^\+\d{1,4}\d{6,14}$'
    return re.match(pattern, phone) is not None

# ----------------- Typing Status -----------------
typing_status = {}

# ----------------- Main Super App Template -----------------
main_app_html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Exomnia Super App</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * {margin: 0; padding: 0; box-sizing: border-box;}
    html {
      height: 100%;
      height: -webkit-fill-available;
    }

    body {
      font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      background: #eef6f6;
      height: 100vh;
      height: 100dvh;
      min-height: -webkit-fill-available;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }

    #main-content {
      flex: 1;
      background: #eef6f6;
      padding: 15px;
      overflow-y: auto;
      transition: 0.3s ease;
      padding-bottom: calc(75px + env(safe-area-inset-bottom, 0px));
    }

    .bottom-nav {
      display: flex;
      justify-content: space-around;
      background: #fff;
      padding: 10px 0 calc(12px + env(safe-area-inset-bottom, 0px));
      color: #0E4950;
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      width: 100%;
      box-shadow: 0 -2px 20px rgba(14,73,80,0.10);
      z-index: 1000;
      border-top: 1px solid #daeaea;
    }

    .tab {
      text-align: center;
      flex: 1;
      cursor: pointer;
      padding: 6px 4px;
      color: #7aabae;
      font-weight: 600;
      font-size: 11px;
      transition: all 0.2s;
      border-radius: 12px;
      margin: 0 4px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 3px;
    }

    .tab.active {
      background: #0E4950;
      color: #fff;
      border-radius: 12px;
      box-shadow: 0 4px 14px rgba(14,73,80,0.25);
    }

    .placeholder-content {
      background: white;
      padding: 24px 20px;
      border-radius: 18px;
      margin-top: 10px;
      text-align: center;
      border: 1px solid #daeaea;
      box-shadow: 0 2px 12px rgba(14,73,80,0.06);
    }

    /* Add Contact Modal Styles */
    .modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.5);
      backdrop-filter: blur(5px);
      z-index: 1000;
      align-items: center;
      justify-content: center;
    }
    .modal-content {
      background: white;
      padding: 25px;
      border-radius: 20px;
      width: 90%;
      max-width: 400px;
      box-shadow: 0 20px 40px rgba(0,0,0,0.3);
      animation: modalSlide 0.3s ease;
    }
    @keyframes modalSlide {
      from { transform: translateY(-50px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }
    .modal h3 {
      margin-bottom: 20px;
      color: #333;
      text-align: center;
    }
    .form-group {
      margin-bottom: 15px;
    }
    .form-group label {
      display: block;
      margin-bottom: 5px;
      color: #666;
      font-weight: 500;
    }
    .form-control {
      width: 100%;
      padding: 12px 15px;
      border: 2px solid #e1e1e1;
      border-radius: 10px;
      font-size: 16px;
      transition: all 0.3s ease;
    }
    .form-control:focus {
      border-color: #0E4950;
      box-shadow: 0 0 0 3px rgba(14, 73, 80, 0.1);
    }
    .button-group {
      display: flex;
      gap: 10px;
      margin-top: 20px;
    }
    .btn {
      flex: 1;
      padding: 12px;
      border: none;
      border-radius: 10px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s ease;
    }
    .btn-primary {
      background: #0E4950;
      color: white;
    }
    .btn-primary:hover {
      background: #0a363a;
      transform: translateY(-2px);
      box-shadow: 0 4px 15px rgba(0,0,0,0.2);
    }
    .btn-secondary {
      background: #f8f9fa;
      color: #666;
    }
    .btn-secondary:hover {
      background: #e9ecef;
      transform: translateY(-2px);
      box-shadow: 0 4px 15px rgba(0,0,0,0.2);
    }

    .loading {
      opacity: 0.7;
      pointer-events: none;
    }

    /* Search Bar Styles */
    .search-container {
      display: flex;
      gap: 10px;
      margin-bottom: 15px;
      align-items: center;
    }
    .search-input {
      flex: 1;
      padding: 10px 15px;
      border: 2px solid #e1e1e1;
      border-radius: 10px;
      font-size: 14px;
      background: white;
      transition: all 0.3s ease;
    }
    .search-input:focus {
      border-color: #0E4950;
      box-shadow: 0 0 0 3px rgba(14, 73, 80, 0.1);
    }
    .search-input::placeholder {
      color: #999;
    }
    .no-contacts-found {
      text-align: center;
      padding: 20px;
      color: #666;
      font-style: italic;
    }
  </style>
</head>
<body>

  <div id="main-content">
    <!-- Content will be loaded here based on active tab -->
  </div>

  <div class="bottom-nav">
    <div class="tab active" onclick="openTab('chat', this)">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
      <span>Chat</span>
    </div>
    <div class="tab" onclick="openTab('social', this)">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
      <span>Social</span>
    </div>
    <div class="tab" onclick="openTab('video', this)">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>
      <span>Video</span>
    </div>
    <div class="tab" onclick="openTab('market', this)">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="21" r="1"/><circle cx="20" cy="21" r="1"/><path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"/></svg>
      <span>Market</span>
    </div>
  </div>

  <!-- Add Contact Modal -->
  <div id="contactModal" class="modal">
    <div class="modal-content">
      <h3>Add New Contact</h3>
      <form id="contactForm">
        <input type="hidden" name="user" id="userPhone">
        <div class="form-group">
          <label>Country Code</label>
          <select name="country_code" class="form-control" required>
            <option value="+91"> India (+91)</option>
            <option value="+1"> USA (+1)</option>
            <option value="+44">UK (+44)</option>
          </select>
        </div>
        <div class="form-group">
          <label>Phone Number</label>
          <input type="text" name="contact_phone" class="form-control"
                 placeholder="Enter phone number" required>
        </div>
        <div class="form-group">
          <label>Contact Name</label>
          <input type="text" name="contact_name" class="form-control"
                 placeholder="Enter full name" required>
        </div>
        <div class="button-group">
          <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
          <button type="submit" class="btn btn-primary" id="saveBtn">Save Contact</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    let allContacts = []; // Store all contacts for search functionality

    function openTab(tabName, element) {
      // Remove active class from all tabs
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));

      // Add active class to clicked tab
      if (element) {
        element.classList.add('active');
      } else {
        // If no element provided, find and activate chat tab
        document.querySelector('.tab[onclick*="chat"]').classList.add('active');
      }

      let content = document.getElementById('main-content');
      const isLoggedIn = localStorage.getItem('exomnia_user_phone');

      if (tabName === 'chat') {
        if (isLoggedIn) {
          // User is logged in - load contacts
          loadContacts(isLoggedIn);
        } else {
          content.innerHTML = `
            <h2> Chat</h2>
            <div class="placeholder-content">
              <p>Please login to access the chat feature</p>
              <button onclick="openChatLogin()" style="background: #0E4950; color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; margin-top: 10px;">
                Login to Chat
              </button>
            </div>
          `;
        }
      }
      else if (tabName === 'social') {
        content.innerHTML = `
          <h2> Social</h2>
          <div class="placeholder-content">
            <p style="text-align: center; color: #666; font-style: italic;">
              Social feed system coming soon...<br>
              Connect with friends and share moments.
            </p>
          </div>
        `;
      }
      else if (tabName === 'video') {
        content.innerHTML = `
          <h2>VideoStream</h2>
          <div class="placeholder-content">
            <p style="text-align: center; color: #666; font-style: italic;">
              Video streaming platform coming soon...<br>
              Watch and share videos with the community.
            </p>
          </div>
        `;
      }
      else if (tabName === 'market') {
        content.innerHTML = `
          <h2>Market</h2>
          <div class="placeholder-content">
            <p style="text-align: center; color: #666; font-style: italic;">
              E-commerce marketplace coming soon...<br>
              Buy and sell products securely.
            </p>
          </div>
        `;
      }
    }

    function openChatLogin() {
      window.location.href = '/';
    }

    function loadContacts(phone) {
      fetch(`/api/contacts?phone=${encodeURIComponent(phone)}`)
        .then(response => response.json())
        .then(contacts => {
          allContacts = contacts; // Store contacts for search functionality
          renderContacts(contacts);
        })
        .catch(error => {
          console.error('Error loading contacts:', error);
          let content = document.getElementById('main-content');
          content.innerHTML = `
            <h2>Chat</h2>
            <div class="placeholder-content">
              <p style="color: red;">Failed to load contacts. Please try again.</p>
            </div>
          `;
        });
    }

    function renderContacts(contacts) {
      let content = document.getElementById('main-content');

      if (contacts.length === 0) {
        content.innerHTML = `
          <h2 style="color: #0E4950; margin-bottom: 15px;"> Chat</h2>
          <div class="placeholder-content">
            <div style="font-size: 40px; margin-bottom: 12px;"></div>
            <h3 style="font-size: 18px; margin-bottom: 8px; color: #333;">No contacts yet</h3>
            <p style="font-size: 14px; color: #666;">Add someone to start chatting!</p>
            <button onclick="addNewContact()" style="background: #0E4950; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; margin-top: 15px; font-weight: bold;">
              + Add Contact
            </button>
          </div>
        `;
      } else {
        let contactsHTML = `
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
            <h2 style="color: #0E4950; margin: 0;">Contacts</h2>
            <div style="display:flex;gap:8px;">
              <button onclick="openCreateGroupModal()" style="background: #2ec4b6; color: white; border: none; padding: 8px 14px; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 700; display:flex; align-items:center; gap:5px;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/></svg>
                Group
              </button>
              <button onclick="addNewContact()" style="background: #0E4950; color: white; border: none; padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: bold;">
                + Add
              </button>
            </div>
          </div>
          <div class="search-container">
            <input type="text" id="searchInput" class="search-input" placeholder="Search contacts by name or phone..." onkeyup="filterContacts()">
          </div>
          <div id="contactsList" style="display: flex; flex-direction: column; gap: 10px;">
        `;

        contacts.forEach(contact => {
          contactsHTML += generateContactHTML(contact);
        });

        contactsHTML += `</div>`;

        // Load groups section below contacts
        const phone = localStorage.getItem('exomnia_user_phone');
        fetch('/api/groups?phone=' + encodeURIComponent(phone))
          .then(r => r.json())
          .then(groups => {
            if (groups.length > 0) {
              let groupsHTML = `
                <div style="margin-top:20px;">
                  <h3 style="color:#0E4950;font-size:15px;font-weight:700;margin-bottom:10px;">Groups</h3>
                  <div style="display:flex;flex-direction:column;gap:10px;">
              `;
              groups.forEach(g => { groupsHTML += generateGroupHTML(g); });
              groupsHTML += `</div></div>`;
              contactsHTML += groupsHTML;
            }
            content.innerHTML = contactsHTML;
          })
          .catch(() => { content.innerHTML = contactsHTML; });
      }
    }

    function generateGroupHTML(group) {
      const phone = localStorage.getItem('exomnia_user_phone');
      const letter = group.avatar_letter || group.name[0].toUpperCase();
      const memberCount = group.member_count || 0;
      return `
        <a href="/group/${group.id}?phone=${encodeURIComponent(phone)}" style="text-decoration:none;color:inherit;">
          <div style="background:white;padding:14px 16px;border-radius:18px;display:flex;align-items:center;gap:13px;box-shadow:0 2px 12px rgba(14,73,80,0.07);border:1px solid #daeaea;">
            <div style="width:48px;height:48px;border-radius:14px;background:linear-gradient(135deg,#2ec4b6,#0E4950);display:flex;align-items:center;justify-content:center;color:white;font-weight:700;font-size:19px;flex-shrink:0;">
              ${letter}
            </div>
            <div style="flex:1;min-width:0;">
              <div style="font-weight:700;color:#1a2e2f;font-size:15px;margin-bottom:2px;">${group.name}</div>
              <div style="color:#8aa3a5;font-size:12px;">${memberCount} member${memberCount !== 1 ? 's' : ''}</div>
              <div style="color:#9bb5b7;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${group.last_message || 'No messages yet'}</div>
            </div>
            <div style="color:#ccd8d8;flex-shrink:0;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg></div>
          </div>
        </a>
      `;
    }

    function generateContactHTML(contact) {
      const initial = contact.contact_name ? contact.contact_name[0].toUpperCase() : contact.contact_phone[0];
      const displayName = contact.contact_name || contact.contact_phone;
      const lastMsg = contact.last_message || 'No messages yet';
      const phone = localStorage.getItem('exomnia_user_phone');

      return `
        <a href="/chat/${encodeURIComponent(contact.contact_phone)}?phone=${encodeURIComponent(phone)}"
           style="text-decoration: none; color: inherit;">
          <div style="background: white; padding: 14px 16px; border-radius: 18px; display: flex; align-items: center; gap: 13px; box-shadow: 0 2px 12px rgba(14,73,80,0.07); transition: all 0.25s ease; border: 1px solid #daeaea;">
            <div style="width: 48px; height: 48px; border-radius: 50%; background: linear-gradient(135deg, #0E4950, #2ec4b6); display: flex; align-items: center; justify-content: center; color: white; font-weight: 700; font-size: 19px; flex-shrink: 0; box-shadow: 0 2px 8px rgba(14,73,80,0.2);">
              ${initial}
            </div>
            <div style="flex: 1; min-width: 0;">
              <div style="font-weight: 700; color: #1a2e2f; font-size: 15px; margin-bottom: 1px; letter-spacing: -0.01em;">${displayName}</div>
              <div style="color: #8aa3a5; font-size: 12px; margin-bottom: 2px;">${contact.contact_phone}</div>
              <div style="color: #9bb5b7; font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${lastMsg}</div>
            </div>
            <div style="color: #ccd8d8; flex-shrink: 0;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg></div>
          </div>
        </a>
      `;
    }

    function filterContacts() {
      const searchTerm = document.getElementById('searchInput').value.toLowerCase();
      const contactsList = document.getElementById('contactsList');

      if (!contactsList) return;

      const filteredContacts = allContacts.filter(contact => {
        const name = (contact.contact_name || '').toLowerCase();
        const phone = (contact.contact_phone || '').toLowerCase();

        return name.includes(searchTerm) || phone.includes(searchTerm);
      });

      if (filteredContacts.length === 0) {
        contactsList.innerHTML = `
          <div class="no-contacts-found">
            <p>No contacts found matching "${searchTerm}"</p>
          </div>
        `;
      } else {
        let contactsHTML = '';
        filteredContacts.forEach(contact => {
          contactsHTML += generateContactHTML(contact);
        });
        contactsList.innerHTML = contactsHTML;
      }
    }

    // Add Contact Modal Functions
    function addNewContact() {
      const phone = localStorage.getItem('exomnia_user_phone');
      if (phone) {
        document.getElementById('userPhone').value = phone;
        openModal();
      }
    }

    function openModal() {
      document.getElementById("contactModal").style.display = "flex";
    }

    function closeModal() {
      document.getElementById("contactModal").style.display = "none";
      document.getElementById("contactForm").reset();
      document.getElementById("saveBtn").classList.remove('loading');
      document.getElementById("saveBtn").textContent = 'Save Contact';
    }

    // Handle contact form submission
    document.getElementById('contactForm').addEventListener('submit', function(e) {
      e.preventDefault();
      const saveBtn = document.getElementById('saveBtn');
      const formData = new FormData(this);

      saveBtn.classList.add('loading');
      saveBtn.textContent = 'Saving...';

      fetch('/add_contact', {
        method: 'POST',
        body: formData,
        headers: {
          'X-Requested-With': 'XMLHttpRequest'
        }
      })
      .then(response => {
        if (response.ok) {
          closeModal();
          // Reload contacts
          const phone = localStorage.getItem('exomnia_user_phone');
          if (phone) {
            loadContacts(phone);
          }
        } else {
          throw new Error('Save failed');
        }
      })
      .catch(error => {
        saveBtn.classList.remove('loading');
        saveBtn.textContent = 'Save Contact';
        alert('Error saving contact. Please try again.');
        console.error('Error:', error);
      });
    });

    // Close modal when clicking outside
    document.getElementById('contactModal').addEventListener('click', function(e) {
      if (e.target === this) closeModal();
    });

    // Check for login status on page load
    window.addEventListener('load', function() {
      const urlParams = new URLSearchParams(window.location.search);
      const loggedInPhone = urlParams.get('logged_in_phone');

      if (loggedInPhone) {
        localStorage.setItem('exomnia_user_phone', loggedInPhone);
        // Remove the parameter from URL
        const newUrl = window.location.pathname;
        window.history.replaceState({}, '', newUrl);

        // Automatically open chat tab with info
        openTab('chat');
      } else {
        // Check if already logged in
        const savedPhone = localStorage.getItem('exomnia_user_phone');
        if (savedPhone) {
          openTab('chat');
        } else {
          // Show chat tab by default
          openTab('chat');
        }
      }
    });
  </script>

  <!-- Create Group Modal -->
  <div id="createGroupModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,30,30,0.55);backdrop-filter:blur(6px);z-index:2000;align-items:flex-end;justify-content:center;">
    <div style="background:#fff;border-radius:28px 28px 0 0;padding:28px 22px calc(32px + env(safe-area-inset-bottom,0px));width:100%;max-height:90vh;overflow-y:auto;animation:slideUpFromBottom 0.35s cubic-bezier(0.25,0.46,0.45,0.94);">
      <div style="width:36px;height:4px;background:#ccd8d8;border-radius:2px;margin:0 auto 20px;"></div>
      <h3 style="color:#0E4950;font-size:18px;font-weight:700;margin-bottom:6px;">New Group</h3>
      <p style="color:#8aa3a5;font-size:13px;margin-bottom:20px;">Name your group and pick contacts to add.</p>

      <div style="margin-bottom:16px;">
        <label style="display:block;font-size:13px;font-weight:600;color:#4a6567;margin-bottom:6px;">Group Name</label>
        <input id="groupNameInput" type="text" placeholder="e.g. Family, Work Team…" style="width:100%;padding:12px 16px;border:1.5px solid #d8e8e8;border-radius:12px;font-size:15px;outline:none;font-family:inherit;background:#f8fafa;color:#1a2e2f;">
      </div>

      <div style="margin-bottom:20px;">
        <label style="display:block;font-size:13px;font-weight:600;color:#4a6567;margin-bottom:10px;">Select Members</label>
        <div id="groupContactPicker" style="display:flex;flex-direction:column;gap:8px;max-height:280px;overflow-y:auto;"></div>
      </div>

      <div style="display:flex;gap:10px;">
        <button onclick="closeCreateGroupModal()" style="flex:1;padding:13px;border:none;border-radius:12px;background:#eef2f2;color:#4a6567;font-weight:600;font-size:14px;cursor:pointer;font-family:inherit;">Cancel</button>
        <button onclick="submitCreateGroup()" style="flex:2;padding:13px;border:none;border-radius:12px;background:linear-gradient(135deg,#0E4950,#1a6b75);color:white;font-weight:700;font-size:14px;cursor:pointer;font-family:inherit;">Create Group</button>
      </div>
    </div>
  </div>

  <script>
    let selectedGroupMembers = [];

    function openCreateGroupModal() {
      const phone = localStorage.getItem('exomnia_user_phone');
      if (!phone) { alert('Please login first.'); return; }

      selectedGroupMembers = [];
      document.getElementById('groupNameInput').value = '';

      // Populate contact picker from allContacts
      const picker = document.getElementById('groupContactPicker');
      picker.innerHTML = '';
      if (!allContacts || allContacts.length === 0) {
        picker.innerHTML = '<p style="color:#8aa3a5;font-size:13px;text-align:center;">No contacts yet. Add contacts first.</p>';
      } else {
        allContacts.forEach(c => {
          const displayName = c.contact_name || c.contact_phone;
          const initial = displayName[0].toUpperCase();
          const div = document.createElement('div');
          div.style.cssText = 'display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:12px;border:1.5px solid #d8e8e8;cursor:pointer;transition:all 0.2s;background:#f8fafa;';
          div.dataset.phone = c.contact_phone;
          div.innerHTML = `
            <div style="width:38px;height:38px;border-radius:50%;background:linear-gradient(135deg,#0E4950,#2ec4b6);display:flex;align-items:center;justify-content:center;color:white;font-weight:700;font-size:15px;flex-shrink:0;">${initial}</div>
            <div style="flex:1;min-width:0;">
              <div style="font-weight:600;color:#1a2e2f;font-size:14px;">${displayName}</div>
              <div style="color:#8aa3a5;font-size:11px;">${c.contact_phone}</div>
            </div>
            <div class="check-icon" style="width:22px;height:22px;border-radius:50%;border:2px solid #d8e8e8;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:all 0.2s;"></div>
          `;
          div.addEventListener('click', () => toggleGroupMember(div, c.contact_phone));
          picker.appendChild(div);
        });
      }

      const modal = document.getElementById('createGroupModal');
      modal.style.display = 'flex';
      setTimeout(() => document.getElementById('groupNameInput').focus(), 100);
    }

    function toggleGroupMember(div, phone) {
      const idx = selectedGroupMembers.indexOf(phone);
      const check = div.querySelector('.check-icon');
      if (idx === -1) {
        selectedGroupMembers.push(phone);
        div.style.borderColor = '#2ec4b6';
        div.style.background = '#f0faf9';
        check.style.background = '#2ec4b6';
        check.style.borderColor = '#2ec4b6';
        check.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
      } else {
        selectedGroupMembers.splice(idx, 1);
        div.style.borderColor = '#d8e8e8';
        div.style.background = '#f8fafa';
        check.style.background = 'transparent';
        check.style.borderColor = '#d8e8e8';
        check.innerHTML = '';
      }
    }

    function closeCreateGroupModal() {
      document.getElementById('createGroupModal').style.display = 'none';
    }

    let isCreatingGroup = false;
    function submitCreateGroup() {
      if (isCreatingGroup) return; // prevent double submission
      const name = document.getElementById('groupNameInput').value.trim();
      const phone = localStorage.getItem('exomnia_user_phone');
      if (!name) { alert('Please enter a group name.'); return; }
      if (selectedGroupMembers.length === 0) { alert('Please select at least one member.'); return; }

      isCreatingGroup = true;
      const createBtn = document.querySelector('#createGroupModal button[onclick="submitCreateGroup()"]');
      if (createBtn) { createBtn.disabled = true; createBtn.textContent = 'Creating...'; }

      fetch('/api/create_group', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, created_by: phone, members: selectedGroupMembers })
      })
      .then(r => r.json())
      .then(data => {
        isCreatingGroup = false;
        if (createBtn) { createBtn.disabled = false; createBtn.textContent = 'Create Group'; }
        if (data.success) {
          closeCreateGroupModal();
          loadContacts(phone); // refresh to show new group
        } else {
          alert(data.error || 'Failed to create group.');
        }
      })
      .catch(() => {
        isCreatingGroup = false;
        if (createBtn) { createBtn.disabled = false; createBtn.textContent = 'Create Group'; }
        alert('Network error. Please try again.');
      });
    }

    document.getElementById('createGroupModal').addEventListener('click', function(e) {
      if (e.target === this) closeCreateGroupModal();
    });
  </script>

</body>
</html>"""

signin_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>EXOMNIA - Sign In</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        }

        html { height: -webkit-fill-available; }

        body {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            min-height: 100dvh;
            min-height: -webkit-fill-available;
            background: linear-gradient(160deg, #c8e6e4 0%, #eef6f6 60%, #d4eceb 100%);
            padding: 20px;
            padding-bottom: calc(20px + env(safe-area-inset-bottom, 0px));
            color: #1a2e2f;
            box-sizing: border-box;
        }

        .login-container {
            width: 100%;
            max-width: 420px;
            background: #ffffff;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.15);
            animation: fadeIn 0.5s ease-out;
        }

        .login-header {
            background: #0E4950;
            color: white;
            padding: 35px 25px;
            text-align: center;
            position: relative;
        }

        .login-header::after {
            content: '';
            position: absolute;
            bottom: -15px;
            left: 0;
            width: 100%;
            height: 30px;
            background: #ffffff;
            border-radius: 50% 50% 0 0;
        }

        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            margin-bottom: 12px;
        }

        .logo i {
            font-size: 32px;
        }

        .logo h1 {
            font-size: 32px;
            font-weight: 700;
            letter-spacing: 1px;
        }

        .login-header p {
            font-size: 16px;
            opacity: 0.9;
            margin-top: 5px;
        }

        .login-body {
            padding: 40px 30px 30px;
        }

        .input-group {
            margin-bottom: 25px;
        }

        .input-with-icon {
            position: relative;
            margin-bottom: 20px;
        }

        .input-with-icon i {
            position: absolute;
            left: 16px;
            top: 50%;
            transform: translateY(-50%);
            color: #6c757d;
            z-index: 2;
        }

        .input-with-icon select, .input-with-icon input {
            width: 100%;
            padding: 16px 16px 16px 48px;
            border-radius: 10px;
            border: 1px solid #ddd;
            font-size: 16px;
            transition: all 0.3s ease;
            background: white;
        }

        .input-with-icon select {
            cursor: pointer;
            appearance: none;
            background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6 9 12 15 18 9'%3e%3c/polyline%3e%3c/svg%3e");
            background-repeat: no-repeat;
            background-position: right 16px center;
            background-size: 16px;
        }

        .input-with-icon select:focus, .input-with-icon input:focus {
            outline: none;
            border-color: #0E4950;
            box-shadow: 0 0 0 3px rgba(14, 73, 80, 0.2);
        }

        .phone-combined {
            display: flex;
            gap: 12px;
        }

        .phone-combined .input-with-icon {
            flex: 1;
        }

        .phone-combined .input-with-icon:last-child {
            flex: 2;
        }

        .btn {
            width: 100%;
            padding: 16px;
            border: none;
            border-radius: 10px;
            font-size: 17px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-top: 10px;
        }

        .btn-primary {
            background: #0E4950;
            color: white;
        }

        .btn-primary:hover {
            background: #0a363b;
            transform: translateY(-2px);
            box-shadow: 0 7px 15px rgba(14, 73, 80, 0.4);
        }

        .btn-primary:disabled {
            opacity: 0.85;
            cursor: not-allowed;
            transform: none;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .btn-spinner {
            width: 18px;
            height: 18px;
            border: 2.5px solid rgba(255,255,255,0.4);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.7s linear infinite;
            display: inline-block;
        }

        #pageOverlay {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(14, 73, 80, 0.92);
            z-index: 9999;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 18px;
            color: #fff;
            font-size: 17px;
            font-weight: 500;
        }

        #pageOverlay.show { display: flex; }

        .overlay-spinner {
            width: 52px;
            height: 52px;
            border: 4px solid rgba(255,255,255,0.25);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }

        .login-footer {
            text-align: center;
            margin-top: 20px;
            font-size: 15px;
            color: #6c757d;
        }

        .login-footer a {
            color: #0E4950;
            text-decoration: none;
            font-weight: 500;
        }

        .login-footer a:hover {
            text-decoration: underline;
        }

        .footer-links {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 6px;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Security Features */
        .security-features {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 15px;
            margin-top: 20px;
            border-left: 4px solid #0E4950;
        }

        .security-features h4 {
            color: #0E4950;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .security-features ul {
            list-style: none;
            padding: 0;
        }

        .security-features li {
            padding: 5px 0;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
        }

        /* Responsive adjustments */
        @media (max-width: 480px) {
            .login-container {
                max-width: 100%;
            }

            .phone-combined {
                flex-direction: column;
            }

            .footer-links {
                flex-direction: column;
                gap: 5px;
            }
        }

        .error-message {
            color: #e74c3c;
            background: #fdf0f0;
            border: 1px solid #f8d7da;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
            font-size: 14px;
            display: none;
        }
    </style>
</head>
<body>
    <div id="pageOverlay">
        <div class="overlay-spinner"></div>
        <span>Signing in...</span>
    </div>

    <div class="login-container">
        <div class="login-header">
            <div class="logo">
                <i class="fas fa-lock"></i>
                <h1>Sign in EXOMNIA</h1>
            </div>
            <p>Enter your phone number to continue</p>
        </div>

        <div class="login-body">
            <!-- Error Message -->
            <div class="error-message" id="errorMessage"></div>

            <!-- Login Form -->
            <form method="POST" id="loginForm">
                <div class="input-group">
                    <!-- Username/Email Input -->
                    <div class="input-with-icon">
                        <i class="fas fa-user"></i>
                        <input type="text" id="username" name="username" placeholder="Username or email" required>
                    </div>

                    <!-- Phone Input Combined -->
                    <div class="phone-combined">
                        <div class="input-with-icon">
                            <i class="fas fa-globe"></i>
                            <select id="country_code" name="country_code" required>
                                <option value="+91"> +91</option>
                                <option value="+1"> +1</option>
                                <option value="+44">+44</option>
                            </select>
                        </div>
                        <div class="input-with-icon">
                            <i class="fas fa-mobile-alt"></i>
                            <input type="tel" id="phone_number" name="phone_number" placeholder="Phone number" pattern="[0-9]*" inputmode="numeric" required>
                        </div>
                    </div>

                    <input type="hidden" name="phone" id="full_number">
                </div>

                <button type="submit" class="btn btn-primary" id="loginBtn">
                    <i class="fas fa-sign-in-alt"></i>
                    Sign In
                </button>
            </form>

            <div class="login-footer">
                <p>Don't have an account? <a href="#">Sign up</a></p>
                <div class="footer-links">
                    <a href="#">Help Center</a>
                    <a href="#">Privacy Policy</a>
                </div>
            </div>
        </div>
    </div>

    <script>
        // DOM Elements
        const loginForm = document.getElementById('loginForm');
        const phoneNumberInput = document.getElementById('phone_number');
        const countryCodeSelect = document.getElementById('country_code');
        const fullNumberInput = document.getElementById('full_number');
        const errorMessage = document.getElementById('errorMessage');

        // Show error message if any
        {% if error %}
            errorMessage.textContent = "{{ error }}";
            errorMessage.style.display = 'block';
        {% endif %}

        // Only allow numbers in phone field
        phoneNumberInput.addEventListener('input', function(e) {
            this.value = this.value.replace(/[^0-9]/g, '');
        });

        // Combine country code and phone number
        function updateFullPhoneNumber() {
            const countryCode = countryCodeSelect.value;
            const phoneNumber = phoneNumberInput.value;
            fullNumberInput.value = countryCode + phoneNumber;
        }

        countryCodeSelect.addEventListener('change', updateFullPhoneNumber);
        phoneNumberInput.addEventListener('input', updateFullPhoneNumber);

        // Handle form submission
        loginForm.addEventListener('submit', function(e) {
            const phoneNumber = phoneNumberInput.value.trim();

            if (!phoneNumber) {
                e.preventDefault();
                errorMessage.textContent = "Please enter your phone number";
                errorMessage.style.display = 'block';
                return;
            }

            // Update the full phone number before submission
            updateFullPhoneNumber();

            // Show full-screen overlay immediately (fastest perceived loading)
            document.getElementById('pageOverlay').classList.add('show');

            // Also update button state
            const loginBtn = document.getElementById('loginBtn');
            loginBtn.innerHTML = '<span class="btn-spinner"></span> Signing In...';
            loginBtn.disabled = true;
        });
    </script>
</body>
</html>"""

# ----------------- Routes -----------------
@app.route("/", methods=["GET","POST"])
def signin():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        country_code = request.form.get("country_code", "").strip()
        phone_number = request.form.get("phone_number", "").strip()
        phone = request.form.get("phone", "").strip()

        # If phone is not directly provided, combine country code and phone number
        if not phone and country_code and phone_number:
            phone = country_code + phone_number

        if not phone:
            return render_template_string(signin_html, error="Please enter your phone number")

        if not validate_phone(phone):
            return render_template_string(signin_html, error="Please use correct phone number format with country code")

        try:
            now_iso = datetime.now().isoformat()
            conn = get_db_connection()
            try:
                c = conn.cursor()
                c.execute("INSERT OR IGNORE INTO users(phone,last_online) VALUES(?,?)",(phone, now_iso))
                c.execute("UPDATE users SET last_online=? WHERE phone=?",(now_iso, phone))
                conn.commit()
            finally:
                return_db_connection(conn)
            return redirect(url_for('main_app', logged_in_phone=phone))
        except Exception as e:
            print(f"Error in signin: {e}")
            return render_template_string(signin_html, error="An error occurred. Please try again.")

    return render_template_string(signin_html)

@app.route("/main")
def main_app():
    logged_in_phone = request.args.get('logged_in_phone')
    return render_template_string(main_app_html)

# ----------------- File Upload Route -----------------
@app.route('/upload_file', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        sender = request.form.get('sender')
        receiver = request.form.get('receiver')
        
        if not all([sender, receiver]):
            return jsonify({'success': False, 'error': 'Missing sender or receiver'}), 400

        # Determine file type
        file_type = get_file_type(file.filename)
        
        # Generate unique filename
        if '.' in file.filename:
            file_ext = file.filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{uuid.uuid4()}.{file_ext}"
        else:
            unique_filename = f"{uuid.uuid4()}"
            
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # Save file
        file.save(file_path)
        file_size = os.path.getsize(file_path)
        
        # For images and videos, you could generate thumbnails here
        thumbnail_path = None
        if file_type in ['image', 'video']:
            # Thumbnail generation would go here
            # For now, we'll use the same file as thumbnail
            thumbnail_path = unique_filename
        
        # Save to database — only log in messages table for 1:1 chats
        is_group_upload = receiver.startswith('group_')
        now_iso = datetime.now().isoformat()
        conn = get_db_connection()
        try:
            c = conn.cursor()
            if not is_group_upload:
                c.execute("""
                    INSERT INTO messages(sender, receiver, message, message_type, file_path, file_name, file_size, thumbnail_path, status, timestamp)
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (sender, receiver, f"Sent a {file_type}", file_type, unique_filename, file.filename, file_size, thumbnail_path, "sent", now_iso))
                message_id = c.lastrowid
                c.execute("INSERT OR IGNORE INTO contacts(user_phone, contact_phone, contact_name, last_message) VALUES(?, ?, ?, ?)",
                          (sender, receiver, "", f"Sent a {file_type}"))
                c.execute("UPDATE contacts SET last_message=?, timestamp=CURRENT_TIMESTAMP WHERE user_phone=? AND contact_phone=?",
                          (f"Sent a {file_type}", sender, receiver))
                c.execute("INSERT OR IGNORE INTO contacts(user_phone, contact_phone, contact_name, last_message) VALUES(?, ?, ?, ?)",
                          (receiver, sender, "", f"Sent a {file_type}"))
                c.execute("UPDATE contacts SET last_message=?, timestamp=CURRENT_TIMESTAMP WHERE user_phone=? AND contact_phone=?",
                          (f"Sent a {file_type}", receiver, sender))
            else:
                # Group upload — no message_id needed here; socket will handle it
                message_id = None
            conn.commit()
        finally:
            return_db_connection(conn)
        
        return jsonify({
            'success': True, 
            'message_id': message_id,
            'file_path': unique_filename,
            'file_name': file.filename,
            'file_type': file_type,
            'file_size': file_size
        })
        
    except Exception as e:
        print(f" Error in upload_file: {e}")
        return jsonify({'success': False, 'error': 'File upload failed'}), 500

@app.route('/uploads/<filename>')
def serve_file(filename):
    """Serve uploaded files with long-lived cache headers"""
    try:
        from flask import make_response
        resp = make_response(send_from_directory(app.config['UPLOAD_FOLDER'], filename))
        resp.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        return resp
    except FileNotFoundError:
        return "File not found", 404

# ----------------- Contacts API -----------------
@app.route("/api/contacts")
def api_contacts():
    phone = request.args.get("phone")
    if not phone:
        return jsonify([]), 400
    
    # Check cache first
    cache_key = f"contacts_{phone}"
    cached_contacts = cache.get(cache_key)
    if cached_contacts:
        return jsonify(cached_contacts)
    
    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("""
                SELECT contact_phone, contact_name,
                       substr(COALESCE(last_message,''), 1, 50) ||
                       CASE WHEN length(last_message) > 50 THEN '...' ELSE '' END as last_message
                FROM contacts
                WHERE user_phone=?
                ORDER BY timestamp DESC
            """,(phone,))
            rows = c.fetchall()
        finally:
            return_db_connection(conn)
        contacts = [{"contact_phone": r[0], "contact_name": r[1], "last_message": r[2]} for r in rows]
        
        # Cache the results
        cache.set(cache_key, contacts)
        
        return jsonify(contacts)
    except Exception as e:
        print(f" Error in api_contacts: {e}")
        return jsonify([]), 500

@app.route("/add_contact", methods=["POST"])
def add_contact():
    try:
        user = request.form.get("user")
        country_code = request.form.get("country_code","")
        contact_phone = request.form.get("contact_phone","").strip()
        contact_name = request.form.get("contact_name","").strip()
        if not all([user, contact_phone, contact_name]):
            return jsonify({"success": False, "error": "Please fill all information"}), 400

        full_contact_phone = contact_phone
        if country_code and not contact_phone.startswith(country_code):
            full_contact_phone = country_code + contact_phone

        if not validate_phone(full_contact_phone):
            return jsonify({"success": False, "error": "Please enter valid phone number"}), 400

        now_iso = datetime.now().isoformat()
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("INSERT OR IGNORE INTO users(phone,last_online) VALUES(?,?)",(full_contact_phone, now_iso))
            c.execute("""
                INSERT OR REPLACE INTO contacts(user_phone,contact_phone,contact_name,last_message)
                VALUES(?,?,?,COALESCE((SELECT last_message FROM contacts WHERE user_phone=? AND contact_phone=?), ''))
            """,(user, full_contact_phone, contact_name, user, full_contact_phone))
            conn.commit()
        finally:
            return_db_connection(conn)

        # Clear cache for this user's contacts
        cache.delete(f"contacts_{user}")

        return jsonify({"success": True})

    except Exception as e:
        print(f" Error in add_contact: {e}")
        return jsonify({"success": False, "error": "An error occurred"}), 500

# ----------------- Get Messages API -----------------
@app.route("/api/get_messages")
def api_get_messages():
    user_phone    = request.args.get("user_phone")
    contact_phone = request.args.get("contact_phone")
    page          = request.args.get("page", 1, type=int)
    limit         = request.args.get("limit", 50, type=int)
    offset        = (page - 1) * limit

    if not all([user_phone, contact_phone]):
        return jsonify([]), 400

    # Normalise cache key so A-B and B-A always hit the same entry
    pair      = "_".join(sorted([user_phone, contact_phone]))
    cache_key = f"messages_{pair}_page_{page}"
    cached    = cache.get(cache_key)
    if cached is not None:
        return jsonify(cached)

    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("""
                SELECT m.id, m.sender, m.receiver, m.message, m.encrypted_message,
                       m.status, m.timestamp, m.message_type,
                       m.file_path, m.file_name, m.file_size, m.thumbnail_path
                FROM messages m
                WHERE ((m.sender=? AND m.receiver=?) OR (m.sender=? AND m.receiver=?))
                ORDER BY m.timestamp ASC
                LIMIT ? OFFSET ?
            """, (user_phone, contact_phone, contact_phone, user_phone, limit, offset))
            messages_data = c.fetchall()

            message_ids = [m[0] for m in messages_data]
            reactions_dict = {}
            if message_ids:
                placeholders = ','.join('?' * len(message_ids))
                c.execute(f"""
                    SELECT message_id, user_phone, emoji
                    FROM message_reactions
                    WHERE message_id IN ({placeholders})
                """, message_ids)
                for msg_id, r_phone, r_emoji in c.fetchall():
                    reactions_dict.setdefault(msg_id, []).append(
                        {'user_phone': r_phone, 'emoji': r_emoji}
                    )
        finally:
            return_db_connection(conn)

        messages = []
        for row in messages_data:
            (message_id, sender, receiver, plaintext, encrypted, status, timestamp,
             message_type, file_path, file_name, file_size, thumbnail_path) = row

            mtype = message_type or 'text'
            if mtype == 'text':
                if encrypted:
                    decrypted = encryptor.decrypt_message(encrypted, sender, receiver)
                    content = decrypted if decrypted is not None else (plaintext or '')
                else:
                    content = plaintext or ''
            else:
                content = file_name or mtype

            messages.append({
                "id":             message_id,
                "sender":         sender,
                "receiver":       receiver,
                "message":        content,
                "status":         status,
                "timestamp":      timestamp,
                "reactions":      reactions_dict.get(message_id, []),
                "message_type":   mtype,
                "file_path":      file_path,
                "file_name":      file_name,
                "file_size":      file_size,
                "thumbnail_path": thumbnail_path,
            })

        cache.set(cache_key, messages)
        return jsonify(messages)

    except Exception as e:
        print(f"Error in api_get_messages: {e}")
        return jsonify([]), 500

# ----------------- Enhanced Chat Page -----------------
chat_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Chat</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover, interactive-widget=resizes-content">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap">
    <style>
        :root {
            --primary-color: #0E4950;
            --primary-light: #1a6b75;
            --primary-dark: #092f34;
            --secondary-color: #A8D0CF;
            --accent-color: #2ec4b6;
            --accent-warm: #ff9f1c;
            --sent-bubble: #e8f8f5;
            --sent-bubble-border: #c3ede8;
            --received-bubble: #ffffff;
            --background-color: #eef6f6;
            --chat-bg: #f0f4f4;
            --text-color: #1a2e2f;
            --text-secondary: #4a6567;
            --light-text: #8aa3a5;
            --border-color: #d8e8e8;
            --shadow: 0 4px 20px rgba(14, 73, 80, 0.08);
            --shadow-strong: 0 8px 32px rgba(14, 73, 80, 0.15);
            --radius-bubble: 20px;
            --radius-ui: 16px;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }

        html {
            height: 100%;
            height: -webkit-fill-available;
        }

        body {
            font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            display: flex;
            flex-direction: column;
            height: 100vh;
            height: 100dvh;
            min-height: -webkit-fill-available;
            background: var(--chat-bg);
            color: var(--text-color);
            overflow: hidden;
            /* Prevent elastic scroll from exposing background */
            position: fixed;
            width: 100%;
            top: 0;
            left: 0;
        }

        #chat-header {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-light) 100%);
            color: #fff;
            padding: calc(14px + env(safe-area-inset-top, 0px)) 18px 14px;
            padding-left: calc(18px + env(safe-area-inset-left, 0px));
            padding-right: calc(18px + env(safe-area-inset-right, 0px));
            font-weight: 600;
            font-size: 17px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 16px rgba(14, 73, 80, 0.25);
            z-index: 10;
            position: relative;
        }

        #contact-info {
            display: flex;
            align-items: center;
            gap: 12px;
            flex: 1;
        }

        .left-header-actions {
            display: flex;
            gap: 8px;
            align-items: center;
            margin-right: 12px;
        }

        #saveBtn {
            background: rgba(255,255,255,0.18);
            border: none;
            color: #fff;
            cursor: pointer;
            padding: 8px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s;
            width: 36px;
            height: 36px;
            backdrop-filter: blur(4px);
        }

        #saveBtn:hover {
            background: rgba(255,255,255,0.3);
            transform: scale(1.1);
        }

        .contact-avatar {
            width: 42px;
            height: 42px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--accent-color), #1a6b75);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 17px;
            border: 2px solid rgba(255,255,255,0.3);
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        }

        .contact-details {
            display: flex;
            flex-direction: column;
            flex: 1;
        }

        .contact-name {
            font-size: 17px;
            font-weight: 700;
            letter-spacing: -0.01em;
        }

        .connection-status {
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 12px;
            margin-top: 1px;
            opacity: 0.85;
        }

        .status-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            display: inline-block;
        }

        .status-online {
            background: #4ade80;
            box-shadow: 0 0 6px rgba(74, 222, 128, 0.6);
            animation: statusPulse 2s ease-in-out infinite;
        }
        @keyframes statusPulse {
            0%,100% { box-shadow: 0 0 4px rgba(74,222,128,0.5); }
            50%      { box-shadow: 0 0 10px rgba(74,222,128,0.9); }
        }
        .status-offline {
            background: #94a3b8;
            box-shadow: none;
        }

        .header-actions {
            display: flex;
            gap: 10px;
            align-items: center;
        }

        #chat-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            min-height: 0; /* critical for flex children to shrink */
            background: #eef6f6;
            background-image: radial-gradient(circle, rgba(14,73,80,0.045) 1px, transparent 1px);
            background-size: 22px 22px;
        }

        #chat {
            flex: 1;
            overflow-y: auto;
            padding: 20px 16px 12px;
            display: flex;
            flex-direction: column;
            gap: 4px;
            scroll-behavior: auto;
            overscroll-behavior: contain;
        }

        .message-group {
            display: flex;
            flex-direction: column;
            margin-bottom: 10px;
            max-width: 82%;
            contain: layout style;
        }

        /* Image bubbles wider than text — up to 72% of viewport */
        .message-group:has(.media-message) {
            max-width: min(72vw, 320px);
        }

        .sent-group {
            align-self: flex-end;
            align-items: flex-end;
        }

        .received-group {
            align-self: flex-start;
            align-items: flex-start;
        }

        .bubble {
            padding: 11px 15px;
            border-radius: 20px;
            margin: 2px 0;
            font-size: 15px;
            line-height: 1.5;
            word-wrap: break-word;
            position: relative;
            white-space: pre-wrap;
            word-break: break-word;
            overflow-wrap: break-word;
            max-width: 100%;
            user-select: none;
            -webkit-user-select: none;
            transition: transform 0.1s ease;
            will-change: transform;
        }

        .bubble.media-message {
            padding: 6px;
            overflow: hidden;
        }

        .bubble:active {
            transform: scale(0.985);
        }

        .sent {
            background: linear-gradient(135deg, #d4f5ef 0%, #c8ede7 100%);
            border-bottom-right-radius: 5px;
            border: 1px solid rgba(46, 196, 182, 0.2);
            box-shadow: 0 1px 4px rgba(14, 73, 80, 0.08);
        }

        .received {
            background: #ffffff;
            border-bottom-left-radius: 5px;
            border: 1px solid #e8eeee;
            box-shadow: 0 1px 4px rgba(0, 0, 0, 0.05);
        }

        .status {
            display: flex;
            justify-content: flex-end;
            align-items: center;
            margin-top: 3px;
            padding-right: 2px;
            color: var(--accent-color);
            line-height: 1;
        }

        .status svg {
            color: var(--accent-color);
        }

        .message-time {
            font-size: 10px;
            color: var(--light-text);
            margin-top: 2px;
            padding: 0 2px;
            font-family: 'DM Mono', monospace;
        }

        #typing {
            font-size: 13px;
            color: var(--text-secondary);
            margin: 0 16px 8px;
            height: 18px;
            font-style: italic;
        }

        #message-box {
            display: flex;
            padding: 10px 12px calc(14px + env(safe-area-inset-bottom, 0px));
            padding-bottom: calc(14px + env(safe-area-inset-bottom, 0px) + var(--keyboard-offset, 0px));
            background: #fff;
            border-top: 1px solid var(--border-color);
            gap: 8px;
            align-items: center;
            min-height: 66px;
            box-shadow: 0 -4px 20px rgba(14, 73, 80, 0.06);
            flex-shrink: 0;
        }

        #message {
            flex: 1;
            padding: 11px 16px;
            font-size: 15px;
            border: 1.5px solid var(--border-color);
            border-radius: 24px;
            outline: none;
            resize: none;
            max-height: 120px;
            font-family: 'DM Sans', inherit;
            transition: border-color 0.2s, box-shadow 0.2s;
            background: #f8fafa;
            line-height: 1.45;
            overflow-y: auto;
            min-height: 44px;
            height: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            word-break: break-word;
            color: var(--text-color);
        }

        #message::placeholder {
            color: var(--light-text);
        }

        #message:focus {
            border-color: var(--accent-color);
            background: #fff;
            box-shadow: 0 0 0 3px rgba(46, 196, 182, 0.12);
        }

        #send-btn {
            width: 48px;
            height: 48px;
            border: none;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary-color), var(--primary-light));
            color: white;
            font-size: 18px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: transform 0.15s, box-shadow 0.15s;
            flex-shrink: 0;
            box-shadow: 0 3px 14px rgba(14, 73, 80, 0.35);
        }

        #send-btn:hover {
            transform: scale(1.07);
            box-shadow: 0 5px 18px rgba(14, 73, 80, 0.45);
        }

        #send-btn:active {
            transform: scale(0.93);
        }

        /* File Upload Button */
        #file-upload-btn {
            width: 40px;
            height: 40px;
            border: none;
            border-radius: 50%;
            background: #e8f6f5;
            color: var(--accent-color);
            font-size: 18px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: background 0.18s, transform 0.15s;
            flex-shrink: 0;
        }

        #file-upload-btn:hover {
            background: #d0efed;
            transform: scale(1.07);
        }

        #file-upload-btn:active {
            transform: scale(0.93);
        }

        /* Mic button — same weight as send */
        #vm-mic-btn {
            width: 48px !important;
            height: 48px !important;
            border-radius: 50% !important;
            border: none !important;
            background: linear-gradient(135deg, var(--primary-color), var(--primary-light)) !important;
            color: #fff !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            cursor: pointer !important;
            flex-shrink: 0 !important;
            transition: transform 0.15s, box-shadow 0.15s !important;
            box-shadow: 0 3px 14px rgba(14,73,80,.35) !important;
        }
        #vm-mic-btn:hover  { transform: scale(1.07) !important; box-shadow: 0 5px 18px rgba(14,73,80,.45) !important; }
        #vm-mic-btn:active { transform: scale(0.93) !important; }
        #vm-mic-btn.vm-recording { background: #e63946 !important; box-shadow: 0 0 0 4px rgba(230,57,70,.25) !important; animation: vmMicPulse 1s infinite !important; }

        /* Modern Bottom Sheet Modal Styles */
        .file-upload-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(10, 30, 30, 0.55);
            backdrop-filter: blur(4px);
            z-index: 2000;
            align-items: flex-end;
            justify-content: center;
        }

        .file-upload-content {
            background: #fff;
            border-radius: 28px 28px 0 0;
            padding: 28px 22px 32px;
            width: 100%;
            max-width: 100%;
            text-align: center;
            box-shadow: 0 -12px 48px rgba(14, 73, 80, 0.18);
            animation: slideUpFromBottom 0.38s cubic-bezier(0.25, 0.46, 0.45, 0.94);
            position: relative;
            overflow: hidden;
            max-height: 80vh;
            overflow-y: auto;
        }

        @keyframes slideUpFromBottom {
            from { opacity: 0; transform: translateY(100%); }
            to { opacity: 1; transform: translateY(0); }
        }

        .file-upload-content::before {
            content: '';
            position: absolute;
            top: 10px;
            left: 50%;
            transform: translateX(-50%);
            width: 36px;
            height: 4px;
            background: #ccd8d8;
            border-radius: 2px;
        }

        .file-upload-content h3 {
            margin-bottom: 6px;
            color: var(--primary-color);
            font-size: 20px;
            font-weight: 700;
            margin-top: 18px;
            letter-spacing: -0.02em;
        }

        .file-upload-subtitle {
            color: var(--text-secondary);
            font-size: 14px;
            margin-bottom: 24px;
        }

        .file-upload-options {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin: 20px 0;
        }

        .file-upload-option {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 10px;
            padding: 18px 10px;
            border: 1.5px solid var(--border-color);
            border-radius: 18px;
            cursor: pointer;
            transition: all 0.25s ease;
            background: #f7fafa;
        }

        .file-upload-option:hover {
            background: #eef6f6;
            border-color: var(--accent-color);
            transform: translateY(-3px);
            box-shadow: 0 6px 20px rgba(46, 196, 182, 0.15);
        }

        .option-icon {
            width: 52px;
            height: 52px;
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 26px;
            transition: all 0.25px ease;
        }

        .photo-option .option-icon { background: linear-gradient(135deg, #d4edda, #a8d8b0); }
        .video-option .option-icon { background: linear-gradient(135deg, #fde8c8, #f9c784); }
        .document-option .option-icon { background: linear-gradient(135deg, #dbeafe, #93c5fd); }

        .option-title {
            font-size: 13px;
            font-weight: 600;
            color: var(--text-color);
        }

        .option-description {
            font-size: 10px;
            color: var(--light-text);
            line-height: 1.3;
        }

        .file-upload-info {
            margin-top: 18px;
            padding: 12px 16px;
            background: #f0f8f7;
            border-radius: 12px;
            border-left: 3px solid var(--accent-color);
        }

        .info-text {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            color: var(--text-secondary);
            font-size: 12px;
            font-weight: 500;
        }

        #fileInput { display: none; }

        .modal-close-btn {
            position: absolute;
            top: 14px;
            right: 14px;
            background: #f0f4f4;
            border: none;
            font-size: 18px;
            color: var(--text-secondary);
            cursor: pointer;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s;
        }

        .modal-close-btn:hover {
            background: var(--border-color);
            color: var(--text-color);
        }

        /* Enhanced Media Message Styles */
        .media-message {
            max-width: 280px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .media-message:hover {
            transform: translateY(-2px);
        }

        .media-preview {
            border-radius: 14px;
            overflow: hidden;
            position: relative;
            transition: opacity 0.2s ease;
            cursor: pointer;
        }

        .media-preview:active {
            opacity: 0.85;
        }

        .media-preview img, .media-preview video {
            width: 100%;
            max-height: 280px;
            object-fit: cover;
            display: block;
            border-radius: 14px;
        }

        .media-info {
            padding: 8px 4px;
        }

        .media-filename {
            font-weight: 600;
            font-size: 13px;
            color: #333;
            margin-bottom: 4px;
            word-break: break-word;
            line-height: 1.3;
        }

        .media-metadata {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 11px;
            color: #666;
        }

        .media-size {
            font-weight: 500;
        }

        .media-type {
            background: #0E4950;
            color: white;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 10px;
            font-weight: 600;
        }

        /* Enhanced File Message Styles */
        .file-message {
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 16px;
            background: linear-gradient(135deg, #f8f9fa, #ffffff);
            border-radius: 16px;
            border: 1px solid #e9ecef;
            transition: all 0.3s ease;
        }

        .file-message:hover {
            background: linear-gradient(135deg, #ffffff, #f8f9fa);
            box-shadow: 0 6px 20px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }

        .file-icon {
            width: 50px;
            height: 50px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            flex-shrink: 0;
        }

        .file-icon.photo { background: #E8F5E8; color: #4CAF50; }
        .file-icon.video { background: #FFF3E0; color: #FF9800; }
        .file-icon.document { background: #E3F2FD; color: #2196F3; }

        .file-info {
            flex: 1;
            min-width: 0;
        }

        .file-name {
            font-weight: 700;
            font-size: 14px;
            margin-bottom: 6px;
            word-break: break-word;
            color: #333;
            line-height: 1.3;
        }

        .file-details {
            display: flex;
            gap: 12px;
            align-items: center;
            font-size: 12px;
            color: #666;
        }

        .file-size {
            font-weight: 600;
            color: #0E4950;
        }

        .file-type {
            background: #0E4950;
            color: white;
            padding: 2px 8px;
            border-radius: 8px;
            font-size: 10px;
            font-weight: 600;
        }

        .download-btn {
            background: linear-gradient(135deg, #0E4950, #1a6b75);
            color: white;
            border: none;
            border-radius: 10px;
            padding: 10px 16px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 6px;
            flex-shrink: 0;
        }

        .download-btn:hover {
            background: linear-gradient(135deg, #1a6b75, #0E4950);
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(14, 73, 80, 0.3);
        }

        .download-btn:active {
            transform: translateY(0);
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .file-upload-options {
                grid-template-columns: 1fr;
                gap: 10px;
            }
            
            .file-upload-option {
                flex-direction: row;
                justify-content: flex-start;
                padding: 12px 15px;
                gap: 15px;
            }
            
            .option-text {
                text-align: left;
            }
        }

        /* Rest of the existing styles remain the same */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(10, 30, 30, 0.55);
            backdrop-filter: blur(6px);
            justify-content: center;
            align-items: center;
            z-index: 1000;
            animation: fadeIn 0.2s ease-out;
        }

        .modal-content {
            background: #fff;
            padding: 28px 24px;
            border-radius: 20px;
            width: 90%;
            max-width: 400px;
            box-shadow: 0 20px 60px rgba(14, 73, 80, 0.2);
            animation: slideUp 0.3s ease-out;
        }

        .modal h3 {
            margin-bottom: 18px;
            color: var(--primary-color);
            font-size: 18px;
            font-weight: 700;
            letter-spacing: -0.01em;
        }

        .modal input {
            width: 100%;
            padding: 13px 16px;
            border: 1.5px solid var(--border-color);
            border-radius: 12px;
            font-size: 15px;
            margin-bottom: 20px;
            outline: none;
            font-family: 'DM Sans', sans-serif;
            transition: border-color 0.2s, box-shadow 0.2s;
            background: #f8fafa;
            color: var(--text-color);
        }

        .modal input:focus {
            border-color: var(--accent-color);
            box-shadow: 0 0 0 3px rgba(46, 196, 182, 0.12);
            background: #fff;
        }

        .modal-buttons {
            display: flex;
            gap: 10px;
        }

        .modal-btn {
            flex: 1;
            padding: 13px;
            border: none;
            border-radius: 12px;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.2s;
            font-family: 'DM Sans', sans-serif;
        }

        .modal-btn.primary {
            background: linear-gradient(135deg, var(--primary-color), var(--primary-light));
            color: white;
            box-shadow: 0 4px 14px rgba(14, 73, 80, 0.25);
        }

        .modal-btn.primary:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(14, 73, 80, 0.35);
        }

        .modal-btn.secondary {
            background: #eef2f2;
            color: var(--text-secondary);
        }

        .modal-btn.secondary:hover {
            background: #e0e8e8;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .message-appear {
            animation: messageAppear 0.25s ease-out;
        }

        @keyframes messageAppear {
            from { opacity: 0; transform: translateY(8px) scale(0.98); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }

        #chat::-webkit-scrollbar { width: 4px; }
        #chat::-webkit-scrollbar-track { background: transparent; }
        #chat::-webkit-scrollbar-thumb {
            background: rgba(14, 73, 80, 0.2);
            border-radius: 4px;
        }
        #chat::-webkit-scrollbar-thumb:hover { background: rgba(14, 73, 80, 0.35); }

        .back-button {
            background: rgba(255,255,255,0.15);
            border: none;
            color: white;
            font-size: 18px;
            cursor: pointer;
            padding: 7px 10px;
            border-radius: 10px;
            transition: background 0.2s;
        }

        .back-button:hover { background: rgba(255,255,255,0.25); }

        /* Message Context Menu */
        .context-menu {
            position: fixed;
            background: rgba(255,255,255,0.96);
            border-radius: 16px;
            box-shadow: 0 12px 40px rgba(14, 73, 80, 0.18), 0 2px 8px rgba(0,0,0,0.08);
            z-index: 1000;
            min-width: 168px;
            padding: 6px 0;
            display: none;
            border: 1px solid rgba(14, 73, 80, 0.08);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            animation: contextMenuAppear 0.15s ease-out;
        }

        .context-menu-item {
            padding: 11px 16px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 14px;
            color: var(--text-color);
            transition: background 0.15s;
            user-select: none;
            -webkit-user-select: none;
            font-weight: 500;
        }

        .context-menu-item:hover { background: rgba(46, 196, 182, 0.08); }
        .context-menu-item:first-child { border-radius: 10px 10px 0 0; }
        .context-menu-item:last-child { border-radius: 0 0 10px 10px; }

        .context-menu-item i,
        .context-menu-item svg {
            font-size: 15px;
            width: 20px;
            text-align: center;
            color: var(--primary-color);
        }

        .context-menu-divider {
            height: 1px;
            background: rgba(14, 73, 80, 0.08);
            margin: 4px 0;
        }

        @keyframes contextMenuAppear {
            from { opacity: 0; transform: scale(0.92) translateY(-6px); }
            to { opacity: 1; transform: scale(1) translateY(0); }
        }

        /* Emoji Reaction Menu */
        .emoji-menu {
            position: fixed;
            background: rgba(255,255,255,0.96);
            border-radius: 28px;
            box-shadow: 0 10px 36px rgba(14, 73, 80, 0.18);
            z-index: 1001;
            padding: 8px 10px;
            display: none;
            animation: slideUp 0.2s ease-out;
            border: 1px solid rgba(14, 73, 80, 0.08);
            backdrop-filter: blur(16px);
        }

        .emoji-options { display: flex; gap: 4px; }

        .emoji-option {
            font-size: 22px;
            padding: 8px;
            cursor: pointer;
            border-radius: 50%;
            transition: all 0.18s;
        }

        .emoji-option:hover {
            background: rgba(46, 196, 182, 0.12);
            transform: scale(1.25);
        }

        /* Message Reactions */
        .message-reactions {
            display: flex;
            gap: 4px;
            margin-top: 5px;
            flex-wrap: wrap;
        }

        .reaction {
            background: rgba(14, 73, 80, 0.06);
            border-radius: 12px;
            padding: 2px 7px;
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 3px;
            border: 1px solid rgba(14, 73, 80, 0.08);
            cursor: pointer;
            user-select: none;
            -webkit-user-select: none;
            transition: transform 0.1s ease, background 0.15s ease;
        }

        .reaction:active { transform: scale(0.92); }

        .reaction-mine {
            background: rgba(46, 196, 182, 0.15);
            border-color: rgba(46, 196, 182, 0.4);
        }

        .reaction-emoji { font-size: 13px; }
        .reaction-count { font-size: 10px; color: var(--text-secondary); font-weight: 600; }

        .bubble.selected,
        .vm-bubble.selected,
        .gvm-bubble.selected {
            background: rgba(46, 196, 182, 0.08) !important;
            border-color: var(--accent-color) !important;
            box-shadow: 0 0 0 2px rgba(46, 196, 182, 0.2) !important;
        }

        /* Copy Feedback */
        .copy-feedback {
            position: fixed;
            background: rgba(14, 73, 80, 0.88);
            color: white;
            padding: 9px 18px;
            border-radius: 22px;
            font-size: 13px;
            font-weight: 600;
            z-index: 1002;
            animation: fadeInOut 2s ease-in-out;
            backdrop-filter: blur(8px);
        }

        @keyframes fadeInOut {
            0%, 100% { opacity: 0; transform: translateY(10px); }
            20%, 80% { opacity: 1; transform: translateY(0); }
        }

        /* Media Viewer */
        .media-viewer {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.9);
            z-index: 3000;
            align-items: center;
            justify-content: center;
        }

        .media-viewer-content {
            max-width: 90%;
            max-height: 90%;
            position: relative;
        }

        .media-viewer-content img,
        .media-viewer-content video {
            max-width: 100%;
            max-height: 90vh;
            border-radius: 8px;
        }

        .close-viewer {
            position: absolute;
            top: -40px;
            right: 0;
            background: none;
            border: none;
            color: white;
            font-size: 24px;
            cursor: pointer;
            width: 30px;
            height: 30px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        @media (max-width: 768px) {
            #chat-header {
                padding: 14px 16px;
            }

            #chat {
                padding: 16px;
            }

            .message-group {
                max-width: 90%;
            }

            #message-box {
                padding: 14px 16px;
                min-height: 65px;
            }

            #message {
                min-height: 44px;
                max-height: 100px;
            }

            #saveBtn {
                width: 34px;
                height: 34px;
                padding: 6px;
            }

            .context-menu {
                min-width: 140px;
            }

            .emoji-menu {
                padding: 6px;
            }

            .emoji-option {
                font-size: 18px;
                padding: 6px;
            }

            .media-message {
                max-width: 250px;
            }
        }

        @media (max-width: 480px) {
            .contact-avatar {
                width: 36px;
                height: 36px;
                font-size: 16px;
            }

            .contact-name {
                font-size: 16px;
            }

            .bubble {
                padding: 10px 14px;
                font-size: 14px;
            }

            #message {
                padding: 10px 16px;
                font-size: 15px;
                min-height: 42px;
                max-height: 90px;
            }

            #send-btn, #file-upload-btn {
                width: 44px;
                height: 44px;
            }

            #message-box {
                min-height: 60px;
            }            #saveBtn {
                width: 32px;
                height: 32px;
                padding: 5px;
            }

            .media-message {
                max-width: 200px;
            }

            .file-message {
                padding: 12px;
                gap: 12px;
            }
            
            .file-icon {
                width: 40px;
                height: 40px;
                font-size: 20px;
            }
        }

        /* Loading Indicator */
        .loading-indicator {
            text-align: center;
            padding: 12px;
            color: var(--light-text);
            font-size: 13px;
            font-style: italic;
        }

        .loading-indicator.hidden { display: none; }

        .message-group .bubble:first-child { margin-top: 0; }
        .message-group .bubble:last-child { margin-bottom: 0; }

        /* ── Voice Message Styles ── */
        #vm-overlay{display:none;position:fixed;inset:0;z-index:9000;background:rgba(14,73,80,0.94);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);flex-direction:column;align-items:center;justify-content:center;gap:22px;}
        #vm-overlay.active{display:flex;}
        #vm-rec-timer{font-size:54px;font-weight:700;color:#fff;letter-spacing:-2px;font-variant-numeric:tabular-nums;font-family:'DM Mono',monospace;}
        #vm-rec-label{font-size:11px;font-weight:600;color:rgba(255,255,255,.6);text-transform:uppercase;letter-spacing:3px;}
        #vm-live-canvas{width:280px;height:60px;border-radius:12px;}
        .vm-dot{width:10px;height:10px;border-radius:50%;background:#ff4d4d;animation:vmPulse 1.1s ease-in-out infinite;}
        @keyframes vmPulse{0%,100%{transform:scale(1);opacity:1;}50%{transform:scale(1.6);opacity:.4;}}
        #vm-cancel-hint{font-size:12px;color:rgba(255,255,255,.4);display:flex;align-items:center;gap:5px;}
        .vm-rec-actions{display:flex;gap:28px;margin-top:6px;}
        .vm-act-btn{width:62px;height:62px;border-radius:50%;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:transform .14s;}
        .vm-act-btn:active{transform:scale(.9);}
        #vm-cancel-act{background:rgba(255,255,255,.14);color:#fff;}
        #vm-send-act{background:#fff;color:var(--primary-color);box-shadow:0 6px 22px rgba(0,0,0,.26);}
        #vm-mic-btn.vm-recording{background:#e63946;animation:vmMicPulse 1s infinite;}
        @keyframes vmMicPulse{0%,100%{box-shadow:0 0 0 0 rgba(230,57,70,.55);}50%{box-shadow:0 0 0 10px rgba(230,57,70,0);}}
        .vm-bubble{display:flex;align-items:center;gap:10px;padding:10px 13px;border-radius:20px;max-width:300px;min-width:210px;font-family:'DM Sans',sans-serif;user-select:none;position:relative;}
        .vm-bubble.vm-out{background:linear-gradient(135deg,#d4f5ef,#c8ede7);border-bottom-right-radius:5px;border:1px solid rgba(46,196,182,.2);box-shadow:0 1px 4px rgba(14,73,80,.08);margin-left:auto;}
        .vm-bubble.vm-in{background:#fff;border-bottom-left-radius:5px;border:1px solid #e8eeee;box-shadow:0 1px 4px rgba(0,0,0,.05);}
        .vm-bubble.vm-uploading::after{content:'';position:absolute;inset:0;border-radius:inherit;background:linear-gradient(90deg,transparent,rgba(255,255,255,.3),transparent);background-size:200% 100%;animation:vmShimmer 1.3s infinite;}
        @keyframes vmShimmer{0%{background-position:-200% 0;}100%{background-position:200% 0;}}
        .vm-play{width:38px;height:38px;border-radius:50%;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:transform .14s;}
        .vm-play:active{transform:scale(.9);}
        .vm-bubble.vm-out .vm-play{background:rgba(14,73,80,.13);color:var(--primary-color);}
        .vm-bubble.vm-in .vm-play{background:#e0f2f4;color:var(--primary-color);}
        .vm-ww{flex:1;display:flex;flex-direction:column;gap:4px;min-width:0;}
        .vm-wave{display:flex;align-items:center;gap:2px;height:30px;cursor:pointer;}
        .vm-bar{flex:1;border-radius:2px;min-width:2px;transition:background .1s;}
        .vm-bubble.vm-out .vm-bar{background:rgba(14,73,80,.22);}
        .vm-bubble.vm-out .vm-bar.vm-p{background:var(--primary-color);}
        .vm-bubble.vm-in .vm-bar{background:rgba(14,73,80,.18);}
        .vm-bubble.vm-in .vm-bar.vm-p{background:var(--primary-color);}
        .vm-meta{display:flex;justify-content:space-between;align-items:center;font-size:10px;opacity:.7;}
        .vm-dur{font-variant-numeric:tabular-nums;font-weight:500;}
        .vm-ticks{display:flex;gap:1px;align-items:center;}
        .vm-tick{width:9px;height:5px;border-bottom:2px solid currentColor;border-right:2px solid currentColor;transform:rotate(45deg) translate(-1px,-2px);opacity:.4;display:inline-block;transition:opacity .25s,color .25s;}
        .vm-tick.vm-on{opacity:1;}
        .vm-ticks.vm-heard .vm-tick{color:#4fc3f7;opacity:1;}
    </style>
</head>
<body>
    <div id="chat-header">
        <div class="left-header-actions">
            <button class="back-button" onclick="goBack()">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
            </button>
            {% if contact_name == contact_phone %}
                <button id="saveBtn" onclick="openSaveModal()" title="Save Contact">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z" fill="white"/>
                    </svg>
                </button>
            {% endif %}
        </div>

        <div id="contact-info">
            <div class="contact-avatar">{{ contact_name[0] if contact_name else '?' }}</div>
            <div class="contact-details">
                <div class="contact-name">{{ contact_name }}</div>
                <div class="connection-status">
                    <span class="status-dot status-offline" id="statusDot"></span>
                    <span id="statusText">Loading…</span>
                </div>
            </div>
        </div>

        <div class="header-actions">
            <!-- Empty for balance -->
        </div>
    </div>

    <div id="chat-container">
        <div id="chat">
            <div id="loadingIndicator" class="loading-indicator hidden">Loading more messages...</div>
        </div>
        <div id="typing"></div>
    </div>

    <!-- Voice Recording Overlay -->
    <div id="vm-overlay">
        <div style="display:flex;align-items:center;gap:10px;">
            <div class="vm-dot"></div>
            <span id="vm-rec-label">RECORDING</span>
        </div>
        <canvas id="vm-live-canvas" width="560" height="120"></canvas>
        <div id="vm-rec-timer">0:00</div>
        <div id="vm-cancel-hint">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            Tap ✕ to cancel &nbsp;·&nbsp; ✓ to send
        </div>
        <div class="vm-rec-actions">
            <button class="vm-act-btn" id="vm-cancel-act" onclick="VM.cancel()">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
            <button class="vm-act-btn" id="vm-send-act" onclick="VM.stopAndSend()">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
            </button>
        </div>
    </div>

    <div id="message-box">
        <button id="file-upload-btn" onclick="openFileUploadModal()" title="Send file">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" stroke="currentColor" stroke-width="2"/>
                <polyline points="14,2 14,8 20,8" stroke="currentColor" stroke-width="2"/>
                <line x1="16" y1="13" x2="8" y2="13" stroke="currentColor" stroke-width="2"/>
                <line x1="16" y1="17" x2="8" y2="17" stroke="currentColor" stroke-width="2"/>
            </svg>
        </button>
        <textarea id="message" placeholder="Type a message..." rows="1"></textarea>
        <button id="vm-mic-btn" onclick="VM.toggle()" title="Voice message">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/>
                <path d="M19 10v2a7 7 0 0 1-14 0v-2"/>
                <line x1="12" y1="19" x2="12" y2="23"/>
                <line x1="8" y1="23" x2="16" y2="23"/>
            </svg>
        </button>
        <button id="send-btn" onclick="sendMessage()">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" fill="white"/>
            </svg>
        </button>
    </div>

    <!-- Modern Bottom Sheet File Upload Modal -->
    <div id="fileUploadModal" class="file-upload-modal">
        <div class="file-upload-content">
            <button class="modal-close-btn" onclick="closeFileUploadModal()"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
            <h3>Share File</h3>
            <div class="file-upload-subtitle">Choose what you'd like to share</div>
            
            <div class="file-upload-options">
                <div class="file-upload-option photo-option" onclick="triggerFileInput('image')">
                    <div class="option-icon"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg></div>
                    <div class="option-text">
                        <div class="option-title">Photos</div>
                        <div class="option-description">JPG, PNG, GIF</div>
                    </div>
                </div>
                <div class="file-upload-option video-option" onclick="triggerFileInput('video')">
                    <div class="option-icon"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg></div>
                    <div class="option-text">
                        <div class="option-title">Videos</div>
                        <div class="option-description">MP4, MOV, AVI</div>
                    </div>
                </div>
                <div class="file-upload-option document-option" onclick="triggerFileInput('document')">
                    <div class="option-icon"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg></div>
                    <div class="option-text">
                        <div class="option-title">Documents</div>
                        <div class="option-description">PDF, DOC, TXT</div>
                    </div>
                </div>
            </div>
            
            <input type="file" id="fileInput" accept="*/*">
            
            <div class="file-upload-info">
                <div class="info-text">
                    <span>Max file size: 16MB • All files are securely encrypted</span>
                </div>
            </div>
        </div>
    </div>

    <!-- Save Contact Modal -->
    <div id="saveModal" class="modal">
        <div class="modal-content">
            <h3>Save Contact</h3>
            <form id="saveContactForm">
                <input type="hidden" name="user" value="{{ phone }}">
                <input type="hidden" name="country_code" value="">
                <input type="hidden" name="contact_phone" value="{{ contact_phone }}">
                <input type="text" name="contact_name" placeholder="Enter name" required>
                <div class="modal-buttons">
                    <button type="submit" class="modal-btn primary">Save</button>
                    <button type="button" onclick="closeSaveModal()" class="modal-btn secondary">Cancel</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Context Menu -->
    <div id="contextMenu" class="context-menu">
        <div class="context-menu-item" onclick="copyMessage()">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            <span>Copy</span>
        </div>
        <div class="context-menu-item" onclick="showEmojiMenu()">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>
            <span>React</span>
        </div>
    </div>

    <!-- Emoji Reaction Menu -->
    <div id="emojiMenu" class="emoji-menu">
        <div class="emoji-options">
            <div class="emoji-option" data-emoji="👍">👍</div>
            <div class="emoji-option" data-emoji="❤️">❤️</div>
            <div class="emoji-option" data-emoji="😂">😂</div>
            <div class="emoji-option" data-emoji="😮">😮</div>
            <div class="emoji-option" data-emoji="😢">😢</div>
            <div class="emoji-option" data-emoji="🙏">🙏</div>
        </div>
    </div>

    <!-- Media Viewer -->
    <div id="mediaViewer" class="media-viewer">
        <div class="media-viewer-content">
            <button class="close-viewer" onclick="closeMediaViewer()"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
            <img id="viewerImage" src="" alt="">
            <video id="viewerVideo" controls style="display: none;"></video>
        </div>
    </div>

    <script src="https://cdn.socket.io/4.7.2/socket.io.min.js" crossorigin="anonymous"></script>
    <script>
        let myPhone = {{ phone|tojson }};
        let contactPhone = {{ contact_phone|tojson }};
        const typingDiv = document.getElementById('typing');
        let chatDiv = document.getElementById('chat');
        const messageInput = document.getElementById('message');
        const messageBox = document.getElementById('message-box');
        const statusDot = document.getElementById('statusDot');
        const statusText = document.getElementById('statusText');
        const contextMenu = document.getElementById('contextMenu');
        const emojiMenu = document.getElementById('emojiMenu');
        const fileInput = document.getElementById('fileInput');
        const fileUploadModal = document.getElementById('fileUploadModal');
        const mediaViewer = document.getElementById('mediaViewer');
        const viewerImage = document.getElementById('viewerImage');
        const viewerVideo = document.getElementById('viewerVideo');
        const loadingIndicator = document.getElementById('loadingIndicator');
        
        let typingTimeout;
        let isConnected = false;
        let lastSender = null;
        let messageGroups = {};
        let groupCounter = 0;
        let currentGroupKey = null;
        let lastMarkedSeenTime = 0;
        let selectedMessage = null;
        let selectedMessageId = null;
        let contextMenuMessageId = null;

        // Enhanced variables for better performance
        let currentPage = 1;
        let isLoading = false;
        let hasMoreMessages = true;
        let scrollPositionBeforeLoad = 0;

        // Context Menu Variables
        let pressTimer;
        let longPressActive = false;

        function goBack() {
            window.location.href = '/main?phone=' + encodeURIComponent(myPhone);
        }

        function autoResizeTextarea() {
            messageInput.style.height = 'auto';
            const scrollHeight = messageInput.scrollHeight;
            const maxHeight = 120;
            if (scrollHeight <= maxHeight) {
                messageInput.style.height = scrollHeight + 'px';
                messageBox.style.minHeight = Math.max(70, scrollHeight + 22) + 'px';
            } else {
                messageInput.style.height = maxHeight + 'px';
                messageInput.style.overflowY = 'auto';
                messageBox.style.minHeight = '140px';
            }
            scrollToBottom(false);
        }

        messageInput.addEventListener('input', autoResizeTextarea);
        messageInput.addEventListener('keydown', autoResizeTextarea);
        messageInput.addEventListener('keyup', autoResizeTextarea);
        messageInput.addEventListener('focus', function() {
            setTimeout(autoResizeTextarea, 10);
        });

        function resetTextareaHeight() {
            setTimeout(() => {
                messageInput.style.height = 'auto';
                messageInput.style.overflowY = 'hidden';
                messageBox.style.minHeight = '70px';
            }, 100);
        }

        // ==================== FIXED CONTEXT MENU SYSTEM ====================
        function initializeContextMenuSystem() {
            console.log('Initializing fixed context menu system...');
            
            // Remove any existing event listeners first
            document.removeEventListener('contextmenu', handleContextMenu);
            document.removeEventListener('touchstart', handleTouchStart);
            document.removeEventListener('touchend', handleTouchEnd);
            document.removeEventListener('touchmove', handleTouchMove);
            
            // Add new event listeners
            document.addEventListener('contextmenu', handleContextMenu);
            document.addEventListener('touchstart', handleTouchStart);
            document.addEventListener('touchend', handleTouchEnd);
            document.addEventListener('touchmove', handleTouchMove);
            
            console.log('Fixed context menu system initialized');
        }

        function handleContextMenu(e) {
            const bubble = e.target.closest('.bubble, .vm-bubble, .gvm-bubble');
            if (bubble && bubble.dataset.messageId) {
                e.preventDefault();
                e.stopPropagation();
                showContextMenu(e.clientX, e.clientY, bubble.dataset.messageId, bubble);
            }
        }

        function handleTouchStart(e) {
            // Don't start a new long-press if a menu is already open
            if (emojiMenu.style.display === 'block' || contextMenu.style.display === 'block') return;
            const bubble = e.target.closest('.bubble, .vm-bubble, .gvm-bubble');
            if (bubble && bubble.dataset.messageId) {
                longPressActive = true;
                pressTimer = setTimeout(() => {
                    const touch = e.touches[0];
                    showContextMenu(touch.clientX, touch.clientY, bubble.dataset.messageId, bubble);
                    longPressActive = false;
                    e.preventDefault();
                }, 500);
            }
        }

        function handleTouchEnd(e) {
            // Don't cancel anything if the user is tapping inside the emoji menu
            if (emojiMenu.style.display === 'block' && emojiMenu.contains(e.target)) return;
            clearTimeout(pressTimer);
            longPressActive = false;
        }

        function handleTouchMove(e) {
            if (emojiMenu.style.display === 'block' && emojiMenu.contains(e.target)) return;
            clearTimeout(pressTimer);
            longPressActive = false;
        }

        function showContextMenu(x, y, messageId, bubble) {
            // Hide any existing menus immediately (clear all state for a fresh open)
            hideContextMenu(true);
            hideEmojiMenu(true);
            
            selectedMessage = bubble;
            selectedMessageId = messageId;
            contextMenuMessageId = messageId;
            
            // Position calculation
            const menuWidth = 160;
            const menuHeight = 180;
            const viewportWidth = window.innerWidth;
            const viewportHeight = window.innerHeight;
            
            let adjustedX = Math.min(x, viewportWidth - menuWidth - 10);
            let adjustedY = Math.min(y, viewportHeight - menuHeight - 10);
            
            // Show menu immediately
            contextMenu.style.display = 'block';
            contextMenu.style.left = adjustedX + 'px';
            contextMenu.style.top = adjustedY + 'px';
            
            // Select bubble
            document.querySelectorAll('.bubble.selected, .vm-bubble.selected, .gvm-bubble.selected').forEach(b => b.classList.remove('selected'));
            bubble.classList.add('selected');
            
            console.log('Context menu shown for message:', messageId);
        }

        function hideContextMenu(clearState = true) {
            contextMenu.style.display = 'none';
            if (clearState) {
                if (selectedMessage) {
                    selectedMessage.classList.remove('selected');
                    selectedMessage = null;
                }
                contextMenuMessageId = null;
            }
        }

        function hideEmojiMenu(clearState = true) {
            emojiMenu.style.display = 'none';
            if (clearState) {
                if (selectedMessage) {
                    selectedMessage.classList.remove('selected');
                    selectedMessage = null;
                }
                contextMenuMessageId = null;
            }
        }

        function showEmojiMenu() {
            if (!selectedMessage || !contextMenuMessageId) return;
            
            const rect = selectedMessage.getBoundingClientRect();
            const menuWidth = 240;
            const menuHeight = 60;
            const viewportWidth = window.innerWidth;
            const viewportHeight = window.innerHeight;
            
            let adjustedX = rect.left + rect.width / 2 - menuWidth / 2;
            let adjustedY = rect.top - menuHeight - 10;
            
            if (adjustedX < 10) adjustedX = 10;
            if (adjustedX + menuWidth > viewportWidth) adjustedX = viewportWidth - menuWidth - 10;
            if (adjustedY < 10) adjustedY = rect.bottom + 10;
            
            emojiMenu.style.display = 'block';
            emojiMenu.style.left = adjustedX + 'px';
            emojiMenu.style.top = adjustedY + 'px';

            // Hide the context menu visually but keep contextMenuMessageId and selectedMessage intact
            hideContextMenu(false);
        }

        function copyMessage() {
            if (!selectedMessage) return;
            
            const messageContent = selectedMessage.querySelector('div:first-child');
            if (messageContent) {
                const textToCopy = messageContent.textContent;
                navigator.clipboard.writeText(textToCopy).then(() => {
                    showCopyFeedback('Copied to clipboard!');
                }).catch(err => {
                    console.error('Failed to copy: ', err);
                    showCopyFeedback('Copy failed!');
                });
            }
            
            hideContextMenu();
        }

        function showCopyFeedback(message) {
            const feedback = document.createElement('div');
            feedback.className = 'copy-feedback';
            feedback.textContent = message;
            feedback.style.left = '50%';
            feedback.style.top = '50%';
            feedback.style.transform = 'translate(-50%, -50%)';
            document.body.appendChild(feedback);
            
            setTimeout(() => {
                document.body.removeChild(feedback);
            }, 2000);
        }

        function addReaction(emoji) {
            if (!contextMenuMessageId) return;
            const messageId = contextMenuMessageId;
            if (String(messageId).startsWith('temp_') || String(messageId).startsWith('vmtmp_') || String(messageId).startsWith('gvmtmp_')) {
                hideEmojiMenu();
                return;
            }
            // Don't do optimistic update — server reaction_updated fires fast and is authoritative
            socket.emit('add_reaction', { message_id: messageId, emoji, user_phone: myPhone });
            hideEmojiMenu(true);
        }

        function updateReactionsOnBubble(messageId, reactingUser, emoji, source, serverReactions) {
            const bubble = document.querySelector('[data-message-id="' + String(messageId) + '"]');
            if (!bubble) return;

            let container = bubble.querySelector('.message-reactions');

            if (source === 'server' && serverReactions) {
                if (container) container.remove();
                if (serverReactions.length > 0) {
                    // Voice bubbles have no .status/.message-time — just append
                    const anchor = bubble.querySelector('.status') || bubble.querySelector('.message-time') || null;
                    if (anchor) bubble.insertBefore(createReactionsElement(serverReactions, messageId), anchor);
                    else bubble.appendChild(createReactionsElement(serverReactions, messageId));
                }
                return;
            }

            if (!container) {
                container = document.createElement('div');
                container.className = 'message-reactions';
                const anchor = bubble.querySelector('.status') || bubble.querySelector('.message-time') || null;
                if (anchor) bubble.insertBefore(container, anchor);
                else bubble.appendChild(container);
            }

            const allPips = Array.from(container.querySelectorAll('.reaction'));
            const myPip = allPips.find(el => el.dataset.reactingUser === reactingUser);
            const emojiPip = allPips.find(el => el.dataset.emoji === emoji);

            if (myPip && myPip.dataset.emoji === emoji) {
                const countEl = myPip.querySelector('.reaction-count');
                const newCount = parseInt(countEl.textContent) - 1;
                if (newCount <= 0) myPip.remove();
                else countEl.textContent = newCount;
            } else {
                if (myPip) {
                    const countEl = myPip.querySelector('.reaction-count');
                    const newCount = parseInt(countEl.textContent) - 1;
                    if (newCount <= 0) myPip.remove();
                    else countEl.textContent = newCount;
                }
                if (emojiPip) {
                    const countEl = emojiPip.querySelector('.reaction-count');
                    countEl.textContent = parseInt(countEl.textContent) + 1;
                    emojiPip.dataset.reactingUser = reactingUser;
                } else {
                    const pip = document.createElement('div');
                    pip.className = 'reaction';
                    pip.dataset.emoji = emoji;
                    pip.dataset.reactingUser = String(reactingUser);
                    pip.innerHTML = '<span class="reaction-emoji">' + emoji + '</span><span class="reaction-count">1</span>';
                    container.appendChild(pip);
                }
            }

            if (container.children.length === 0) container.remove();
        }

        // ==================== ENHANCED MESSAGE LOADING ====================
        function onChatScroll() {
            if (chatDiv.scrollTop < 100 && !isLoading && hasMoreMessages) {
                loadMoreMessages();
            }
        }

        function setupInfiniteScroll() {
            chatDiv.removeEventListener('scroll', onChatScroll);
            chatDiv.addEventListener('scroll', onChatScroll);
        }

        async function loadMoreMessages() {
            if (isLoading || !hasMoreMessages) return;
            
            isLoading = true;
            currentPage++;
            scrollPositionBeforeLoad = chatDiv.scrollHeight - chatDiv.scrollTop;
            
            loadingIndicator.classList.remove('hidden');
            
            try {
                const response = await fetch(`/api/get_messages?user_phone=${encodeURIComponent(myPhone)}&contact_phone=${encodeURIComponent(contactPhone)}&page=${currentPage}&limit=50`);
                const newMessages = await response.json();
                
                if (newMessages.length === 0) {
                    hasMoreMessages = false;
                    loadingIndicator.textContent = 'No more messages';
                    return;
                }
                
                // Prepend messages to chat
                prependMessages(newMessages);
                
                // Restore scroll position
                const newScrollHeight = chatDiv.scrollHeight;
                chatDiv.scrollTop = newScrollHeight - scrollPositionBeforeLoad;
                
            } catch (error) {
                console.error('Error loading more messages:', error);
                currentPage--; // Revert page on error
            } finally {
                isLoading = false;
                loadingIndicator.classList.add('hidden');
                
                // Re-initialize context menu for new messages
                setTimeout(initializeContextMenuSystem, 100);
            }
        }

        function prependMessages(messages) {
            const fragment = document.createDocumentFragment();
            let currentGroup = null;
            let lastMessageSender = null;

            messages.forEach(message => {
                if (message.sender !== lastMessageSender) {
                    currentGroup = createMessageGroup(message.sender === String(myPhone));
                    fragment.appendChild(currentGroup);
                }
                if (message.message_type === 'text') {
                    const messageElement = createTextMessage(message);
                    currentGroup.appendChild(messageElement);
                } else {
                    const messageElement = createMediaMessage(message);
                    currentGroup.appendChild(messageElement);
                }
                lastMessageSender = message.sender;
            });

            chatDiv.prepend(fragment);
        }

        function createMessageGroup(isSent) {
            const group = document.createElement('div');
            group.className = `message-group ${isSent ? 'sent-group' : 'received-group'}`;
            return group;
        }

        function createTextMessage(message) {
            const bubble = document.createElement('div');
            bubble.className = `bubble ${message.sender === String(myPhone) ? 'sent' : 'received'} message-appear`;
            
            // Use database ID or temp ID
            if (message.id && message.id !== 'null' && !message.id.toString().startsWith('temp_')) {
                bubble.dataset.messageId = message.id;
                console.log(' Message with DB ID:', message.id);
            } else {
                const tempId = 'temp_' + Date.now();
                bubble.dataset.messageId = tempId;
                console.log('Message with temp ID:', tempId);
            }

            const messageContent = document.createElement('div');
            messageContent.textContent = message.message;
            bubble.appendChild(messageContent);

            // Add reactions if any
            if (message.reactions && message.reactions.length > 0) {
                bubble.appendChild(createReactionsElement(message.reactions, message.id));
            }

            // Add status and time
            if (message.sender === String(myPhone)) {
                bubble.appendChild(createStatusElement(message.status));
            }
            bubble.appendChild(createTimeElement());

            return bubble;
        }

        function createMediaMessage(message) {
            const bubble = document.createElement('div');
            bubble.className = `bubble ${message.sender === String(myPhone) ? 'sent' : 'received'} media-message message-appear`;
            
            // Use database ID or temp ID
            if (message.id && message.id !== 'null' && !message.id.toString().startsWith('temp_')) {
                bubble.dataset.messageId = message.id;
                console.log('Media message with DB ID:', message.id);
            } else {
                const tempId = 'temp_' + Date.now();
                bubble.dataset.messageId = tempId;
                console.log('Media message with temp ID:', tempId);
            }

            // Media content will be added here based on message type
            if (message.message_type === 'image') {
                bubble.appendChild(createImageMessage(message));
            } else if (message.message_type === 'video') {
                bubble.appendChild(createVideoMessage(message));
            } else {
                bubble.appendChild(createFileMessage(message));
            }

            // Add reactions if any
            if (message.reactions && message.reactions.length > 0) {
                bubble.appendChild(createReactionsElement(message.reactions, message.id));
            }

            // Add status and time
            if (message.sender === String(myPhone)) {
                bubble.appendChild(createStatusElement(message.status));
            }
            bubble.appendChild(createTimeElement());

            return bubble;
        }

        function createReactionsElement(reactions, messageId) {
            const container = document.createElement('div');
            container.className = 'message-reactions';

            const emojiMap = {};
            reactions.forEach(reaction => {
                if (!emojiMap[reaction.emoji]) emojiMap[reaction.emoji] = [];
                emojiMap[reaction.emoji].push(reaction.user_phone);
            });

            Object.entries(emojiMap).forEach(([emoji, users]) => {
                const pip = document.createElement('div');
                pip.className = 'reaction';
                pip.dataset.emoji = emoji;
                const isMine = users.map(String).includes(String(myPhone));
                if (isMine) {
                    pip.dataset.reactingUser = String(myPhone);
                    pip.classList.add('reaction-mine');
                }
                pip.innerHTML = '<span class="reaction-emoji">' + emoji + '</span>'
                    + (users.length > 1 ? '<span class="reaction-count">' + users.length + '</span>' : '');

                const emitReact = () => {
                    if (!messageId) return;
                    socket.emit('add_reaction', { message_id: messageId, emoji, user_phone: myPhone });
                };

                // Track whether the touch actually started on this pip
                let touchStartedOnPip = false;
                pip.addEventListener('touchstart', function(e) {
                    touchStartedOnPip = true;
                    e.stopPropagation();
                }, { passive: true });
                pip.addEventListener('touchend', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    if (touchStartedOnPip) { touchStartedOnPip = false; emitReact(); }
                });
                pip.addEventListener('touchcancel', () => { touchStartedOnPip = false; });
                pip.addEventListener('click', function(e) {
                    e.stopPropagation();
                    emitReact();
                });

                container.appendChild(pip);
            });

            return container;
        }

        function createStatusElement(status) {
            const statusDiv = document.createElement('div');
            statusDiv.className = 'status';
            statusDiv.innerHTML = status === 'seen' ? '<svg width="18" height="14" viewBox="0 0 28 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/><polyline points="26 6 15 17"/></svg>' : (status === 'delivered') ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>' : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
            return statusDiv;
        }

        function createTimeElement(timestamp) {
            const timeDiv = document.createElement('div');
            timeDiv.className = 'message-time';
            timeDiv.textContent = timestamp
                ? new Date(timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})
                : new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
            return timeDiv;
        }

        // ==================== EVENT LISTENERS ====================
        let _emojiJustPicked = false;
        document.addEventListener('click', function(e) {
            if (_emojiJustPicked) { _emojiJustPicked = false; return; }
            if (contextMenu.style.display === 'block' && !contextMenu.contains(e.target)) {
                hideContextMenu(true);
            }
            if (emojiMenu.style.display === 'block' && !emojiMenu.contains(e.target)) {
                hideEmojiMenu(true);
            }
        });

        contextMenu.addEventListener('click', function(e) {
            e.stopPropagation();
        });

        // Delegated click handler for emoji options
        function handleEmojiPick(e) {
            const option = e.target.closest('.emoji-option');
            if (option && option.dataset.emoji) {
                e.stopPropagation();
                addReaction(option.dataset.emoji);
            }
        }
        emojiMenu.addEventListener('click', handleEmojiPick);
        emojiMenu.addEventListener('touchend', function(e) {
            const option = e.target.closest('.emoji-option');
            if (option && option.dataset.emoji) {
                e.preventDefault();
                e.stopPropagation();
                _emojiJustPicked = true;
                const messageId = contextMenuMessageId;
                const emoji = option.dataset.emoji;
                if (!messageId) return;
                hideEmojiMenu(true);
                if (String(messageId).startsWith('temp_') || String(messageId).startsWith('vmtmp_') || String(messageId).startsWith('gvmtmp_')) return;
                socket.emit('add_reaction', { message_id: messageId, emoji, user_phone: myPhone });
            }
        });

        document.getElementById('saveModal').addEventListener('click', function(e) {
            if (e.target === this) closeSaveModal();
        });

        document.getElementById('fileUploadModal').addEventListener('click', function(e) {
            if (e.target === this) closeFileUploadModal();
        });

        // Escape key to close menus
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeFileUploadModal();
                closeSaveModal();
                closeMediaViewer();
                hideContextMenu(true);
                hideEmojiMenu(true);
            }
        });

        // Load messages from API
        function scrollToBottom(smooth = false) {
            requestAnimationFrame(() => {
                chatDiv.scrollTop = chatDiv.scrollHeight;
            });
        }

        function renderMessageList(all) {
            chatDiv.innerHTML = '<div id="loadingIndicator" class="loading-indicator hidden">Loading more messages...</div>';
            messageGroups = {};
            lastSender = null;
            groupCounter = 0;
            currentGroupKey = null;
            currentPage = 1;
            hasMoreMessages = true;
            isLoading = false;

            const frag = document.createDocumentFragment();
            all.forEach(m => {
                if (m.message_type === 'voice') {
                    const el = VM.renderBubble(m);
                    const group = ensureGroup(m.sender, frag);
                    group.appendChild(el);
                    lastSender = m.sender;
                } else if (m.message_type === 'text') {
                    addMessage(m.sender, m.message, m.status, m.id, m.reactions || [], m.timestamp, frag);
                } else {
                    addMediaMessage(m.sender, m.message_type, m.file_path, m.file_name, m.file_size, m.status, m.id, m.reactions || [], frag, m.timestamp);
                }
            });
            chatDiv.appendChild(frag);
            chatDiv.querySelectorAll('.message-appear').forEach(el => el.classList.remove('message-appear'));
            lastSender = null;
            currentGroupKey = null;
            scrollToBottom(false);
            setupInfiniteScroll();
            initializeContextMenuSystem();
        }

        function loadMessages() {
            // Step 1: Render server-side messages instantly (zero network wait)
            const seedMessages = {{ messages|tojson }};
            if (seedMessages && seedMessages.length > 0) {
                renderMessageList(seedMessages.map(m => ({ ...m, message_type: m.message_type || 'text' })));
            }

            // Step 2: Silently fetch fresh data (includes voice + updated reactions)
            const textUrl  = `/api/get_messages?user_phone=${encodeURIComponent(myPhone)}&contact_phone=${encodeURIComponent(contactPhone)}&page=1&limit=50`;
            const voiceUrl = `/api/voice/history?sender=${encodeURIComponent(myPhone)}&receiver=${encodeURIComponent(contactPhone)}&limit=50`;

            Promise.all([
                fetch(textUrl).then(r => r.json()).catch(() => null),
                fetch(voiceUrl).then(r => r.json()).catch(() => [])
            ]).then(([textMsgs, voiceMsgs]) => {
                if (!textMsgs) return; // network error — keep seed render
                voiceMsgs.forEach(m => { m.message_type = 'voice'; });
                const all = [...textMsgs, ...voiceMsgs].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
                renderMessageList(all);
            }).catch(() => { /* seed render stays */ });
        }

        // Enhanced socket connection
        var socket = io({
            reconnection: true,
            reconnectionDelay: 2000,
            reconnectionDelayMax: 10000,
            reconnectionAttempts: Infinity,
            timeout: 30000,
            autoConnect: true,
            transports: ['polling', 'websocket'],
            upgrade: true,
        });

        // Connection quality monitoring
        let connectionAttempts = 0;
        const MAX_CONNECTION_ATTEMPTS = 5;

        // ── Presence helpers ─────────────────────────────────────────
        function formatLastSeen(isoStr) {
            if (!isoStr) return 'Offline';
            const diff = Math.floor((Date.now() - new Date(isoStr)) / 1000);
            if (diff < 60)  return 'Last seen just now';
            if (diff < 3600) {
                const m = Math.floor(diff / 60);
                return `Last seen ${m} min${m>1?'s':''} ago`;
            }
            if (diff < 86400) {
                const h = Math.floor(diff / 3600);
                return `Last seen ${h} hour${h>1?'s':''} ago`;
            }
            const d = Math.floor(diff / 86400);
            return `Last seen ${d} day${d>1?'s':''} ago`;
        }

        function setPresence(status, lastOnline) {
            if (status === 'online') {
                statusDot.className = 'status-dot status-online';
                statusText.textContent = 'Online';
            } else {
                statusDot.className = 'status-dot status-offline';
                statusText.textContent = formatLastSeen(lastOnline);
            }
        }

        function updateConnectionStatus(connected) {
            isConnected = connected;
            // Only update the dot for our own socket state if the contact
            // presence hasn't been received yet
            if (!connected) {
                statusDot.className = 'status-dot status-offline';
                statusText.textContent = 'Reconnecting…';
            }
        }

        // Listen for real-time presence updates from the server
        socket.on('presence_update', data => {
            if (String(data.phone) === String(contactPhone)) {
                setPresence(data.status, data.last_online);
            }
        });

        // Heartbeat — tell server we're still here every 30s
        setInterval(() => {
            if (socket.connected) {
                socket.emit('heartbeat', { phone: String(myPhone) });
            }
        }, 30000);
        // ─────────────────────────────────────────────────────────────

        socket.on('connect', () => {
            console.log('Connected to server with ID:', socket.id);
            connectionAttempts = 0;
            isConnected = true;
            updateConnectionStatus(true);
            joinChatRoom();
        });

        function joinChatRoom() {
            if (socket.connected) {
                socket.emit('join', {
                    user: myPhone,
                    contact: contactPhone
                });
            }
        }

        // join_success confirms the room was joined
        socket.on('join_success', () => {
            markAllMessagesAsSeen();
        });

        // Handle connection errors
        socket.on('connect_error', (error) => {
            console.error('Connection error:', error);
            connectionAttempts++;
            
            if (connectionAttempts >= MAX_CONNECTION_ATTEMPTS) {
                console.error(' Max connection attempts reached');
                showToast('Connection lost. Retrying…', 5000);
            } else {
                console.log(` Connection attempt ${connectionAttempts}/${MAX_CONNECTION_ATTEMPTS}`);
            }
            
            updateConnectionStatus(false);
        });

        // Modern Bottom Sheet File Upload Functions
        function openFileUploadModal() {
            fileUploadModal.style.display = 'flex';
        }

        function closeFileUploadModal() {
            fileUploadModal.style.display = 'none';
            fileInput.value = '';
        }

        fileUploadModal.addEventListener('click', function(e) {
            if (e.target === this) {
                closeFileUploadModal();
            }
        });

        function triggerFileInput(fileType) {
            let accept = '';
            switch(fileType) {
                case 'image':
                    accept = 'image/*';
                    break;
                case 'video':
                    accept = 'video/*';
                    break;
                case 'document':
                    accept = '*/*';
                    break;
            }
            fileInput.accept = accept;
            fileInput.onchange = function() {
                if (this.files.length > 0) {
                    uploadFile(this.files[0], fileType);
                }
            };
            fileInput.click();
            closeFileUploadModal();
        }

        function getFileIcon(fileType, fileName) {
            const extension = fileName ? fileName.split('.').pop()?.toLowerCase() : '';

            if (fileType === 'image') return '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>';
            if (fileType === 'video') return '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>';

            const svgDoc = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
            const svgZip = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10V8l-6-6H5a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h7"/><path d="M15 2v6h6"/><path d="M18 22v-6m0 0l-2 2m2-2l2 2"/></svg>';

            const docIcons = {
                'pdf': svgDoc, 'doc': svgDoc, 'docx': svgDoc,
                'txt': svgDoc, 'ppt': svgDoc, 'pptx': svgDoc,
                'xls': svgDoc, 'xlsx': svgDoc,
                'zip': svgZip, 'rar': svgZip
            };

            return docIcons[extension] || svgDoc;
        }

        function getFileTypeClass(fileType) {
            switch(fileType) {
                case 'image': return 'photo';
                case 'video': return 'video';
                default: return 'document';
            }
        }

        function uploadFile(file, fileType) {
            if (!file) return;

            const maxSize = 16 * 1024 * 1024;
            if (file.size > maxSize) {
                alert('File size too large. Maximum size is 16MB.');
                return;
            }

            const formData = new FormData();
            formData.append('file', file);
            formData.append('sender', myPhone);
            formData.append('receiver', contactPhone);

            // Show uploading indicator
            const tempMessageId = 'temp_' + Date.now();
            addTempMediaMessage(file, tempMessageId);

            fetch('/upload_file', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Remove temp message and add real one
                    removeTempMessage(tempMessageId);
                    addMediaMessage(myPhone, data.file_type, data.file_path, data.file_name, data.file_size, 'sent', data.message_id, []);
                    
                    // Emit socket event for real-time update
                    socket.emit('send_file_message', {
                        sender: String(myPhone),
                        receiver: String(contactPhone),
                        message_type: data.file_type,
                        file_path: data.file_path,
                        file_name: data.file_name,
                        file_size: data.file_size,
                        message_id: data.message_id,
                        timestamp: new Date().toISOString()
                    });
                } else {
                    throw new Error(data.error || 'Upload failed');
                }
            })
            .catch(error => {
                console.error('Upload error:', error);
                removeTempMessage(tempMessageId);
                alert('File upload failed: ' + error.message);
            });
        }

        function addTempMediaMessage(file, tempId) {
            const isSent = true;
            const messageGroupId = 'sent';

            if (lastSender !== String(myPhone) || !messageGroups[messageGroupId]) {
                messageGroups[messageGroupId] = document.createElement('div');
                messageGroups[messageGroupId].className = 'message-group sent-group';
                chatDiv.appendChild(messageGroups[messageGroupId]);
            }

            const bubble = document.createElement('div');
            bubble.className = 'bubble sent message-appear';
            bubble.id = tempId;

            const messageContent = document.createElement('div');
            messageContent.textContent = `Uploading ${file.name}...`;
            messageContent.style.fontStyle = 'italic';
            messageContent.style.color = '#666';
            bubble.appendChild(messageContent);

            messageGroups[messageGroupId].appendChild(bubble);
            lastSender = String(myPhone);
            scrollToBottom(true);
        }

        function removeTempMessage(messageId) {
            const tempElement = document.getElementById(messageId);
            if (tempElement) {
                tempElement.remove();
            }
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function downloadFile(filePath, fileName) {
            const link = document.createElement('a');
            link.href = `/uploads/${filePath}`;
            link.download = fileName;
            link.click();
        }

        function viewMedia(filePath, mediaType) {
            const mediaUrl = `/uploads/${filePath}`;
            
            if (mediaType === 'image') {
                viewerImage.src = mediaUrl;
                viewerImage.style.display = 'block';
                viewerVideo.style.display = 'none';
            } else if (mediaType === 'video') {
                viewerVideo.src = mediaUrl;
                viewerVideo.style.display = 'block';
                viewerImage.style.display = 'none';
            }
            
            mediaViewer.style.display = 'flex';
        }

        function closeMediaViewer() {
            mediaViewer.style.display = 'none';
            viewerVideo.pause();
        }

        function addMediaMessage(sender, messageType, filePath, fileName, fileSize, status, messageId = null, reactions = [], frag = null, timestamp = null) {
            const isSent = sender === String(myPhone);
            const target = frag || chatDiv;
            const group = ensureGroup(sender, target);

            const bubble = document.createElement('div');
            bubble.className = `bubble ${isSent ? 'sent' : 'received'} media-message message-appear`;
            
            if (messageId && messageId !== 'null' && !messageId.toString().startsWith('temp_')) {
                bubble.dataset.messageId = messageId;
                console.log('Added media with DB ID:', messageId);
            } else {
                const tempId = 'temp_' + Date.now();
                bubble.dataset.messageId = tempId;
                console.log('Added media with temp ID:', tempId);
            }

            const fileIcon = getFileIcon(messageType, fileName);
            const fileTypeClass = getFileTypeClass(messageType);

            if (messageType === 'image') {
                const mediaPreview = document.createElement('div');
                mediaPreview.className = 'media-preview';
                mediaPreview.onclick = () => viewMedia(filePath, 'image');

                const img = document.createElement('img');
                img.src = `/uploads/${filePath}`;
                img.alt = '';
                img.loading = 'lazy';

                mediaPreview.appendChild(img);
                bubble.appendChild(mediaPreview);
                
            } else if (messageType === 'video') {
                const mediaContainer = document.createElement('div');
                mediaContainer.style.position = 'relative';
                
                const mediaPreview = document.createElement('div');
                mediaPreview.className = 'media-preview';
                mediaPreview.onclick = () => viewMedia(filePath, 'video');
                
                const video = document.createElement('video');
                video.src = `/uploads/${filePath}`;
                video.alt = fileName;
                video.controls = false;
                
                const playOverlay = document.createElement('div');
                playOverlay.style.cssText = `
                    position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
                    background: rgba(0,0,0,0.7); border-radius: 50%; width: 50px; height: 50px;
                    display: flex; align-items: center; justify-content: center; color: white;
                    font-size: 20px; pointer-events: none;
                `;
                playOverlay.innerHTML = '<svg width="22" height="22" viewBox="0 0 24 24" fill="white" stroke="none"><polygon points="5 3 19 12 5 21 5 3"/></svg>';
                
                mediaPreview.appendChild(video);
                mediaPreview.appendChild(playOverlay);
                mediaContainer.appendChild(mediaPreview);
                
                const mediaInfo = document.createElement('div');
                mediaInfo.className = 'media-info';
                
                const fileNameDiv = document.createElement('div');
                fileNameDiv.className = 'media-filename';
                fileNameDiv.textContent = fileName;
                
                const metadataDiv = document.createElement('div');
                metadataDiv.className = 'media-metadata';
                
                const sizeDiv = document.createElement('div');
                sizeDiv.className = 'media-size';
                sizeDiv.textContent = formatFileSize(fileSize);
                
                const typeDiv = document.createElement('div');
                typeDiv.className = 'media-type';
                typeDiv.textContent = 'VIDEO';
                
                metadataDiv.appendChild(sizeDiv);
                metadataDiv.appendChild(typeDiv);
                
                mediaInfo.appendChild(fileNameDiv);
                mediaInfo.appendChild(metadataDiv);
                mediaContainer.appendChild(mediaInfo);
                
                bubble.appendChild(mediaContainer);
                
            } else {
                const fileMessage = document.createElement('div');
                fileMessage.className = 'file-message';
                fileMessage.onclick = () => downloadFile(filePath, fileName);
                
                const fileIconDiv = document.createElement('div');
                fileIconDiv.className = `file-icon ${fileTypeClass}`;
                fileIconDiv.innerHTML = fileIcon;
                
                const fileInfo = document.createElement('div');
                fileInfo.className = 'file-info';
                
                const fileNameDiv = document.createElement('div');
                fileNameDiv.className = 'file-name';
                fileNameDiv.textContent = fileName;
                
                const fileDetails = document.createElement('div');
                fileDetails.className = 'file-details';
                
                const fileSizeDiv = document.createElement('div');
                fileSizeDiv.className = 'file-size';
                fileSizeDiv.textContent = formatFileSize(fileSize);
                
                const fileTypeDiv = document.createElement('div');
                fileTypeDiv.className = 'file-type';
                fileTypeDiv.textContent = messageType.toUpperCase();
                
                fileDetails.appendChild(fileSizeDiv);
                fileDetails.appendChild(fileTypeDiv);
                
                fileInfo.appendChild(fileNameDiv);
                fileInfo.appendChild(fileDetails);
                
                const downloadBtn = document.createElement('button');
                downloadBtn.className = 'download-btn';
                downloadBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right:5px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Download';
                downloadBtn.onclick = (e) => {
                    e.stopPropagation();
                    downloadFile(filePath, fileName);
                };
                
                fileMessage.appendChild(fileIconDiv);
                fileMessage.appendChild(fileInfo);
                fileMessage.appendChild(downloadBtn);
                
                bubble.appendChild(fileMessage);
            }

            // Add reactions if any
            if (reactions && reactions.length > 0) {
                const reactionsContainer = document.createElement('div');
                reactionsContainer.className = 'message-reactions';
                
                const reactionCounts = {};
                reactions.forEach(reaction => {
                    if (!reactionCounts[reaction.emoji]) {
                        reactionCounts[reaction.emoji] = 0;
                    }
                    reactionCounts[reaction.emoji]++;
                });

                Object.entries(reactionCounts).forEach(([emoji, count]) => {
                    const reactionElement = document.createElement('div');
                    reactionElement.className = 'reaction';
                    reactionElement.innerHTML = `
                        <span class="reaction-emoji">${emoji}</span>
                        <span class="reaction-count">${count}</span>
                    `;
                    reactionsContainer.appendChild(reactionElement);
                });

                bubble.appendChild(reactionsContainer);
            }

            if (isSent) {
                const statusDiv = document.createElement('div');
                statusDiv.className = 'status';
                statusDiv.innerHTML = (status === 'seen') ? '<svg width="18" height="14" viewBox="0 0 28 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/><polyline points="26 6 15 17"/></svg>' : (status === 'delivered') ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>' : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
                bubble.appendChild(statusDiv);
            }

            const timeDiv = document.createElement('div');
            timeDiv.className = 'message-time';
            timeDiv.textContent = timestamp
                ? new Date(timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})
                : new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
            bubble.appendChild(timeDiv);

            group.appendChild(bubble);
            lastSender = sender;

            if (!frag) {
                scrollToBottom(true);
                if (!isSent) {
                    setTimeout(() => {
                        markAllMessagesAsSeen();
                    }, 500);
                }
            }
        }

        // Close media viewer when clicking outside
        mediaViewer.addEventListener('click', function(e) {
            if (e.target === this) {
                closeMediaViewer();
            }
        });

        socket.on('disconnect', () => {
            console.log(' Disconnected from server');
            updateConnectionStatus(false);
        });

        // Handle socket errors
        socket.on('error', (error) => {
            console.error('Socket error:', error);
            if (error.message && error.message.includes('unauthorized')) {
                console.log(' Authentication error, reloading...');
                setTimeout(() => location.reload(), 2000);
            }
        });

        messageInput.addEventListener('input', ()=>{
            if(!isConnected) return;
            socket.emit('typing', {actor: myPhone, target: contactPhone});
            clearTimeout(typingTimeout);
            typingTimeout = setTimeout(()=>{
                socket.emit('stop_typing', {actor: myPhone, target: contactPhone});
            }, 2000);
        });

        socket.on('typing', data=>{
            if(data.actor === contactPhone) typingDiv.textContent = 'Typing...';
        });

        socket.on('stop_typing', data=>{
            if(data.actor === contactPhone) typingDiv.textContent = '';
        });

        // ── Unified group manager ─────────────────────────────────────
        function ensureGroup(sender, target) {
            const isSent = sender === String(myPhone);
            const existingGroup = messageGroups[currentGroupKey];
            // Need a new group if: sender changed, no group exists, or existing
            // group is not inside the target (e.g. was built inside a fragment)
            const needsNewGroup = lastSender !== sender
                || !currentGroupKey
                || !existingGroup
                || (target !== document && !target.contains(existingGroup))
                || (target === chatDiv && !chatDiv.contains(existingGroup));
            if (needsNewGroup) {
                groupCounter++;
                currentGroupKey = `grp_${groupCounter}`;
                const g = document.createElement('div');
                g.className = `message-group ${isSent ? 'sent-group' : 'received-group'}`;
                messageGroups[currentGroupKey] = g;
                target.appendChild(g);
            }
            return messageGroups[currentGroupKey];
        }

        function addMessage(sender, msg, status, messageId = null, reactions = [], timestamp = null, frag = null) {
            const isSent = sender === String(myPhone);
            const target = frag || chatDiv;
            const group  = ensureGroup(sender, target);

            const bubble = document.createElement('div');
            bubble.className = `bubble ${isSent ? 'sent' : 'received'} message-appear`;
            bubble.dataset.messageId = (messageId && messageId !== 'null' && !String(messageId).startsWith('temp_'))
                ? messageId : ('temp_' + Date.now());

            const messageContent = document.createElement('div');
            messageContent.textContent = msg;
            bubble.appendChild(messageContent);

            if (reactions && reactions.length > 0) bubble.appendChild(createReactionsElement(reactions, messageId));
            if (isSent) bubble.appendChild(createStatusElement(status));

            const timeDiv = document.createElement('div');
            timeDiv.className = 'message-time';
            timeDiv.textContent = timestamp
                ? new Date(timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})
                : new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
            bubble.appendChild(timeDiv);

            group.appendChild(bubble);
            lastSender = sender;

            if (!frag) {
                scrollToBottom(true);
                if (!isSent) setTimeout(markAllMessagesAsSeen, 500);
            }
        }

        // Track pending temp messages waiting for real DB ID
        const pendingTempMessages = {};

        function showToast(message, duration = 3000) {
            const existing = document.getElementById('toastNotif');
            if (existing) existing.remove();
            const toast = document.createElement('div');
            toast.id = 'toastNotif';
            toast.textContent = message;
            toast.style.cssText = `
                position: fixed; bottom: 90px; left: 50%; transform: translateX(-50%);
                background: rgba(14,73,80,0.88); color: white; padding: 10px 20px;
                border-radius: 22px; font-size: 13px; font-weight: 600; z-index: 9999;
                backdrop-filter: blur(8px); animation: fadeInOut ${duration}ms ease-in-out;
                pointer-events: none; white-space: nowrap;
            `;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), duration);
        }

        function sendMessage() {
            const msg = messageInput.value.trim();
            if(!msg) return;

            // Add temporary ID first
            const tempId = 'temp_' + Date.now();
            addMessage(String(myPhone), msg, 'sent', tempId, []);
            pendingTempMessages[tempId] = msg;

            messageInput.value = '';
            resetTextareaHeight();

            if(!isConnected) {
                showToast('Reconnecting… message will send shortly');
                // Retry once connected
                const retry = setInterval(() => {
                    if (isConnected) {
                        clearInterval(retry);
                        socket.emit('send_message', {
                            sender: String(myPhone),
                            receiver: String(contactPhone),
                            message: msg,
                            temp_id: tempId,
                            timestamp: new Date().toISOString()
                        });
                    }
                }, 500);
                setTimeout(() => clearInterval(retry), 15000);
                return;
            }

            try {
                socket.emit('send_message', {
                    sender: String(myPhone),
                    receiver: String(contactPhone),
                    message: msg,
                    temp_id: tempId,
                    timestamp: new Date().toISOString()
                });
            } catch(error) {
                console.error('Error sending message:', error);
                showToast('Failed to send message. Please try again.');
            }
        }

        messageInput.addEventListener('keydown', function(e) {
            if(e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });

        socket.on('receive_message', data => {
            console.log(' Received message via socket:', data);
            if(data.sender === String(myPhone) && data.temp_id && data.id) {
                // This is our own sent message confirmed — update temp bubble with real DB ID
                const tempBubble = document.querySelector(`[data-message-id="${data.temp_id}"]`);
                if (tempBubble) {
                    tempBubble.dataset.messageId = data.id;
                    console.log('Updated temp ID', data.temp_id, '→ real ID', data.id);
                }
                delete pendingTempMessages[data.temp_id];
                setTimeout(initializeContextMenuSystem, 100);
            } else if(data.sender === String(contactPhone)) {
                addMessage(data.sender, data.message, 'delivered', data.id, []);
                setTimeout(() => {
                    markAllMessagesAsSeen();
                    initializeContextMenuSystem();
                }, 100);
            }
        });

        socket.on('receive_file_message', data => {
            if(data.sender === String(contactPhone)) {
                addMediaMessage(data.sender, data.message_type, data.file_path, data.file_name, data.file_size, 'delivered', data.message_id, []);
                setTimeout(() => {
                    markAllMessagesAsSeen();
                    initializeContextMenuSystem();
                }, 100);
            }
        });

        // Handle reaction events from socket
        socket.on('reaction_updated', function(data) {
            const bubble = document.querySelector('[data-message-id="' + String(data.message_id) + '"]');
            if (!bubble) return;
            const container = bubble.querySelector('.message-reactions');
            if (container) container.remove();
            if (data.reactions && data.reactions.length > 0) {
                const el = createReactionsElement(data.reactions, data.message_id);
                const anchor = bubble.querySelector('.status') || bubble.querySelector('.message-time') || bubble.querySelector('.vm-meta') || null;
                if (anchor) bubble.insertBefore(el, anchor);
                else bubble.appendChild(el);
            }
        });

        socket.on('message_seen_confirmation', data => {
            if(data.receiver === String(myPhone)) {
                updateAllSentMessagesStatus('seen');
            }
        });

        function updateAllSentMessagesStatus(status) {
            const sentMessages = document.querySelectorAll('#chat .bubble.sent');
            sentMessages.forEach(bubble => {
                const statusDiv = bubble.querySelector('.status');
                if(statusDiv) {
                    if(status === 'seen') {
                        statusDiv.innerHTML = '<svg width="18" height="14" viewBox="0 0 28 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/><polyline points="26 6 15 17"/></svg>';
                    } else if(status === 'delivered') {
                        statusDiv.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
                    }
                }
            });
        }

        function openSaveModal() {
            document.getElementById("saveModal").style.display = "flex";
        }

        function closeSaveModal() {
            document.getElementById("saveModal").style.display = "none";
        }

        // Contact save form handling
        document.getElementById('saveContactForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const formData = new FormData(this);
            const saveBtn = this.querySelector('.modal-btn.primary');
            const originalText = saveBtn.textContent;

            saveBtn.textContent = 'Saving...';
            saveBtn.disabled = true;

            fetch('/add_contact', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    closeSaveModal();
                    alert('Contact saved successfully!');
                    const newName = formData.get('contact_name');
                    updateContactNameInHeader(newName);
                } else {
                    throw new Error(data.error || 'Save failed');
                }
            })
            .catch(error => {
                console.error('Error saving contact:', error);
                alert('Error saving contact: ' + error.message);
            })
            .finally(() => {
                saveBtn.textContent = originalText;
                saveBtn.disabled = false;
            });
        });

        function updateContactNameInHeader(newName) {
            const contactNameElement = document.querySelector('.contact-name');
            const contactAvatar = document.querySelector('.contact-avatar');

            if (contactNameElement) {
                contactNameElement.textContent = newName;
            }

            if (contactAvatar) {
                contactAvatar.textContent = newName[0].toUpperCase();
            }

            const saveBtn = document.getElementById('saveBtn');
            if (saveBtn) {
                saveBtn.style.display = 'none';
            }
        }

        function markAllMessagesAsSeen() {
            const receivedMessages = document.querySelectorAll('#chat .bubble.received');
            if (receivedMessages.length > 0) {
                const now = Date.now();
                if (now - lastMarkedSeenTime > 1000) {
                    socket.emit('mark_seen', {
                        sender: contactPhone,
                        receiver: myPhone
                    });
                    lastMarkedSeenTime = now;
                }
            }
        }

        document.addEventListener('visibilitychange', function() {
            if (!document.hidden) {
                markAllMessagesAsSeen();
                // Re-announce presence when tab becomes visible again
                if (socket.connected) {
                    socket.emit('set_presence', { phone: String(myPhone), contact: String(contactPhone), status: 'online' });
                }
            } else {
                // Tab hidden — tell server we're away
                if (socket.connected) {
                    socket.emit('set_presence', { phone: String(myPhone), contact: String(contactPhone), status: 'away' });
                }
            }
        });

        chatDiv.addEventListener('scroll', function() {
            markAllMessagesAsSeen();
        });

        chatDiv.addEventListener('click', markAllMessagesAsSeen);

        // ==================== INITIALIZATION ====================
        // Disable browser scroll restoration so position is consistent across all browsers
        if ('scrollRestoration' in history) history.scrollRestoration = 'manual';

        window.addEventListener('load', function() {
            loadMessages();  // loadMessages calls setupInfiniteScroll internally
        });

        // On bfcache restore (back/forward navigation in all browsers), reload fresh
        window.addEventListener('pageshow', function(e) {
            if (e.persisted) {
                loadMessages();
            }
        });

        document.addEventListener('visibilitychange', function() {
            if (!document.hidden) {
                setTimeout(initializeContextMenuSystem, 100);
            }
        });

        setTimeout(autoResizeTextarea, 100);

        // ── Keyboard / viewport handling ──────────────────────────────────
        // On mobile, when the soft keyboard opens the visual viewport shrinks.
        // We use visualViewport API (supported in all modern browsers) to keep
        // the message-box anchored above the keyboard at all times.
        if (window.visualViewport) {
            function onViewportChange() {
                const vv = window.visualViewport;
                // Distance between the layout viewport bottom and visual viewport bottom
                const keyboardHeight = window.innerHeight - vv.height - vv.offsetTop;
                const offset = Math.max(0, keyboardHeight);
                document.body.style.setProperty('--keyboard-offset', offset + 'px');
            }
            window.visualViewport.addEventListener('resize', onViewportChange);
            window.visualViewport.addEventListener('scroll', onViewportChange);
        }

        // Scroll chat to bottom when input is focused (keyboard opens)
        messageInput.addEventListener('focus', function() {
            setTimeout(() => {
                scrollToBottom(false);
            }, 350);
        });

        // ── VOICE MESSAGING ──────────────────────────────────────────
        const VM = (() => {
            let mediaRecorder=null,audioChunks=[],audioCtx=null,analyser=null,
                liveSource=null,animFrame=null,startTime=0,timerInterval=null,
                isRec=false,ampHistory=[];
            const overlay  = () => document.getElementById('vm-overlay');
            const timerEl  = () => document.getElementById('vm-rec-timer');
            const cvs      = () => document.getElementById('vm-live-canvas');
            const micBtn   = () => document.getElementById('vm-mic-btn');

            function toggle(){ isRec ? stopAndSend() : start(); }

            async function start(){
                if(isRec) return;
                if(!window.MediaRecorder||!navigator.mediaDevices){
                    alert('Voice messages are not supported in this browser. Please use Chrome, Firefox, or Safari 14.1+.');
                    return;
                }
                try{
                    const stream = await navigator.mediaDevices.getUserMedia({audio:true});
                    audioCtx = new (window.AudioContext||window.webkitAudioContext)();
                    analyser = audioCtx.createAnalyser(); analyser.fftSize=256;
                    liveSource = audioCtx.createMediaStreamSource(stream);
                    liveSource.connect(analyser);
                    const mime = ['audio/mp4','audio/webm;codecs=opus','audio/webm','audio/ogg;codecs=opus']
                        .find(m=>MediaRecorder.isTypeSupported(m))||'';
                    mediaRecorder = new MediaRecorder(stream, mime?{mimeType:mime}:{});
                    audioChunks=[]; ampHistory=[];
                    mediaRecorder.ondataavailable=e=>{ if(e.data&&e.data.size>0) audioChunks.push(e.data); };
                    mediaRecorder.start(100);
                    isRec=true; startTime=Date.now();
                    overlay().classList.add('active');
                    micBtn()?.classList.add('vm-recording');
                    timerInterval=setInterval(()=>{
                        const s=Math.floor((Date.now()-startTime)/1000);
                        timerEl().textContent=Math.floor(s/60)+':'+String(s%60).padStart(2,'0');
                        if(s>=300) stopAndSend();
                    },500);
                    drawLive();
                }catch(e){ alert('Microphone access required for voice messages.'); }
            }

            function cancel(){
                if(!isRec) return;
                cleanup();
                overlay().classList.remove('active');
                micBtn()?.classList.remove('vm-recording');
            }

            function stopAndSend(){
                if(!isRec) return;
                const dur=Date.now()-startTime;
                mediaRecorder.onstop=async()=>{
                    const mt=mediaRecorder.mimeType||'audio/mp4';
                    const ext=mt.includes('ogg')?'ogg':mt.includes('mp4')||mt.includes('aac')?'m4a':'webm';
                    const blob=new Blob(audioChunks,{type:mt||'audio/mp4'});
                    await upload(blob,ext,dur,deriveWave());
                };
                // Flush final chunk before stopping so blob is complete immediately
                if(mediaRecorder.state==='recording') mediaRecorder.requestData();
                mediaRecorder.stop();
                cleanup();
                overlay().classList.remove('active');
                micBtn()?.classList.remove('vm-recording');
            }

            async function upload(blob,ext,durMs,waveform){
                const tempId='vmtmp_'+Date.now();
                const tempMsg={id:tempId,sender:String(myPhone),receiver:String(contactPhone),
                    file_name:null,duration_ms:durMs,waveform,timestamp:new Date().toISOString(),
                    status:'uploading',message_type:'voice'};
                const el=renderBubble(tempMsg);
                appendVoiceBubble(el);
                const fd=new FormData();
                fd.append('audio',blob,'voice.'+ext);
                fd.append('sender',String(myPhone));
                fd.append('receiver',String(contactPhone));
                fd.append('duration_ms',durMs);
                fd.append('waveform',JSON.stringify(waveform));
                try{
                    const res=await fetch('/api/voice/upload',{method:'POST',body:fd});
                    const data=await res.json();
                    // Don't wireAudio here — onVoiceMessage handles it via socket event
                    // Just remove temp bubble if upload failed
                    if(!data.success){ el.remove(); }
                }catch(e){ el.remove(); }
            }

            function renderBubble(msg){
                const isOut=String(msg.sender)===String(myPhone);
                const wave=msg.waveform&&msg.waveform.length?msg.waveform:Array(40).fill(0.5);
                const wrap=document.createElement('div');
                wrap.className='vm-bubble '+(isOut?'vm-out':'vm-in')+(msg.status==='uploading'?' vm-uploading':'');
                wrap.dataset.vmId=String(msg.id||'');
                wrap.dataset.file=msg.file_name||'';
                // Prefix voice IDs with 'v_' to avoid collision with text message IDs in reactions table
                if(msg.id && !String(msg.id).startsWith('vmtmp_')) wrap.dataset.messageId='v_'+String(msg.id);

                const play=document.createElement('button');
                play.className='vm-play'; play.innerHTML=playIcon();
                wrap.appendChild(play);

                const ww=document.createElement('div'); ww.className='vm-ww';
                const waveEl=document.createElement('div'); waveEl.className='vm-wave';
                wave.forEach((a,i)=>{
                    const b=document.createElement('div'); b.className='vm-bar';
                    b.style.height=Math.max(4,Math.round(a*28))+'px';
                    b.dataset.i=i; waveEl.appendChild(b);
                });
                ww.appendChild(waveEl);

                const meta=document.createElement('div'); meta.className='vm-meta';
                const dur=document.createElement('span'); dur.className='vm-dur';
                dur.textContent=fmtMs(msg.duration_ms||0); meta.appendChild(dur);
                if(isOut){
                    const tks=document.createElement('span');
                    tks.className='vm-ticks'+(msg.status==='listened'?' vm-heard':'');
                    tks.innerHTML='<span class="vm-tick vm-on"></span><span class="vm-tick'+(msg.status!=='sent'?' vm-on':'')+'"></span>';
                    meta.appendChild(tks);
                }
                ww.appendChild(meta); wrap.appendChild(ww);
                // Render existing reactions from history
                if(msg.reactions && msg.reactions.length > 0){
                    const msgId = msg.id ? 'v_'+String(msg.id) : null;
                    if(msgId) wrap.appendChild(createReactionsElement(msg.reactions, msgId));
                }
                if(msg.file_name&&msg.status!=='uploading') wireAudio(wrap,msg.file_name,msg.duration_ms||0,wave,isOut,msg);
                return wrap;
            }

            function wireAudio(wrap,fileName,durMs,wave,isOut,msg){
                const audio=new Audio('/api/voice/file/'+fileName);
                audio.preload='metadata';
                let playing=false;
                const bars=wrap.querySelectorAll('.vm-bar');
                const durEl=wrap.querySelector('.vm-dur');
                const play=wrap.querySelector('.vm-play');
                const waveEl=wrap.querySelector('.vm-wave');

                waveEl.addEventListener('click',e=>{
                    const r=waveEl.getBoundingClientRect();
                    const ratio=(e.clientX-r.left)/r.width;
                    if(audio.duration){ audio.currentTime=ratio*audio.duration; updateProg(); }
                });
                audio.addEventListener('timeupdate',updateProg);
                audio.addEventListener('ended',()=>{
                    playing=false; play.innerHTML=playIcon();
                    bars.forEach(b=>b.classList.remove('vm-p'));
                    durEl.textContent=fmtMs(durMs);
                    if(!isOut&&msg&&msg.id&&msg.status!=='listened') markListened(msg.id,wrap);
                });
                play.addEventListener('click',()=>{
                    if(playing){ audio.pause(); playing=false; play.innerHTML=playIcon(); }
                    else{
                        document.querySelectorAll('.vm-audio-active,.gvm-audio-active').forEach(a=>{
                            a.pause(); a.dispatchEvent(new Event('ended')); a.classList.remove('vm-audio-active','gvm-audio-active');
                        });
                        audio.play().then(()=>{
                            audio.classList.add('vm-audio-active');
                            playing=true; play.innerHTML=pauseIcon();
                            if(!isOut&&msg&&msg.id) markListened(msg.id,wrap);
                        }).catch(err=>{
                            // NotAllowedError = browser blocked autoplay; show visual feedback
                            play.style.opacity='0.5';
                            setTimeout(()=>play.style.opacity='',600);
                        });
                    }
                });
                function updateProg(){
                    if(!audio.duration) return;
                    const pct=audio.currentTime/audio.duration;
                    const filled=Math.floor(pct*bars.length);
                    bars.forEach((b,i)=>i<filled?b.classList.add('vm-p'):b.classList.remove('vm-p'));
                    durEl.textContent=fmtMs(Math.max(0,(audio.duration-audio.currentTime)*1000));
                }
            }

            function markListened(id,wrap){
                fetch('/api/voice/listened',{method:'POST',headers:{'Content-Type':'application/json'},
                    body:JSON.stringify({id,user_phone:String(myPhone)})}).catch(()=>{});
            }

            function onVoiceListened(data){
                const el=document.querySelector(`.vm-bubble[data-vm-id="${data.id}"]`);
                if(el){ const t=el.querySelector('.vm-ticks'); if(t) t.classList.add('vm-heard'); }
            }

            function onVoiceMessage(msg){
                if(String(msg.sender)===String(myPhone)){
                    const tmpEl=document.querySelector('.vm-bubble.vm-uploading');
                    if(tmpEl && !tmpEl.dataset.wired){
                        tmpEl.dataset.wired='1';
                        tmpEl.dataset.vmId=String(msg.id);
                        tmpEl.dataset.file=msg.file_name;
                        // Set v_-prefixed messageId so reactions can target this bubble
                        tmpEl.dataset.messageId='v_'+String(msg.id);
                        tmpEl.classList.remove('vm-uploading');
                        wireAudio(tmpEl,msg.file_name,msg.duration_ms||0,msg.waveform||[],true,msg);
                    }
                    return;
                }
                if(msg.id && document.querySelector(`.vm-bubble[data-vm-id="${msg.id}"]`)) return;
                appendVoiceBubble(renderBubble(msg));
            }

            function appendVoiceBubble(el){
                // Voice bubbles are standalone — don't mix with text ensureGroup state
                const wrapper = document.createElement('div');
                wrapper.className = 'message-group ' + (el.classList.contains('vm-out') ? 'sent-group' : 'received-group');
                wrapper.appendChild(el);
                chatDiv.appendChild(wrapper);
                // Reset text grouping so next text message starts a fresh group
                lastSender = null;
                currentGroupKey = null;
                scrollToBottom(true);
            }

            function drawLive(){
                const c=cvs(); if(!c) return;
                const ctx=c.getContext('2d'); const W=c.width,H=c.height;
                const buf=new Uint8Array(analyser.frequencyBinCount);
                (function frame(){
                    if(!isRec) return;
                    animFrame=requestAnimationFrame(frame);
                    analyser.getByteFrequencyData(buf);
                    const amp=buf.reduce((s,v)=>s+v,0)/(buf.length*255);
                    ampHistory.push(amp); if(ampHistory.length>200) ampHistory.shift();
                    ctx.clearRect(0,0,W,H);
                    const bars=56,barW=W/bars-2;
                    for(let i=0;i<bars;i++){
                        const idx=Math.min(Math.floor(i*ampHistory.length/bars),ampHistory.length-1);
                        const a=ampHistory[idx]||0,bH=Math.max(4,a*(H-8));
                        ctx.fillStyle=`rgba(255,255,255,${0.35+a*0.65})`;
                        ctx.beginPath(); ctx.roundRect(i*(barW+2),(H-bH)/2,barW,bH,2); ctx.fill();
                    }
                })();
            }

            function deriveWave(bars=40){
                if(!ampHistory.length) return Array(bars).fill(0.5);
                const out=[]; const step=ampHistory.length/bars;
                for(let i=0;i<bars;i++){
                    const s=Math.floor(i*step),e=Math.min(Math.floor((i+1)*step),ampHistory.length);
                    let sum=0; for(let j=s;j<e;j++) sum+=ampHistory[j];
                    out.push(Math.round(Math.min(1,(e>s?sum/(e-s):0)*2.5)*1000)/1000);
                }
                return out;
            }

            function cleanup(){
                isRec=false; clearInterval(timerInterval); cancelAnimationFrame(animFrame);
                if(mediaRecorder&&mediaRecorder.state!=='inactive') mediaRecorder.stop();
                mediaRecorder?.stream?.getTracks().forEach(t=>t.stop());
                if(audioCtx){ audioCtx.close(); audioCtx=null; }
                analyser=null; liveSource=null; timerEl().textContent='0:00';
            }

            function fmtMs(ms){ const s=Math.ceil(ms/1000); return Math.floor(s/60)+':'+String(s%60).padStart(2,'0'); }
            function playIcon(){ return '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>'; }
            function pauseIcon(){ return '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>'; }

            return { toggle, cancel, stopAndSend, renderBubble, appendVoiceBubble, onVoiceMessage, onVoiceListened };
        })();

        // Wire socket voice events
        socket.on('voice_message', data => VM.onVoiceMessage(data));
        socket.on('voice_listened', data => VM.onVoiceListened(data));
        // ─────────────────────────────────────────────────────────────
    </script>
</body>
</html>"""

@app.route("/chat/<contact_phone>")
def chat_page(contact_phone):
    phone = request.args.get("phone")
    if not phone:
        return redirect(url_for('signin'))
    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("SELECT contact_name FROM contacts WHERE user_phone=? AND contact_phone=?", (phone, contact_phone))
            row = c.fetchone()
            c.execute("""
                SELECT id, sender, receiver, message, encrypted_message, status, timestamp,
                       message_type, file_path, file_name, file_size, thumbnail_path
                FROM messages
                WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
                ORDER BY timestamp ASC
                LIMIT 100
            """, (phone, contact_phone, contact_phone, phone))
            messages_data = c.fetchall()

            # Process messages
            messages = []
            for m in messages_data:
                message_id, sender, receiver, plaintext, encrypted, status, timestamp, message_type, file_path, file_name, file_size, thumbnail_path = m

                if message_type == 'text':
                    if encrypted:
                        decrypted = encryptor.decrypt_message(encrypted, sender, receiver)
                        msg_text = decrypted if decrypted is not None else plaintext
                    else:
                        msg_text = plaintext
                    messages.append({
                        "id": message_id, "sender": sender, "receiver": receiver,
                        "message": msg_text, "status": status, "timestamp": timestamp,
                        "message_type": "text"
                    })
                else:
                    messages.append({
                        "id": message_id,
                        "sender": sender,
                        "receiver": receiver,
                        "message": f"Sent a {message_type}",
                        "status": status,
                        "timestamp": timestamp,
                        "message_type": message_type,
                        "file_path": file_path,
                        "file_name": file_name,
                        "file_size": file_size,
                        "thumbnail_path": thumbnail_path
                    })

            c.execute("UPDATE messages SET status='seen' WHERE receiver=? AND sender=? AND status!='seen'", (phone, contact_phone))
            conn.commit()
        finally:
            return_db_connection(conn)
        contact_name = row[0] if row and row[0] else contact_phone
        return render_template_string(chat_html, phone=phone, contact_phone=contact_phone, contact_name=contact_name, messages=messages)
    except Exception as e:
        print(f" Error in chat_page: {e}")
        return "An error occurred", 500

# ----------------- Enhanced Socket.IO Events -----------------
def get_room(user, contact):
    """Create consistent room name for two users"""
    try:
        user = str(user).strip()
        contact = str(contact).strip()
        
        users = [user, contact]
        users.sort(key=str.lower)
        
        room = f"room_{users[0]}_{users[1]}"
        
        print(f"Room created: {room} for users {user} and {contact}")
        return room
    except Exception as e:
        print(f"Error in get_room: {e}, user={user}, contact={contact}")
        return f"room_{user}_{contact}"

connected_users = {}      # sid -> {phone, room, contact}
online_users   = {}      # phone -> set of sids  (multiple tabs)

def _user_online(phone):
    return bool(online_users.get(phone))

def _broadcast_presence(phone, contact, status, last_online=None):
    """Emit a presence update to the room shared by phone and contact."""
    room = get_room(phone, contact)
    socketio.emit('presence_update', {
        'phone':       phone,
        'status':      status,          # 'online' | 'offline'
        'last_online': last_online,
    }, room=room)

@socketio.on('join')
def on_join(data):
    try:
        user    = str(data['user'])
        contact = str(data['contact'])
        room    = get_room(user, contact)

        join_room(room)
        connected_users[request.sid] = {'phone': user, 'room': room, 'contact': contact}

        # Track online sids for this user
        if user not in online_users:
            online_users[user] = set()
        online_users[user].add(request.sid)

        # Update last_online in DB
        now_iso = datetime.now().isoformat()
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("UPDATE users SET last_online=? WHERE phone=?", (now_iso, user))
            conn.commit()
        finally:
            return_db_connection(conn)

        # Tell the contact this user is online
        _broadcast_presence(user, contact, 'online')

        # Tell this user whether their contact is currently online
        contact_online = _user_online(contact)
        if contact_online:
            emit('presence_update', {'phone': contact, 'status': 'online', 'last_online': None})
        else:
            # Fetch contact's last_online from DB
            conn2 = get_db_connection()
            try:
                c2 = conn2.cursor()
                c2.execute("SELECT last_online FROM users WHERE phone=?", (contact,))
                row = c2.fetchone()
                last_seen = row[0] if row else None
            finally:
                return_db_connection(conn2)
            emit('presence_update', {'phone': contact, 'status': 'offline', 'last_online': last_seen})

        if typing_status.get((user, contact)):
            emit('typing', {'actor': contact}, room=request.sid)

        emit('join_success', {'room': room, 'success': True}, room=request.sid)
    except Exception as e:
        print(f"Error in join: {e}")
        emit('error', {'message': 'Failed to join room'})

@socketio.on('disconnect')
def on_disconnect():
    try:
        sid  = request.sid
        info = connected_users.pop(sid, None)
        if info:
            phone   = info['phone']
            contact = info.get('contact')

            # Remove this sid from online set
            if phone in online_users:
                online_users[phone].discard(sid)
                if not online_users[phone]:          # last tab closed
                    del online_users[phone]
                    # Stamp last_online in DB
                    now_iso = datetime.now().isoformat()
                    conn = get_db_connection()
                    try:
                        c = conn.cursor()
                        c.execute("UPDATE users SET last_online=? WHERE phone=?", (now_iso, phone))
                        conn.commit()
                    finally:
                        return_db_connection(conn)
                    # Notify contact they went offline
                    if contact:
                        _broadcast_presence(phone, contact, 'offline', now_iso)

        # Clean up stale typing statuses
        for key in list(typing_status.keys()):
            if typing_status.get(key):
                del typing_status[key]
    except Exception as e:
        print(f"Error in disconnect: {e}")


@socketio.on('send_message')
def handle_message(data):
    try:
        sender = str(data.get('sender', ''))
        receiver = str(data.get('receiver', ''))
        message = data.get('message', '').strip()
        if not all([sender, receiver, message]):
            emit('error', {'message': 'Invalid message data'})
            return
        if len(message) > 5000:
            emit('error', {'message': 'Message too long'})
            return

        encrypted_message = encryptor.encrypt_message(message, sender, receiver)
        if not encrypted_message:
            emit('error', {'message': 'Failed to encrypt message'})
            return

        now_iso = datetime.now().isoformat()
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("INSERT INTO messages(sender,receiver,message,encrypted_message,status,timestamp) VALUES(?,?,?,?,?,?)",
                      (sender, receiver, message, encrypted_message, "sent", now_iso))
            message_id = c.lastrowid
            c.execute("INSERT OR IGNORE INTO users(phone,last_online) VALUES(?,?)", (receiver, now_iso))
            c.execute("INSERT OR IGNORE INTO contacts(user_phone,contact_phone,contact_name,last_message) VALUES(?,?,?,?)",
                      (sender, receiver, "", message))
            c.execute("UPDATE contacts SET last_message=?, timestamp=CURRENT_TIMESTAMP WHERE user_phone=? AND contact_phone=?",
                      (message, sender, receiver))
            c.execute("INSERT OR IGNORE INTO contacts(user_phone,contact_phone,contact_name,last_message) VALUES(?,?,?,?)",
                      (receiver, sender, "", message))
            c.execute("UPDATE contacts SET last_message=?, timestamp=CURRENT_TIMESTAMP WHERE user_phone=? AND contact_phone=?",
                      (message, receiver, sender))
            conn.commit()
        finally:
            return_db_connection(conn)
        temp_id = data.get('temp_id', None)
        room = get_room(sender, receiver)
        emit('receive_message', {'id': message_id, 'sender': sender, 'message': message, 'temp_id': temp_id}, room=room)
        
        cache.clear_for_users(sender, receiver)
        
    except Exception as e:
        print(f" Error in send_message: {e}")
        emit('error', {'message': 'Failed to send message'})

@socketio.on('send_file_message')
def handle_file_message(data):
    try:
        sender = str(data.get('sender', ''))
        receiver = str(data.get('receiver', ''))
        message_type = data.get('message_type', '')
        file_path = data.get('file_path', '')
        file_name = data.get('file_name', '')
        file_size = data.get('file_size', 0)
        message_id = data.get('message_id', '')

        if not all([sender, receiver, message_type, file_path]):
            emit('error', {'message': 'Invalid file message data'})
            return

        room = get_room(sender, receiver)
        emit('receive_file_message', {
            'id': message_id,
            'sender': sender,
            'message_type': message_type,
            'file_path': file_path,
            'file_name': file_name,
            'file_size': file_size
        }, room=room, broadcast=True)

        cache.clear_for_users(sender, receiver)

    except Exception as e:
        print(f"Error in send_file_message: {e}")
        emit('error', {'message': 'Failed to send file message'})

@socketio.on('add_reaction')
def handle_add_reaction(data):
    try:
        message_id = data.get('message_id')
        emoji = data.get('emoji')
        user_phone = data.get('user_phone')

        if not all([message_id, emoji, user_phone]):
            emit('error', {'message': 'Invalid reaction data'})
            return

        conn = get_db_connection()
        try:
            c = conn.cursor()

            sender, receiver, group_id = None, None, None

            # Detect if this is a voice message ID (prefixed with 'v_')
            raw_id = str(message_id)
            if raw_id.startswith('v_'):
                voice_id = raw_id[2:]
                c.execute("SELECT sender, receiver, group_id FROM voice_messages WHERE id=?", (voice_id,))
                vmsg = c.fetchone()
                if not vmsg:
                    emit('error', {'message': 'Voice message not found'})
                    return_db_connection(conn)
                    return
                sender, receiver, group_id = vmsg
                db_reaction_id = raw_id  # store as 'v_X'
            else:
                # Text/media message
                c.execute("SELECT sender, receiver FROM messages WHERE id=?", (message_id,))
                msg = c.fetchone()
                if not msg:
                    # Fallback: try voice_messages without prefix (legacy)
                    c.execute("SELECT sender, receiver, group_id FROM voice_messages WHERE id=?", (message_id,))
                    vmsg = c.fetchone()
                    if vmsg:
                        sender, receiver, group_id = vmsg
                        db_reaction_id = f'v_{message_id}'
                    else:
                        emit('error', {'message': 'Message not found'})
                        return_db_connection(conn)
                        return
                else:
                    sender, receiver = msg
                    db_reaction_id = message_id

            c.execute("SELECT emoji FROM message_reactions WHERE message_id=? AND user_phone=?",
                     (db_reaction_id, user_phone))
            existing = c.fetchone()

            if existing:
                if existing[0] == emoji:
                    c.execute("DELETE FROM message_reactions WHERE message_id=? AND user_phone=?",
                             (db_reaction_id, user_phone))
                    action = 'removed'
                else:
                    c.execute("UPDATE message_reactions SET emoji=? WHERE message_id=? AND user_phone=?",
                             (emoji, db_reaction_id, user_phone))
                    action = 'updated'
            else:
                c.execute("INSERT INTO message_reactions (message_id, user_phone, emoji) VALUES (?,?,?)",
                         (db_reaction_id, user_phone, emoji))
                action = 'added'

            conn.commit()
            c.execute("SELECT user_phone, emoji FROM message_reactions WHERE message_id=?", (db_reaction_id,))
            reactions_list = [{'user_phone': r[0], 'emoji': r[1]} for r in c.fetchall()]

        finally:
            return_db_connection(conn)

        payload = {
            'message_id': message_id,  # return original client ID for DOM lookup
            'user_phone': user_phone,
            'emoji': emoji,
            'action': action,
            'reactions': reactions_list
        }

        if group_id:
            emit('reaction_updated', payload, room=f'group_{group_id}')
        else:
            room = get_room(sender, receiver)
            emit('reaction_updated', payload, room=room)

        if sender and receiver:
            cache.clear_for_users(sender, receiver)

    except Exception as e:
        print(f"Error in add_reaction: {e}")
        emit('error', {'message': 'Failed to add reaction'})

@socketio.on('join_group')
def on_join_group(data):
    try:
        group_id = str(data.get('group_id'))
        user = str(data.get('user'))
        room = f"group_{group_id}"
        join_room(room)
        emit('join_group_success', {'room': room, 'success': True}, room=request.sid)
    except Exception as e:
        print(f"Error in join_group: {e}")


@socketio.on('send_group_message')
def handle_group_message(data):
    try:
        group_id = data.get('group_id')
        sender = str(data.get('sender', ''))
        message = data.get('message', '').strip()
        temp_id = data.get('temp_id')
        message_type = data.get('message_type', 'text')
        file_path = data.get('file_path')
        file_name = data.get('file_name')
        file_size = data.get('file_size')

        if not group_id or not sender:
            emit('error', {'message': 'Invalid group message data'})
            return
        # For file messages the text body may be the filename; require either message or file_path
        if not message and not file_path:
            emit('error', {'message': 'Invalid group message data'})
            return

        # Verify membership
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_phone=?", (group_id, sender))
            if not c.fetchone():
                emit('error', {'message': 'Not a group member'})
                return

            now_iso = datetime.now().isoformat()
            c.execute("""
                INSERT INTO group_messages (group_id, sender, message, message_type, file_path, file_name, file_size, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (group_id, sender, message, message_type, file_path, file_name, file_size, now_iso))
            message_id = c.lastrowid

            # Resolve sender display name for recipients
            c.execute("SELECT name FROM groups WHERE id=?", (group_id,))
            group_row = c.fetchone()
            conn.commit()
        finally:
            return_db_connection(conn)

        room = f"group_{group_id}"
        emit('receive_group_message', {
            'id': message_id,
            'group_id': group_id,
            'sender': sender,
            'message': message,
            'message_type': message_type,
            'file_path': file_path,
            'file_name': file_name,
            'file_size': file_size,
            'temp_id': temp_id,
            'timestamp': now_iso
        }, room=room, broadcast=True)

        cache.clear_pattern(f"group_{group_id}")

    except Exception as e:
        print(f"Error in send_group_message: {e}")
        emit('error', {'message': 'Failed to send group message'})


@socketio.on('group_typing')
def handle_group_typing(data):
    try:
        group_id = str(data.get('group_id'))
        user = str(data.get('user'))
        room = f"group_{group_id}"
        emit('group_typing', {'group_id': group_id, 'user': user}, room=room, broadcast=True)
    except Exception as e:
        print(f"Error in group_typing: {e}")


@socketio.on('group_stop_typing')
def handle_group_stop_typing(data):
    try:
        group_id = str(data.get('group_id'))
        user = str(data.get('user'))
        room = f"group_{group_id}"
        emit('group_stop_typing', {'group_id': group_id, 'user': user}, room=room, broadcast=True)
    except Exception as e:
        print(f"Error in group_stop_typing: {e}")


@socketio.on('add_group_reaction')
def handle_add_group_reaction(data):
    try:
        message_id = data.get('message_id')
        emoji = data.get('emoji')
        user_phone = data.get('user_phone')
        group_id = data.get('group_id')

        if not all([message_id, emoji, user_phone, group_id]):
            emit('error', {'message': 'Invalid group reaction data'})
            return

        conn = get_db_connection()
        try:
            c = conn.cursor()

            raw_id = str(message_id)
            if raw_id.startswith('v_'):
                voice_id = raw_id[2:]
                c.execute("SELECT id FROM voice_messages WHERE id=? AND group_id=?", (voice_id, group_id))
                if not c.fetchone():
                    emit('error', {'message': 'Voice message not found in group'})
                    return_db_connection(conn)
                    return
                db_reaction_id = raw_id
            else:
                c.execute("SELECT id FROM group_messages WHERE id=? AND group_id=?", (message_id, group_id))
                if not c.fetchone():
                    emit('error', {'message': 'Message not found in group'})
                    return_db_connection(conn)
                    return
                db_reaction_id = message_id

            c.execute("SELECT emoji FROM message_reactions WHERE message_id=? AND user_phone=?",
                      (db_reaction_id, user_phone))
            existing = c.fetchone()

            if existing:
                if existing[0] == emoji:
                    c.execute("DELETE FROM message_reactions WHERE message_id=? AND user_phone=?",
                              (db_reaction_id, user_phone))
                    action = 'removed'
                else:
                    c.execute("UPDATE message_reactions SET emoji=? WHERE message_id=? AND user_phone=?",
                              (emoji, db_reaction_id, user_phone))
                    action = 'updated'
            else:
                c.execute("INSERT INTO message_reactions (message_id, user_phone, emoji) VALUES (?,?,?)",
                          (db_reaction_id, user_phone, emoji))
                action = 'added'
            conn.commit()

            c.execute("SELECT user_phone, emoji FROM message_reactions WHERE message_id=?", (db_reaction_id,))
            reactions_list = [{'user_phone': r[0], 'emoji': r[1]} for r in c.fetchall()]
        finally:
            return_db_connection(conn)

        room = f"group_{group_id}"
        emit('group_reaction_updated', {
            'message_id': message_id,
            'group_id': group_id,
            'user_phone': user_phone,
            'emoji': emoji,
            'action': action,
            'reactions': reactions_list
        }, room=room)

    except Exception as e:
        print(f"Error in add_group_reaction: {e}")
        emit('error', {'message': 'Failed to add group reaction'})


@socketio.on('mark_seen')
def handle_mark_seen(data):
    try:
        sender = str(data.get('sender', ''))
        receiver = str(data.get('receiver', ''))

        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("UPDATE messages SET status='seen' WHERE sender=? AND receiver=? AND status!='seen'",
                     (sender, receiver))
            conn.commit()
        finally:
            return_db_connection(conn)

        room = get_room(sender, receiver)
        emit('message_seen_confirmation', {
            'receiver': sender,
            'status': 'seen'
        }, room=room)

        print(f"Messages seen by {receiver}, notifying {sender}")

    except Exception as e:
        print(f"Error in mark_seen: {e}")

@socketio.on('typing')
def handle_typing(data):
    try:
        actor = str(data.get('actor', ''))
        target = str(data.get('target', ''))
        if not all([actor, target]):
            return
        typing_status[(target, actor)] = True
        room = get_room(actor, target)
        emit('typing', {'actor': actor}, room=room, broadcast=True)
    except Exception as e:
        print(f" Error in typing: {e}")

@socketio.on('stop_typing')
def handle_stop_typing(data):
    try:
        actor = str(data.get('actor', ''))
        target = str(data.get('target', ''))
        if not all([actor, target]):
            return
        typing_status[(target, actor)] = False
        room = get_room(actor, target)
        emit('stop_typing', {'actor': actor}, room=room, broadcast=True)
    except Exception as e:
        print(f"Error in stop_typing: {e}")

@socketio.on('set_presence')
def handle_set_presence(data):
    try:
        phone   = str(data.get('phone', ''))
        contact = str(data.get('contact', ''))
        status  = data.get('status', 'online')
        if not phone or not contact:
            return
        now_iso = datetime.now().isoformat()
        if status == 'away':
            # Treat away as offline for the contact's view
            _broadcast_presence(phone, contact, 'offline', now_iso)
        else:
            _broadcast_presence(phone, contact, 'online')
    except Exception as e:
        print(f"Error in set_presence: {e}")

@socketio.on('heartbeat')
def handle_heartbeat(data):
    try:
        phone = str(data.get('phone', ''))
        if phone:
            now_iso = datetime.now().isoformat()
            conn = get_db_connection()
            try:
                c = conn.cursor()
                c.execute("UPDATE users SET last_online=? WHERE phone=?", (now_iso, phone))
                conn.commit()
            finally:
                return_db_connection(conn)
    except Exception as e:
        print(f"Error in heartbeat: {e}")

@socketio.on_error_default
def default_error_handler(e):
    print(f"SocketIO Error: {e}")
    emit('error', {'message': 'An error occurred'})


group_chat_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Group Chat</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover, interactive-widget=resizes-content">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap">
    <style>

        :root {
            --primary: #0E4950;
            --primary-light: #1a6b75;
            --accent: #2ec4b6;
            --bg: #eef6f6;
            --border: #d8e8e8;
            --text: #1a2e2f;
            --text-sec: #4a6567;
            --light: #8aa3a5;
        }

        * { margin:0; padding:0; box-sizing:border-box; -webkit-tap-highlight-color:transparent; }

        html { height:100%; height:-webkit-fill-available; }

        body {
            font-family:'DM Sans',-apple-system,BlinkMacSystemFont,sans-serif;
            display:flex; flex-direction:column;
            height:100vh; height:100dvh;
            min-height:-webkit-fill-available;
            background:#eef6f6; color:var(--text);
            overflow:hidden; position:fixed; width:100%; top:0; left:0;
        }

        /* ── Header ── */
        #grp-header {
            background:linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);
            color:#fff;
            padding:calc(14px + env(safe-area-inset-top,0px)) 16px 14px;
            display:flex; align-items:center; gap:12px;
            box-shadow:0 2px 16px rgba(14,73,80,0.25);
            z-index:10; position:relative; flex-shrink:0;
        }

        .grp-back {
            background:rgba(255,255,255,0.15); border:none; color:#fff;
            padding:7px 10px; border-radius:10px; cursor:pointer; font-size:18px;
            display:flex; align-items:center; justify-content:center;
            transition:background 0.2s;
        }
        .grp-back:hover { background:rgba(255,255,255,0.25); }

        .grp-avatar {
            width:42px; height:42px; border-radius:12px;
            background:linear-gradient(135deg,var(--accent),var(--primary-light));
            display:flex; align-items:center; justify-content:center;
            font-weight:700; font-size:17px; border:2px solid rgba(255,255,255,0.3);
            flex-shrink:0;
        }

        .grp-info { flex:1; min-width:0; }
        .grp-name { font-size:17px; font-weight:700; letter-spacing:-0.01em; }
        .grp-meta { font-size:12px; opacity:0.8; margin-top:1px; cursor:pointer; }

        .grp-info-btn {
            background:rgba(255,255,255,0.15); border:none; color:#fff;
            width:36px; height:36px; border-radius:50%; cursor:pointer;
            display:flex; align-items:center; justify-content:center;
            transition:background 0.2s; flex-shrink:0;
        }
        .grp-info-btn:hover { background:rgba(255,255,255,0.25); }

        /* ── Chat area ── */
        #grp-chat-container {
            flex:1; display:flex; flex-direction:column;
            overflow:hidden; min-height:0;
            background:#eef6f6;
            background-image:radial-gradient(circle,rgba(14,73,80,0.045) 1px,transparent 1px);
            background-size:22px 22px;
        }

        #grp-chat {
            flex:1; overflow-y:auto; padding:20px 16px 12px;
            display:flex; flex-direction:column; gap:4px;
            scroll-behavior:auto;
        }

        #grp-chat::-webkit-scrollbar { width:4px; }
        #grp-chat::-webkit-scrollbar-thumb { background:rgba(14,73,80,0.2); border-radius:4px; }

        #grp-typing {
            font-size:13px; color:var(--text-sec); margin:0 16px 8px;
            height:18px; font-style:italic; flex-shrink:0;
        }

        /* ── Message groups ── */
        .grp-msg-group {
            display:flex; flex-direction:column; margin-bottom:10px; max-width:82%;
        }
        .grp-sent-group { align-self:flex-end; align-items:flex-end; }
        .grp-recv-group { align-self:flex-start; align-items:flex-start; }

        .grp-sender-label {
            font-size:11px; font-weight:600; color:var(--accent);
            margin-bottom:2px; padding:0 4px;
        }

        .bubble {
            padding:11px 15px; border-radius:20px; margin:2px 0;
            font-size:15px; line-height:1.5; word-wrap:break-word;
            white-space:pre-wrap; word-break:break-word; max-width:100%;
            user-select:none; -webkit-user-select:none;
            transition:transform 0.1s, box-shadow 0.15s;
            will-change:transform;
            contain:content;
        }
        .bubble:active { transform:scale(0.985); }
        .sent { background:linear-gradient(135deg,#d4f5ef,#c8ede7); border-bottom-right-radius:5px; border:1px solid rgba(46,196,182,0.2); box-shadow:0 1px 4px rgba(14,73,80,0.08); }
        .received { background:#fff; border-bottom-left-radius:5px; border:1px solid #e8eeee; box-shadow:0 1px 4px rgba(0,0,0,0.05); }

        .msg-time { font-size:10px; color:var(--light); margin-top:2px; padding:0 2px; font-family:'DM Mono',monospace; }

        /* ── Input bar ── */
        #grp-message-box {
            display:flex; padding:10px 12px calc(14px + env(safe-area-inset-bottom,0px));
            background:#fff; border-top:1px solid var(--border);
            gap:8px; align-items:center; min-height:66px;
            box-shadow:0 -4px 20px rgba(14,73,80,0.06); flex-shrink:0;
        }

        #grp-message {
            flex:1; padding:11px 16px; font-size:15px;
            border:1.5px solid var(--border); border-radius:24px;
            outline:none; resize:none; max-height:120px;
            font-family:'DM Sans',inherit; background:#f8fafa;
            line-height:1.45; overflow-y:auto; min-height:44px;
            height:auto; white-space:pre-wrap; word-wrap:break-word;
            color:var(--text); transition:border-color 0.2s,box-shadow 0.2s;
        }
        #grp-message:focus { border-color:var(--accent); background:#fff; box-shadow:0 0 0 3px rgba(46,196,182,0.12); }
        #grp-message::placeholder { color:var(--light); }

        #grp-send-btn {
            width:48px; height:48px; border:none; border-radius:50%;
            background:linear-gradient(135deg,var(--primary),var(--primary-light));
            color:white; font-size:18px; cursor:pointer;
            display:flex; align-items:center; justify-content:center;
            transition:transform 0.15s,box-shadow 0.15s; flex-shrink:0;
            box-shadow:0 3px 14px rgba(14,73,80,0.35);
        }
        #grp-send-btn:hover { transform:scale(1.07); box-shadow:0 5px 18px rgba(14,73,80,0.45); }
        #grp-send-btn:active { transform:scale(0.93); }

        #grp-file-btn {
            width:40px; height:40px; border:none; border-radius:50%;
            background:#e8f6f5; color:var(--accent);
            display:flex; align-items:center; justify-content:center;
            cursor:pointer; flex-shrink:0; transition:background 0.18s,transform 0.15s;
        }
        #grp-file-btn:hover { background:#d0efed; transform:scale(1.07); }
        #grp-file-btn:active { transform:scale(0.93); }

        #grp-mic-btn {
            width:48px !important; height:48px !important; border-radius:50% !important;
            border:none !important;
            background:linear-gradient(135deg,var(--primary),var(--primary-light)) !important;
            color:#fff !important; display:flex !important; align-items:center !important;
            justify-content:center !important; cursor:pointer !important; flex-shrink:0 !important;
            transition:transform 0.15s,box-shadow 0.15s !important;
            box-shadow:0 3px 14px rgba(14,73,80,.35) !important;
        }
        #grp-mic-btn:hover  { transform:scale(1.07) !important; }
        #grp-mic-btn:active { transform:scale(0.93) !important; }
        #grp-mic-btn.grp-vm-rec { background:#e63946 !important; box-shadow:0 0 0 4px rgba(230,57,70,.25) !important; animation:gvmMicPulse 1s infinite !important; }

        /* ── Members panel ── */
        #members-panel {
            display:none; position:fixed; top:0; left:0; width:100%; height:100%;
            background:rgba(10,30,30,0.55); backdrop-filter:blur(6px);
            z-index:2000; align-items:flex-end; justify-content:center;
        }
        .members-sheet {
            background:#fff; border-radius:28px 28px 0 0;
            padding:22px 20px calc(28px + env(safe-area-inset-bottom,0px));
            width:100%; max-height:70vh; overflow-y:auto;
            animation:slideUpFromBottom 0.35s cubic-bezier(0.25,0.46,0.45,0.94);
        }
        .members-handle { width:36px; height:4px; background:#ccd8d8; border-radius:2px; margin:0 auto 18px; }

        @keyframes slideUpFromBottom {
            from { opacity:0; transform:translateY(100%); }
            to { opacity:1; transform:translateY(0); }
        }

        /* ── Media message ── */
        .media-message { max-width:280px; cursor:pointer; }
        .media-preview { border-radius:16px; overflow:hidden; margin-bottom:8px; box-shadow:0 4px 20px rgba(0,0,0,0.15); }
        .media-preview img { width:100%; height:auto; display:block; }

        .file-message { display:flex; align-items:center; gap:12px; padding:14px; background:#f8f9fa; border-radius:14px; border:1px solid #e9ecef; }
        .file-icon-box { width:44px; height:44px; border-radius:10px; display:flex; align-items:center; justify-content:center; background:#E3F2FD; color:#2196F3; flex-shrink:0; }
        .file-dl-btn { background:linear-gradient(135deg,var(--primary),var(--primary-light)); color:white; border:none; border-radius:8px; padding:8px 12px; font-size:12px; font-weight:600; cursor:pointer; white-space:nowrap; }

        /* Toast */
        .grp-toast { position:fixed; bottom:90px; left:50%; transform:translateX(-50%); background:rgba(14,73,80,0.88); color:white; padding:10px 20px; border-radius:22px; font-size:13px; font-weight:600; z-index:9999; pointer-events:none; white-space:nowrap; }

        /* ── Context menu ── */
        #grp-context-menu {
            position:fixed; z-index:9000; background:#fff;
            border-radius:18px; padding:8px 0;
            box-shadow:0 8px 32px rgba(14,73,80,0.18),0 2px 8px rgba(0,0,0,0.10);
            min-width:160px; display:none;
            border:1px solid rgba(14,73,80,0.08);
            animation:grpCtxFadeIn 0.15s ease;
        }
        @keyframes grpCtxFadeIn { from{opacity:0;transform:scale(0.92)} to{opacity:1;transform:scale(1)} }
        .grp-ctx-item {
            display:flex; align-items:center; gap:10px;
            padding:11px 18px; font-size:14px; font-weight:500;
            color:#1a2e2f; cursor:pointer; transition:background 0.15s;
        }
        .grp-ctx-item:hover { background:#f0faf9; }
        .grp-ctx-item svg { flex-shrink:0; }

        /* ── Emoji picker ── */
        #grp-emoji-bar {
            position:fixed; z-index:9001; background:#fff;
            border-radius:50px; padding:8px 14px;
            box-shadow:0 8px 28px rgba(14,73,80,0.18);
            display:none; gap:6px; align-items:center;
            border:1px solid rgba(14,73,80,0.08);
            animation:grpCtxFadeIn 0.15s ease;
        }
        .grp-emoji-btn {
            font-size:22px; cursor:pointer; padding:4px 6px;
            border-radius:50%; transition:all 0.15s; border:none; background:none;
            line-height:1;
        }
        .grp-emoji-btn:hover { background:#f0faf9; transform:scale(1.25); }

        /* ── Reactions display ── */
        .grp-msg-reactions {
            display:flex; flex-wrap:wrap; gap:4px;
            margin-top:4px;
        }
        .grp-reaction-pill {
            display:flex; align-items:center; gap:3px;
            background:rgba(46,196,182,0.12); border:1px solid rgba(46,196,182,0.25);
            border-radius:20px; padding:3px 8px;
            font-size:13px; cursor:pointer; transition:all 0.15s;
            user-select:none; -webkit-user-select:none;
        }
        .grp-reaction-pill:active { transform:scale(0.92); }
        .grp-reaction-mine {
            background:rgba(46,196,182,0.28);
            border-color:rgba(46,196,182,0.6);
        }
        .grp-reaction-pill .grp-r-count { font-size:11px; font-weight:700; color:var(--primary); }

        @media(max-width:480px) {
            .bubble { padding:10px 14px; font-size:14px; }
            .grp-msg-group { max-width:90%; }
        }

        /* ── Image viewer ── */
        #grp-img-viewer {
            display:none; position:fixed; inset:0; z-index:5000;
            background:rgba(0,0,0,0.92);
            align-items:center; justify-content:center;
        }
        #grp-img-viewer.open { display:flex; }
        #grp-img-viewer img {
            max-width:92vw; max-height:88vh;
            border-radius:10px; object-fit:contain;
            box-shadow:0 8px 40px rgba(0,0,0,0.5);
        }
        #grp-img-viewer-close {
            position:absolute; top:18px; right:18px;
            background:rgba(255,255,255,0.15); border:none; color:#fff;
            width:40px; height:40px; border-radius:50%; cursor:pointer;
            display:flex; align-items:center; justify-content:center;
            font-size:22px; transition:background 0.2s;
        }
        #grp-img-viewer-close:hover { background:rgba(255,255,255,0.28); }

        .media-preview { cursor:pointer; }
        .media-preview img { transition:opacity 0.15s; }
        .media-preview:active img { opacity:0.75; }

        /* ── Voice Message Styles (group) ── */
        #grp-vm-overlay{display:none;position:fixed;inset:0;z-index:9000;background:rgba(14,73,80,0.94);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);flex-direction:column;align-items:center;justify-content:center;gap:22px;}
        #grp-vm-overlay.active{display:flex;}
        #grp-vm-timer{font-size:54px;font-weight:700;color:#fff;letter-spacing:-2px;font-variant-numeric:tabular-nums;font-family:'DM Mono',monospace;}
        #grp-vm-label{font-size:11px;font-weight:600;color:rgba(255,255,255,.6);text-transform:uppercase;letter-spacing:3px;}
        #grp-vm-canvas{width:280px;height:60px;border-radius:12px;}
        .grp-vm-dot{width:10px;height:10px;border-radius:50%;background:#ff4d4d;animation:gvmPulse 1.1s ease-in-out infinite;}
        @keyframes gvmPulse{0%,100%{transform:scale(1);opacity:1;}50%{transform:scale(1.6);opacity:.4;}}
        .grp-vm-actions{display:flex;gap:28px;margin-top:6px;}
        .grp-vm-btn{width:62px;height:62px;border-radius:50%;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:transform .14s;}
        .grp-vm-btn:active{transform:scale(.9);}
        #grp-vm-cancel-btn{background:rgba(255,255,255,.14);color:#fff;}
        #grp-vm-send-btn{background:#fff;color:var(--primary);box-shadow:0 6px 22px rgba(0,0,0,.26);}
        #grp-mic-btn.grp-vm-rec{background:#e63946;animation:gvmMicPulse 1s infinite;}
        @keyframes gvmMicPulse{0%,100%{box-shadow:0 0 0 0 rgba(230,57,70,.55);}50%{box-shadow:0 0 0 10px rgba(230,57,70,0);}}
        .gvm-bubble{display:flex;align-items:center;gap:10px;padding:10px 13px;border-radius:20px;max-width:300px;min-width:210px;font-family:'DM Sans',sans-serif;user-select:none;position:relative;}
        .gvm-bubble.gvm-out{background:linear-gradient(135deg,#d4f5ef,#c8ede7);border-bottom-right-radius:5px;border:1px solid rgba(46,196,182,.2);box-shadow:0 1px 4px rgba(14,73,80,.08);margin-left:auto;}
        .gvm-bubble.gvm-in{background:#fff;border-bottom-left-radius:5px;border:1px solid #e8eeee;box-shadow:0 1px 4px rgba(0,0,0,.05);}
        .gvm-bubble.gvm-uploading::after{content:'';position:absolute;inset:0;border-radius:inherit;background:linear-gradient(90deg,transparent,rgba(255,255,255,.3),transparent);background-size:200% 100%;animation:gvmShimmer 1.3s infinite;}
        @keyframes gvmShimmer{0%{background-position:-200% 0;}100%{background-position:200% 0;}}
        .gvm-play{width:38px;height:38px;border-radius:50%;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:transform .14s;}
        .gvm-play:active{transform:scale(.9);}
        .gvm-bubble.gvm-out .gvm-play{background:rgba(14,73,80,.13);color:var(--primary);}
        .gvm-bubble.gvm-in .gvm-play{background:#e0f2f4;color:var(--primary);}
        .gvm-ww{flex:1;display:flex;flex-direction:column;gap:4px;min-width:0;}
        .gvm-wave{display:flex;align-items:center;gap:2px;height:30px;cursor:pointer;}
        .gvm-bar{flex:1;border-radius:2px;min-width:2px;transition:background .1s;}
        .gvm-bubble.gvm-out .gvm-bar{background:rgba(14,73,80,.22);}
        .gvm-bubble.gvm-out .gvm-bar.gvm-p{background:var(--primary);}
        .gvm-bubble.gvm-in .gvm-bar{background:rgba(14,73,80,.18);}
        .gvm-bubble.gvm-in .gvm-bar.gvm-p{background:var(--primary);}
        .gvm-meta{display:flex;justify-content:space-between;align-items:center;font-size:10px;opacity:.7;}
        .gvm-dur{font-variant-numeric:tabular-nums;font-weight:500;}
    </style>
</head>
<body>

<div id="grp-header">
    <button class="grp-back" onclick="goBack()">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <div class="grp-avatar" id="grpAvatar">{{ avatar_letter }}</div>
    <div class="grp-info">
        <div class="grp-name">{{ group_name }}</div>
        <div class="grp-meta" onclick="openMembersPanel()" id="grpMeta">Loading members…</div>
    </div>
    <button class="grp-info-btn" onclick="openMembersPanel()" title="Group info">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
    </button>
</div>

<div id="grp-chat-container">
    <div id="grp-chat">
        <div id="grpLoadingIndicator" style="text-align:center;padding:12px;color:var(--light);font-size:13px;font-style:italic;">Loading messages…</div>
    </div>
    <div id="grp-typing"></div>
</div>

<!-- Image viewer -->
<div id="grp-img-viewer" onclick="closeGrpImgViewer()">
    <button id="grp-img-viewer-close" onclick="closeGrpImgViewer()">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
    <img id="grp-img-viewer-img" src="" alt="">
</div>

<!-- Group Voice Recording Overlay -->
<div id="grp-vm-overlay">
    <div style="display:flex;align-items:center;gap:10px;">
        <div class="grp-vm-dot"></div>
        <span id="grp-vm-label">RECORDING</span>
    </div>
    <canvas id="grp-vm-canvas" width="560" height="120"></canvas>
    <div id="grp-vm-timer">0:00</div>
    <div class="grp-vm-actions">
        <button class="grp-vm-btn" id="grp-vm-cancel-btn" onclick="GVM.cancel()">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
        <button class="grp-vm-btn" id="grp-vm-send-btn" onclick="GVM.stopAndSend()">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
        </button>
    </div>
</div>

<div id="grp-message-box">
    <button id="grp-file-btn" onclick="openGrpFileModal()" title="Send file">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14,2 14,8 20,8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
    </button>
    <textarea id="grp-message" placeholder="Message group…" rows="1"></textarea>
    <button id="grp-mic-btn" onclick="GVM.toggle()" title="Voice message">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/>
            <path d="M19 10v2a7 7 0 0 1-14 0v-2"/>
            <line x1="12" y1="19" x2="12" y2="23"/>
            <line x1="8" y1="23" x2="16" y2="23"/>
        </svg>
    </button>
    <button id="grp-send-btn" onclick="sendGroupMessage()">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" fill="white"/></svg>
    </button>
</div>

<!-- File upload modal (reuses same pattern as 1:1 chat) -->
<div id="grpFileModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,30,30,0.55);backdrop-filter:blur(4px);z-index:2000;align-items:flex-end;justify-content:center;">
    <div style="background:#fff;border-radius:28px 28px 0 0;padding:28px 22px calc(32px + env(safe-area-inset-bottom,0px));width:100%;">
        <div style="width:36px;height:4px;background:#ccd8d8;border-radius:2px;margin:0 auto 18px;"></div>
        <h3 style="color:var(--primary);font-size:20px;font-weight:700;margin-bottom:6px;">Share File</h3>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:18px 0;">
            <div onclick="triggerGrpFile('image')" style="display:flex;flex-direction:column;align-items:center;gap:10px;padding:18px 10px;border:1.5px solid var(--border);border-radius:18px;cursor:pointer;background:#f7fafa;">
                <div style="width:52px;height:52px;border-radius:14px;background:linear-gradient(135deg,#d4edda,#a8d8b0);display:flex;align-items:center;justify-content:center;">
                    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#4CAF50" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
                </div>
                <span style="font-size:13px;font-weight:600;">Photos</span>
            </div>
            <div onclick="triggerGrpFile('video')" style="display:flex;flex-direction:column;align-items:center;gap:10px;padding:18px 10px;border:1.5px solid var(--border);border-radius:18px;cursor:pointer;background:#f7fafa;">
                <div style="width:52px;height:52px;border-radius:14px;background:linear-gradient(135deg,#fde8c8,#f9c784);display:flex;align-items:center;justify-content:center;">
                    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#FF9800" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>
                </div>
                <span style="font-size:13px;font-weight:600;">Videos</span>
            </div>
            <div onclick="triggerGrpFile('document')" style="display:flex;flex-direction:column;align-items:center;gap:10px;padding:18px 10px;border:1.5px solid var(--border);border-radius:18px;cursor:pointer;background:#f7fafa;">
                <div style="width:52px;height:52px;border-radius:14px;background:linear-gradient(135deg,#dbeafe,#93c5fd);display:flex;align-items:center;justify-content:center;">
                    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#2196F3" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                </div>
                <span style="font-size:13px;font-weight:600;">Docs</span>
            </div>
        </div>
        <input type="file" id="grpFileInput" style="display:none">
        <button onclick="closeGrpFileModal()" style="width:100%;padding:13px;border:none;border-radius:12px;background:#eef2f2;color:#4a6567;font-weight:600;cursor:pointer;font-size:14px;">Cancel</button>
    </div>
</div>

<!-- Members panel -->
<div id="members-panel">
    <div class="members-sheet">
        <div class="members-handle"></div>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
            <h3 style="font-size:17px;font-weight:700;color:var(--primary);margin:0;">Group Members</h3>
            <button id="addMemberBtn" onclick="openAddMemberModal()" style="display:none;align-items:center;gap:6px;background:linear-gradient(135deg,#0E4950,#1a6b75);color:white;border:none;padding:8px 14px;border-radius:20px;font-size:13px;font-weight:600;cursor:pointer;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                Add
            </button>
        </div>
        <div id="membersList" style="display:flex;flex-direction:column;gap:0;"></div>
    </div>
</div>

<!-- Add Member modal -->
<div id="addMemberModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,30,30,0.55);z-index:3000;align-items:flex-end;justify-content:center;">
    <div style="background:#fff;border-radius:28px 28px 0 0;padding:24px 20px calc(28px + env(safe-area-inset-bottom,0px));width:100%;max-height:75vh;display:flex;flex-direction:column;">
        <div style="width:36px;height:4px;background:#ccd8d8;border-radius:2px;margin:0 auto 18px;"></div>
        <h3 style="font-size:17px;font-weight:700;color:var(--primary);margin-bottom:4px;">Add Members</h3>
        <p style="font-size:13px;color:#8aa3a5;margin-bottom:16px;">Select contacts to add to this group.</p>
        <div id="addMemberPicker" style="flex:1;overflow-y:auto;display:flex;flex-direction:column;gap:8px;margin-bottom:16px;"></div>
        <div style="display:flex;gap:10px;flex-shrink:0;">
            <button onclick="closeAddMemberModal()" style="flex:1;padding:13px;border:none;border-radius:12px;background:#eef2f2;color:#4a6567;font-weight:600;font-size:14px;cursor:pointer;">Cancel</button>
            <button id="addMemberConfirmBtn" onclick="submitAddMembers()" style="flex:2;padding:13px;border:none;border-radius:12px;background:linear-gradient(135deg,#0E4950,#1a6b75);color:white;font-weight:700;font-size:14px;cursor:pointer;">Add</button>
        </div>
    </div>
</div>

<!-- Context menu -->
<div id="grp-context-menu">
    <div class="grp-ctx-item" id="grpCtxReact">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2ec4b6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>
        React
    </div>
    <div class="grp-ctx-item" id="grpCtxCopy">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#0E4950" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        Copy
    </div>
</div>

<!-- Emoji reaction bar -->
<div id="grp-emoji-bar">
    <button class="grp-emoji-btn" data-emoji="👍">👍</button>
    <button class="grp-emoji-btn" data-emoji="❤️">❤️</button>
    <button class="grp-emoji-btn" data-emoji="😂">😂</button>
    <button class="grp-emoji-btn" data-emoji="😮">😮</button>
    <button class="grp-emoji-btn" data-emoji="😢">😢</button>
    <button class="grp-emoji-btn" data-emoji="🔥">🔥</button>
</div>

<script src="https://cdn.socket.io/4.7.2/socket.io.min.js" crossorigin="anonymous"></script>
<script>
    const myPhone = {{ phone|tojson }};
    const groupId = {{ group_id }};
    const groupName = {{ group_name|tojson }};

    const grpChat = document.getElementById('grp-chat');
    const grpInput = document.getElementById('grp-message');
    const grpTyping = document.getElementById('grp-typing');
    const grpFileInput = document.getElementById('grpFileInput');
    let isConnected = false;
    let typingTimer;
    let groupMembers = [];

    // ── Helpers ──────────────────────────────────────────────────
    function goBack() { window.history.back(); }

    function showGrpToast(msg, dur=3000) {
        const t = document.createElement('div');
        t.className = 'grp-toast'; t.textContent = msg;
        document.body.appendChild(t);
        setTimeout(() => t.remove(), dur);
    }

    function formatTime(ts) {
        const d = ts ? new Date(ts) : new Date();
        return d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
    }

    function formatFileSize(b) {
        if (!b) return '';
        if (b < 1024) return b + ' B';
        if (b < 1024*1024) return (b/1024).toFixed(1) + ' KB';
        return (b/(1024*1024)).toFixed(1) + ' MB';
    }

    function resizeTextarea() {
        grpInput.style.height = 'auto';
        grpInput.style.height = Math.min(grpInput.scrollHeight, 120) + 'px';
    }
    grpInput.addEventListener('input', resizeTextarea);

    // ── Members panel ─────────────────────────────────────────────
    let isAdmin = false;

    function loadGroupInfo() {
        fetch('/api/group_info?group_id=' + groupId + '&user_phone=' + encodeURIComponent(myPhone))
        .then(r => r.json())
        .then(info => {
            groupMembers = info.members || [];
            document.getElementById('grpMeta').textContent = groupMembers.length + ' member' + (groupMembers.length !== 1 ? 's' : '');

            // Check if current user is admin
            const me = groupMembers.find(m => String(m.phone) === String(myPhone));
            isAdmin = me && me.role === 'admin';

            const list = document.getElementById('membersList');

            // Build all rows off-DOM then insert once
            const frag = document.createDocumentFragment();
            groupMembers.forEach(m => {
                const isMe = String(m.phone) === String(myPhone);
                const displayName = m.name || m.phone || 'Unknown';
                const initial = displayName[0].toUpperCase();
                const row = document.createElement('div');
                row.style.cssText = 'display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid #f0f4f4;';
                row.innerHTML = `
                  <div style="width:42px;height:42px;border-radius:50%;background:linear-gradient(135deg,#0E4950,#2ec4b6);display:flex;align-items:center;justify-content:center;color:white;font-weight:700;font-size:16px;flex-shrink:0;">${initial}</div>
                  <div style="flex:1;min-width:0;">
                    <div style="font-weight:600;color:#1a2e2f;font-size:14px;">${displayName}${isMe ? ' <span style="color:#8aa3a5;font-weight:400;">(You)</span>' : ''}</div>
                    <div style="color:#8aa3a5;font-size:11px;">${m.phone}</div>
                  </div>
                  ${m.role === 'admin' ? '<span style="font-size:10px;font-weight:700;color:#2ec4b6;background:#f0faf9;padding:3px 8px;border-radius:8px;flex-shrink:0;">Admin</span>' : ''}
                `;
                frag.appendChild(row);
            });

            list.innerHTML = '';
            list.appendChild(frag);

            // Show Add Member button for admins
            const addBtn = document.getElementById('addMemberBtn');
            if (addBtn) addBtn.style.display = isAdmin ? 'flex' : 'none';
        })
        .catch(() => {
            document.getElementById('grpMeta').textContent = 'Members';
        });
    }

    // ── Add Member ────────────────────────────────────────────────
    function openAddMemberModal() {
        // Load contacts and show picker
        fetch('/api/contacts?phone=' + encodeURIComponent(myPhone))
        .then(r => r.json())
        .then(contacts => {
            const existingPhones = new Set(groupMembers.map(m => String(m.phone)));
            const eligible = contacts.filter(c => !existingPhones.has(String(c.contact_phone)));

            const modal = document.getElementById('addMemberModal');
            const picker = document.getElementById('addMemberPicker');
            picker.innerHTML = '';

            if (eligible.length === 0) {
                picker.innerHTML = '<p style="color:#8aa3a5;font-size:13px;text-align:center;padding:20px 0;">All your contacts are already in this group.</p>';
            } else {
                eligible.forEach(c => {
                    const name = c.contact_name || c.contact_phone;
                    const initial = name[0].toUpperCase();
                    const row = document.createElement('div');
                    row.style.cssText = 'display:flex;align-items:center;gap:12px;padding:11px 12px;border-radius:12px;border:1.5px solid #d8e8e8;cursor:pointer;background:#f8fafa;transition:all 0.15s;';
                    row.dataset.phone = c.contact_phone;
                    row.dataset.selected = 'false';
                    row.innerHTML = `
                      <div style="width:38px;height:38px;border-radius:50%;background:linear-gradient(135deg,#0E4950,#2ec4b6);display:flex;align-items:center;justify-content:center;color:white;font-weight:700;font-size:15px;flex-shrink:0;">${initial}</div>
                      <div style="flex:1;min-width:0;">
                        <div style="font-weight:600;color:#1a2e2f;font-size:14px;">${name}</div>
                        <div style="color:#8aa3a5;font-size:11px;">${c.contact_phone}</div>
                      </div>
                      <div class="add-check" style="width:22px;height:22px;border-radius:50%;border:2px solid #d8e8e8;flex-shrink:0;display:flex;align-items:center;justify-content:center;transition:all 0.15s;"></div>
                    `;
                    row.addEventListener('click', () => {
                        const sel = row.dataset.selected === 'true';
                        row.dataset.selected = sel ? 'false' : 'true';
                        const check = row.querySelector('.add-check');
                        if (!sel) {
                            row.style.borderColor = '#2ec4b6';
                            row.style.background = '#f0faf9';
                            check.style.background = '#2ec4b6';
                            check.style.borderColor = '#2ec4b6';
                            check.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>';
                        } else {
                            row.style.borderColor = '#d8e8e8';
                            row.style.background = '#f8fafa';
                            check.style.background = 'transparent';
                            check.style.borderColor = '#d8e8e8';
                            check.innerHTML = '';
                        }
                    });
                    picker.appendChild(row);
                });
            }
            modal.style.display = 'flex';
        })
        .catch(() => showGrpToast('Could not load contacts'));
    }

    function closeAddMemberModal() {
        document.getElementById('addMemberModal').style.display = 'none';
    }

    function submitAddMembers() {
        const selected = [...document.querySelectorAll('#addMemberPicker [data-selected="true"]')]
            .map(r => r.dataset.phone);
        if (selected.length === 0) { showGrpToast('Select at least one person'); return; }

        const btn = document.getElementById('addMemberConfirmBtn');
        btn.disabled = true; btn.textContent = 'Adding…';

        fetch('/api/add_group_members', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({group_id: groupId, added_by: String(myPhone), members: selected})
        })
        .then(r => r.json())
        .then(data => {
            btn.disabled = false; btn.textContent = 'Add';
            if (data.success) {
                closeAddMemberModal();
                closeMembersPanel();
                loadGroupInfo();
                showGrpToast('Members added!');
            } else {
                showGrpToast(data.error || 'Failed to add members');
            }
        })
        .catch(() => { btn.disabled = false; btn.textContent = 'Add'; showGrpToast('Network error'); });
    }

    document.getElementById('addMemberModal').addEventListener('click', function(e) {
        if (e.target === this) closeAddMemberModal();
    });

    function openMembersPanel() {
        document.getElementById('members-panel').style.display = 'flex';
    }
    function closeMembersPanel() {
        document.getElementById('members-panel').style.display = 'none';
    }
    document.getElementById('members-panel').addEventListener('click', function(e) {
        if (e.target === this) closeMembersPanel();
    });

    // ── Render messages ───────────────────────────────────────────
    function getSenderName(senderPhone) {
        if (String(senderPhone) === String(myPhone)) return 'You';
        const m = groupMembers.find(x => x.phone === String(senderPhone));
        return m ? m.name : senderPhone;
    }

    function createBubble(msg) {
        const isSent = String(msg.sender) === String(myPhone);
        const group = document.createElement('div');
        group.className = 'grp-msg-group ' + (isSent ? 'grp-sent-group' : 'grp-recv-group');

        if (!isSent) {
            const label = document.createElement('div');
            label.className = 'grp-sender-label';
            label.textContent = getSenderName(msg.sender);
            group.appendChild(label);
        }

        const bubble = document.createElement('div');
        bubble.className = 'bubble ' + (isSent ? 'sent' : 'received');
        if (msg.id) bubble.dataset.messageId = msg.id;
        else bubble.dataset.tempId = msg.temp_id || ('temp_' + Date.now());

        if (msg.message_type === 'image' && msg.file_path) {
            const img = document.createElement('img');
            img.src = '/uploads/' + msg.file_path;
            img.alt = '';
            img.loading = 'lazy';
            bubble.className += ' media-message';
            const preview = document.createElement('div');
            preview.className = 'media-preview';
            preview.appendChild(img);
            preview.onclick = () => openGrpImgViewer('/uploads/' + msg.file_path);
            bubble.appendChild(preview);
        } else if (msg.message_type === 'video' && msg.file_path) {
            const fm = document.createElement('div');
            fm.className = 'file-message';
            fm.innerHTML = `<div class="file-icon-box"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg></div><div style="flex:1;min-width:0;"><div style="font-weight:600;font-size:13px;margin-bottom:4px;">${msg.file_name||'Video'}</div><div style="font-size:11px;color:#666;">${formatFileSize(msg.file_size)}</div></div><button class="file-dl-btn" onclick="window.open('/uploads/${msg.file_path}')">Open</button>`;
            bubble.appendChild(fm);
        } else if (msg.message_type !== 'text' && msg.file_path) {
            const fm = document.createElement('div');
            fm.className = 'file-message';
            fm.innerHTML = `<div class="file-icon-box"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></div><div style="flex:1;min-width:0;"><div style="font-weight:600;font-size:13px;margin-bottom:4px;">${msg.file_name||'File'}</div><div style="font-size:11px;color:#666;">${formatFileSize(msg.file_size)}</div></div><button class="file-dl-btn" onclick="window.location='/uploads/${msg.file_path}'">Download</button>`;
            bubble.appendChild(fm);
        } else {
            const txt = document.createElement('div');
            txt.textContent = msg.message;
            bubble.appendChild(txt);
        }

        const time = document.createElement('div');
        time.className = 'msg-time';
        time.textContent = formatTime(msg.timestamp);
        bubble.appendChild(time);

        // Render persisted reactions (loaded from DB)
        if (msg.reactions && msg.reactions.length > 0) {
            renderGroupReactions(bubble, msg.reactions);
        }

        group.appendChild(bubble);
        return group;
    }

    function scrollGrpToBottom(smooth = false) {
        requestAnimationFrame(() => {
            grpChat.scrollTop = grpChat.scrollHeight;
        });
    }

    function appendMessage(msg, scroll=true) {
        const indicator = document.getElementById('grpLoadingIndicator');
        if (indicator) indicator.remove();
        const el = createBubble(msg);
        grpChat.appendChild(el);
        attachBubbleEvents(el);
        if (scroll) scrollGrpToBottom(true);
    }

    // ── Load messages ─────────────────────────────────────────────
    function loadMessages() {
        const textUrl  = '/api/group_messages?group_id=' + groupId + '&user_phone=' + encodeURIComponent(myPhone) + '&page=1&limit=50';
        const voiceUrl = '/api/voice/history?group_id=' + groupId + '&user_phone=' + encodeURIComponent(myPhone);

        Promise.all([
            fetch(textUrl).then(r => r.json()).catch(() => []),
            fetch(voiceUrl).then(r => r.json()).catch(() => [])
        ]).then(([textMsgs, voiceMsgs]) => {
            voiceMsgs.forEach(m => { m.message_type = 'voice'; });
            const all = [...textMsgs, ...voiceMsgs].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
            const frag = document.createDocumentFragment();
            all.forEach(m => {
                const el = m.message_type === 'voice' ? GVM_renderBubble(m) : createBubble(m);
                attachBubbleEvents(el);
                frag.appendChild(el);
            });
            grpChat.innerHTML = '';
            grpChat.appendChild(frag);
            grpChat.querySelectorAll('.message-appear').forEach(el => el.classList.remove('message-appear'));
            scrollGrpToBottom(false);
        }).catch(() => showGrpToast('Failed to load messages'));
    }

    // ── Send message ──────────────────────────────────────────────
    function sendGroupMessage() {
        const msg = grpInput.value.trim();
        if (!msg) return;

        const tempId = 'temp_' + Date.now();
        appendMessage({ sender: myPhone, message: msg, message_type: 'text', temp_id: tempId });
        grpInput.value = '';
        grpInput.style.height = 'auto';

        if (!isConnected) {
            showGrpToast('Reconnecting… message will send shortly');
            const retry = setInterval(() => {
                if (isConnected) {
                    clearInterval(retry);
                    socket.emit('send_group_message', { group_id: groupId, sender: String(myPhone), message: msg, temp_id: tempId });
                }
            }, 500);
            setTimeout(() => clearInterval(retry), 15000);
            return;
        }
        socket.emit('send_group_message', { group_id: groupId, sender: String(myPhone), message: msg, temp_id: tempId });
    }

    grpInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendGroupMessage(); }
    });

    grpInput.addEventListener('input', function() {
        if (!isConnected) return;
        socket.emit('group_typing', { group_id: groupId, user: String(myPhone) });
        clearTimeout(typingTimer);
        typingTimer = setTimeout(() => socket.emit('group_stop_typing', { group_id: groupId, user: String(myPhone) }), 2000);
    });

    // ── File upload ───────────────────────────────────────────────
    function openGrpFileModal() { document.getElementById('grpFileModal').style.display = 'flex'; }
    function closeGrpFileModal() { document.getElementById('grpFileModal').style.display = 'none'; grpFileInput.value = ''; }

    function triggerGrpFile(type) {
        const accepts = { image:'image/*', video:'video/*', document:'*/*' };
        grpFileInput.accept = accepts[type] || '*/*';
        grpFileInput.onchange = function() {
            if (this.files.length > 0) uploadGroupFile(this.files[0], type);
        };
        grpFileInput.click();
        closeGrpFileModal();
    }

    // Tracks temp_ids for in-flight file uploads so socket won't double-render them
    const pendingFileTempIds = new Set();

    function uploadGroupFile(file, fileType) {
        if (file.size > 16*1024*1024) { showGrpToast('File too large (max 16MB)'); return; }

        // Create and track a temp bubble element directly
        const tempId = 'temp_' + Date.now();
        pendingFileTempIds.add(tempId);
        const tempEl = createBubble({ sender: myPhone, message: 'Uploading ' + file.name + '…', message_type: 'text', temp_id: tempId });
        grpChat.appendChild(tempEl);
        scrollGrpToBottom(false);

        const fd = new FormData();
        fd.append('file', file);
        fd.append('sender', String(myPhone));
        fd.append('receiver', 'group_' + groupId);

        fetch('/upload_file', { method:'POST', body:fd })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                // Remove the temp bubble group element directly
                if (tempEl.parentNode) tempEl.remove();
                const newTempId = 'temp_' + Date.now();
                pendingFileTempIds.add(newTempId);
                const filePayload = {
                    group_id: groupId, sender: String(myPhone),
                    message: file.name, message_type: data.file_type,
                    file_path: data.file_path, file_name: data.file_name,
                    file_size: data.file_size, temp_id: newTempId
                };
                if (!isConnected) {
                    showGrpToast('Reconnecting… file will send shortly');
                    const retry = setInterval(() => {
                        if (isConnected) {
                            clearInterval(retry);
                            socket.emit('send_group_message', filePayload);
                        }
                    }, 500);
                    setTimeout(() => { clearInterval(retry); pendingFileTempIds.delete(newTempId); showGrpToast('Could not send file. Please try again.'); }, 15000);
                    return;
                }
                socket.emit('send_group_message', filePayload);
            } else {
                if (tempEl.parentNode) tempEl.remove();
                pendingFileTempIds.delete(tempId);
                showGrpToast('Upload failed: ' + (data.error || 'Unknown error'));
            }
        })
        .catch(() => {
            if (tempEl.parentNode) tempEl.remove();
            pendingFileTempIds.delete(tempId);
            showGrpToast('Upload error. Please try again.');
        });
    }

    // ── Image viewer ──────────────────────────────────────────────
    function openGrpImgViewer(src) {
        const viewer = document.getElementById('grp-img-viewer');
        document.getElementById('grp-img-viewer-img').src = src;
        viewer.classList.add('open');
    }
    function closeGrpImgViewer() {
        const viewer = document.getElementById('grp-img-viewer');
        viewer.classList.remove('open');
        document.getElementById('grp-img-viewer-img').src = '';
    }
    // Prevent close when tapping the image itself
    document.getElementById('grp-img-viewer-img').addEventListener('click', e => e.stopPropagation());

    document.getElementById('grpFileModal').addEventListener('click', function(e) {
        if (e.target === this) closeGrpFileModal();
    });

    // ── Socket ────────────────────────────────────────────────────
    const socket = io({
        reconnection:true, reconnectionDelay:2000,
        reconnectionDelayMax:10000, reconnectionAttempts:Infinity,
        timeout:30000, transports:['polling','websocket'],
        upgrade:true,
    });

    socket.on('connect', () => {
        isConnected = true;
        socket.emit('join_group', { group_id: groupId, user: String(myPhone) });
    });

    socket.on('disconnect', () => { isConnected = false; });

    socket.on('receive_group_message', function(data) {
        if (String(data.group_id) !== String(groupId)) return;

        if (String(data.sender) === String(myPhone) && data.temp_id) {
            // Own message confirmed — remove from pending set and render the real bubble
            pendingFileTempIds.delete(data.temp_id);
            // Update temp text bubble ID if present (text messages)
            const t = document.querySelector('[data-temp-id="' + data.temp_id + '"]');
            if (t) { t.dataset.messageId = data.id; delete t.dataset.tempId; return; }
            // For file messages the temp element was already removed; render the real bubble now
            appendMessage(data);
            return;
        }

        appendMessage(data);
    });

    socket.on('group_typing', function(data) {
        if (String(data.group_id) !== String(groupId) || String(data.user) === String(myPhone)) return;
        const name = getSenderName(data.user);
        grpTyping.textContent = name + ' is typing…';
    });

    socket.on('group_stop_typing', function(data) {
        if (String(data.group_id) !== String(groupId)) return;
        grpTyping.textContent = '';
    });

    // ── Keyboard / visualViewport ─────────────────────────────────
    if (window.visualViewport) {
        window.visualViewport.addEventListener('resize', () => {
            const offset = Math.max(0, window.innerHeight - window.visualViewport.height);
            document.getElementById('grp-message-box').style.paddingBottom = 'calc(16px + env(safe-area-inset-bottom,0px) + ' + offset + 'px)';
        });
    }
    grpInput.addEventListener('focus', () => setTimeout(() => { scrollGrpToBottom(false); }, 350));

    // ── Context menu & reactions ──────────────────────────────────
    let ctxTargetBubble = null;
    let ctxTargetMsg = null;
    const ctxMenu = document.getElementById('grp-context-menu');
    const emojiBar = document.getElementById('grp-emoji-bar');

    function closeCtx() {
        ctxMenu.style.display = 'none';
        emojiBar.style.display = 'none';
        ctxTargetBubble = null;
        ctxTargetMsg = null;
    }

    function positionPopup(el, x, y) {
        el.style.display = 'flex';
        const r = el.getBoundingClientRect();
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        let left = x, top = y + 10;
        if (left + r.width > vw - 8) left = vw - r.width - 8;
        if (top + r.height > vh - 8) top = y - r.height - 10;
        el.style.left = Math.max(8, left) + 'px';
        el.style.top = Math.max(8, top) + 'px';
    }

    function openCtxMenu(bubble, msgId, msgText, clientX, clientY) {
        ctxTargetBubble = bubble;
        ctxTargetMsg = { id: msgId, text: msgText };
        emojiBar.style.display = 'none';
        ctxMenu.style.display = 'block';
        positionPopup(ctxMenu, clientX, clientY);
    }

    // Long-press & right-click on bubbles
    let longPressTimer = null;
    function attachBubbleEvents(el) {
        // Support both text (.bubble) and voice (.gvm-bubble) elements
        // For received voice, el is outer wrapper; for sent voice, el IS the .gvm-bubble
        const bubble = el.classList.contains('gvm-bubble') ? el
            : el.querySelector('.gvm-bubble') || el.querySelector('.bubble') || el;

        // messageId may be on el (outer) or on bubble (inner) — check both
        const getMsgId = () => el.dataset.messageId || bubble.dataset.messageId || null;
        const getMsgText = () => {
            if (bubble.classList.contains('gvm-bubble')) return '🎤 Voice message';
            const txt = bubble.querySelector('div:not(.msg-time):not(.grp-msg-reactions)');
            return txt ? txt.textContent : '';
        };

        const target = bubble.classList.contains('gvm-bubble') ? bubble : (el.querySelector('.bubble') || el);

        target.addEventListener('contextmenu', function(e) {
            e.preventDefault();
            const id = getMsgId();
            if (id) openCtxMenu(bubble, id, getMsgText(), e.clientX, e.clientY);
        });

        target.addEventListener('touchstart', function(e) {
            longPressTimer = setTimeout(() => {
                const id = getMsgId();
                if (!id) return;
                const t = e.touches[0];
                openCtxMenu(bubble, id, getMsgText(), t.clientX, t.clientY);
            }, 500);
        }, { passive: true });
        target.addEventListener('touchend', () => clearTimeout(longPressTimer), { passive: true });
        target.addEventListener('touchmove', () => clearTimeout(longPressTimer), { passive: true });
    }

    document.addEventListener('click', function(e) {
        if (!ctxMenu.contains(e.target) && !emojiBar.contains(e.target)) closeCtx();
    });

    // Copy action
    document.getElementById('grpCtxCopy').addEventListener('click', function() {
        if (!ctxTargetMsg) return;
        const text = ctxTargetMsg.text;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => showGrpToast('Copied!'));
        } else {
            const ta = document.createElement('textarea');
            ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
            document.body.appendChild(ta); ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            showGrpToast('Copied!');
        }
        closeCtx();
    });

    // React action — show emoji bar
    document.getElementById('grpCtxReact').addEventListener('click', function() {
        if (!ctxTargetMsg) return;
        const rect = ctxMenu.getBoundingClientRect();
        ctxMenu.style.display = 'none';
        emojiBar.style.display = 'flex';
        positionPopup(emojiBar, rect.left, rect.top);
    });

    // Emoji buttons
    document.querySelectorAll('.grp-emoji-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            if (!ctxTargetMsg || !ctxTargetMsg.id) { closeCtx(); return; }
            socket.emit('add_group_reaction', {
                message_id: ctxTargetMsg.id,
                emoji: this.dataset.emoji,
                user_phone: String(myPhone),
                group_id: groupId
            });
            closeCtx();
        });
        btn.addEventListener('touchend', function(e) {
            e.preventDefault();
            if (!ctxTargetMsg || !ctxTargetMsg.id) { closeCtx(); return; }
            socket.emit('add_group_reaction', {
                message_id: ctxTargetMsg.id,
                emoji: this.dataset.emoji,
                user_phone: String(myPhone),
                group_id: groupId
            });
            closeCtx();
        });
    });

    // Render reactions on a bubble
    function renderGroupReactions(bubble, reactions) {
        let container = bubble.querySelector('.grp-msg-reactions');
        if (container) container.remove();
        if (!reactions || reactions.length === 0) return;
        const counts = {};
        const myEmojis = new Set();
        reactions.forEach(r => {
            counts[r.emoji] = (counts[r.emoji] || 0) + 1;
            if (String(r.user_phone) === String(myPhone)) myEmojis.add(r.emoji);
        });
        container = document.createElement('div');
        container.className = 'grp-msg-reactions';
        Object.entries(counts).forEach(([emoji, count]) => {
            const pill = document.createElement('div');
            pill.className = 'grp-reaction-pill' + (myEmojis.has(emoji) ? ' grp-reaction-mine' : '');
            pill.innerHTML = `<span>${emoji}</span>` + (count > 1 ? `<span class="grp-r-count">${count}</span>` : '');
            const emitReact = () => {
                const msgId = bubble.dataset.messageId;
                if (!msgId) return;
                socket.emit('add_group_reaction', {
                    message_id: msgId, emoji, user_phone: String(myPhone), group_id: groupId
                });
            };
            let touchStartedOnPill = false;
            pill.addEventListener('touchstart', function(e) {
                touchStartedOnPill = true;
                e.stopPropagation();
            }, { passive: true });
            pill.addEventListener('touchend', function(e) {
                e.preventDefault(); e.stopPropagation();
                if (touchStartedOnPill) { touchStartedOnPill = false; emitReact(); }
            });
            pill.addEventListener('touchcancel', () => { touchStartedOnPill = false; });
            pill.addEventListener('click', function(e) { e.stopPropagation(); emitReact(); });
            container.appendChild(pill);
        });
        const anchor = bubble.querySelector('.msg-time') || bubble.querySelector('.gvm-meta') || null;
        if (anchor) bubble.insertBefore(container, anchor);
        else bubble.appendChild(container);
    }

    // Socket: receive group reaction updates
    socket.on('group_reaction_updated', function(data) {
        if (String(data.group_id) !== String(groupId)) return;
        const bubble = document.querySelector('[data-message-id="' + String(data.message_id) + '"]');
        if (bubble) renderGroupReactions(bubble, data.reactions);
    });

    // ── Init ──────────────────────────────────────────────────────
    loadGroupInfo();

    // ── GROUP VOICE MESSAGING ─────────────────────────────────────
    const GVM = (() => {
        let mediaRecorder=null,audioChunks=[],audioCtx=null,analyser=null,
            liveSource=null,animFrame=null,startTime=0,timerInterval=null,
            isRec=false,ampHistory=[];
        const overlay  = ()=>document.getElementById('grp-vm-overlay');
        const timerEl  = ()=>document.getElementById('grp-vm-timer');
        const cvs      = ()=>document.getElementById('grp-vm-canvas');
        const micBtn   = ()=>document.getElementById('grp-mic-btn');

        function toggle(){ isRec?stopAndSend():start(); }

        async function start(){
            if(isRec) return;
            if(!window.MediaRecorder||!navigator.mediaDevices){
                alert('Voice messages are not supported in this browser. Please use Chrome, Firefox, or Safari 14.1+.');
                return;
            }
            try{
                const stream=await navigator.mediaDevices.getUserMedia({audio:true});
                audioCtx=new(window.AudioContext||window.webkitAudioContext)();
                analyser=audioCtx.createAnalyser(); analyser.fftSize=256;
                liveSource=audioCtx.createMediaStreamSource(stream); liveSource.connect(analyser);
                const mime=['audio/mp4','audio/webm;codecs=opus','audio/webm','audio/ogg;codecs=opus']
                    .find(m=>MediaRecorder.isTypeSupported(m))||'';
                mediaRecorder=new MediaRecorder(stream,mime?{mimeType:mime}:{});
                audioChunks=[]; ampHistory=[];
                mediaRecorder.ondataavailable=e=>{ if(e.data&&e.data.size>0) audioChunks.push(e.data); };
                mediaRecorder.start(100);
                isRec=true; startTime=Date.now();
                overlay().classList.add('active'); micBtn()?.classList.add('grp-vm-rec');
                timerInterval=setInterval(()=>{
                    const s=Math.floor((Date.now()-startTime)/1000);
                    timerEl().textContent=Math.floor(s/60)+':'+String(s%60).padStart(2,'0');
                    if(s>=300) stopAndSend();
                },500);
                drawLive();
            }catch(e){ alert('Microphone access required for voice messages.'); }
        }

        function cancel(){
            if(!isRec) return;
            cleanup(); overlay().classList.remove('active'); micBtn()?.classList.remove('grp-vm-rec');
        }

        function stopAndSend(){
            if(!isRec) return;
            const dur=Date.now()-startTime;
            mediaRecorder.onstop=async()=>{
                const mt=mediaRecorder.mimeType||'audio/mp4';
                const ext=mt.includes('ogg')?'ogg':mt.includes('mp4')||mt.includes('aac')?'m4a':'webm';
                const blob=new Blob(audioChunks,{type:mt||'audio/mp4'});
                await upload(blob,ext,dur,deriveWave());
            };
            // Request final chunk before stopping so blob is complete immediately
            if(mediaRecorder.state==='recording') mediaRecorder.requestData();
            mediaRecorder.stop(); cleanup();
            overlay().classList.remove('active'); micBtn()?.classList.remove('grp-vm-rec');
        }

        async function upload(blob,ext,durMs,waveform){
            const tempEl=document.createElement('div');
            tempEl.className='gvm-temp-marker'; // marker to find this specific upload
            const tempMsg={id:'gvmtmp_'+Date.now(),sender:String(myPhone),group_id:groupId,
                file_name:null,duration_ms:durMs,waveform,timestamp:new Date().toISOString(),
                status:'uploading',message_type:'voice'};
            const el=renderBubble(tempMsg);
            el.appendChild(tempEl);
            grpChat.appendChild(el); scrollGrpToBottom(true);
            const fd=new FormData();
            fd.append('audio',blob,'voice.'+ext);
            fd.append('sender',String(myPhone));
            fd.append('group_id',groupId);
            fd.append('duration_ms',durMs);
            fd.append('waveform',JSON.stringify(waveform));
            try{
                const res=await fetch('/api/voice/upload',{method:'POST',body:fd});
                const data=await res.json();
                // Don't wireAudio here — socket onVoiceMessage handles it
                // If socket already confirmed it (fast path), bubble is already wired
                if(!data.success){ el.remove(); }
            }catch(e){ el.remove(); }
        }

        function renderBubble(msg){
            const isOut=String(msg.sender)===String(myPhone);
            const wave=msg.waveform&&msg.waveform.length?msg.waveform:Array(40).fill(0.5);
            const wrap=document.createElement('div');
            wrap.className='gvm-bubble '+(isOut?'gvm-out':'gvm-in')+(msg.status==='uploading'?' gvm-uploading':'');
            wrap.dataset.vmId=msg.id||'';
            if(msg.id && !String(msg.id).startsWith('gvmtmp_')) wrap.dataset.messageId='v_'+String(msg.id);
            wrap.dataset.file=msg.file_name||'';
            const play=document.createElement('button'); play.className='gvm-play'; play.innerHTML=pi();
            wrap.appendChild(play);
            const ww=document.createElement('div'); ww.className='gvm-ww';
            const waveEl=document.createElement('div'); waveEl.className='gvm-wave';
            wave.forEach((a)=>{
                const b=document.createElement('div'); b.className='gvm-bar';
                b.style.height=Math.max(4,Math.round(a*28))+'px'; waveEl.appendChild(b);
            });
            ww.appendChild(waveEl);
            const meta=document.createElement('div'); meta.className='gvm-meta';
            const dur=document.createElement('span'); dur.className='gvm-dur';
            dur.textContent=fmtMs(msg.duration_ms||0); meta.appendChild(dur);
            ww.appendChild(meta); wrap.appendChild(ww);
            if(!isOut){
                const lbl=document.createElement('div');
                lbl.style.cssText='font-size:11px;font-weight:600;color:var(--accent);margin-bottom:3px;';
                lbl.textContent=getSenderName(msg.sender);
                const outer=document.createElement('div');
                outer.style.cssText='display:flex;flex-direction:column;align-items:'+(isOut?'flex-end':'flex-start');
                outer.appendChild(lbl); outer.appendChild(wrap);
                if(msg.id && !String(msg.id).startsWith('gvmtmp_')) outer.dataset.messageId='v_'+String(msg.id);
                if(msg.reactions && msg.reactions.length > 0){
                    const msgId = msg.id ? 'v_'+String(msg.id) : null;
                    if(msgId){
                        const reEl = renderGroupReactions_el(msg.reactions, msgId);
                        if(reEl) wrap.appendChild(reEl);
                    }
                }
                if(msg.file_name&&msg.status!=='uploading') wireAudio(wrap,msg.file_name,msg.duration_ms||0,wave,isOut,msg);
                return outer;
            }
            if(msg.reactions && msg.reactions.length > 0){
                const msgId = msg.id ? 'v_'+String(msg.id) : null;
                if(msgId){
                    const reEl = renderGroupReactions_el(msg.reactions, msgId);
                    if(reEl) wrap.appendChild(reEl);
                }
            }
            if(msg.file_name&&msg.status!=='uploading') wireAudio(wrap,msg.file_name,msg.duration_ms||0,wave,isOut,msg);
            return wrap;
        }

        // Build a reactions container element (used by renderBubble for history)
        function renderGroupReactions_el(reactions, msgId) {
            if (!reactions || reactions.length === 0) return null;
            const counts = {}; const myEmojis = new Set();
            reactions.forEach(r => {
                counts[r.emoji] = (counts[r.emoji] || 0) + 1;
                if (String(r.user_phone) === String(myPhone)) myEmojis.add(r.emoji);
            });
            const container = document.createElement('div');
            container.className = 'grp-msg-reactions';
            Object.entries(counts).forEach(([emoji, count]) => {
                const pill = document.createElement('div');
                pill.className = 'grp-reaction-pill' + (myEmojis.has(emoji) ? ' grp-reaction-mine' : '');
                pill.innerHTML = `<span>${emoji}</span>` + (count > 1 ? `<span class="grp-r-count">${count}</span>` : '');
                const emitReact = () => socket.emit('add_group_reaction', { message_id: msgId, emoji, user_phone: String(myPhone), group_id: groupId });
                let tsp = false;
                pill.addEventListener('touchstart', e => { tsp = true; e.stopPropagation(); }, { passive: true });
                pill.addEventListener('touchend', e => { e.preventDefault(); e.stopPropagation(); if(tsp){ tsp=false; emitReact(); } });
                pill.addEventListener('touchcancel', () => { tsp = false; });
                pill.addEventListener('click', e => { e.stopPropagation(); emitReact(); });
                container.appendChild(pill);
            });
            return container;
        }

        function wireAudio(wrap,fileName,durMs,wave,isOut,msg){
            const audio=new Audio('/api/voice/file/'+fileName);
            audio.preload='metadata';
            let playing=false;
            const bars=wrap.querySelectorAll('.gvm-bar');
            const durEl=wrap.querySelector('.gvm-dur');
            const play=wrap.querySelector('.gvm-play');
            const waveEl=wrap.querySelector('.gvm-wave');
            waveEl.addEventListener('click',e=>{
                const r=waveEl.getBoundingClientRect();
                const ratio=(e.clientX-r.left)/r.width;
                if(audio.duration){ audio.currentTime=ratio*audio.duration; upd(); }
            });
            audio.addEventListener('timeupdate',upd);
            audio.addEventListener('ended',()=>{
                playing=false; play.innerHTML=pi();
                bars.forEach(b=>b.classList.remove('gvm-p'));
                durEl.textContent=fmtMs(durMs);
            });
            play.addEventListener('click',()=>{
                if(playing){ audio.pause(); playing=false; play.innerHTML=pi(); }
                else{
                    document.querySelectorAll('.gvm-audio-active,.vm-audio-active').forEach(a=>{
                        a.pause(); a.dispatchEvent(new Event('ended')); a.classList.remove('gvm-audio-active','vm-audio-active');
                    });
                    audio.play().then(()=>{
                        audio.classList.add('gvm-audio-active'); playing=true; play.innerHTML=pauseI();
                    }).catch(err=>{
                        play.style.opacity='0.5';
                        setTimeout(()=>play.style.opacity='',600);
                    });
                }
            });
            function upd(){
                if(!audio.duration) return;
                const pct=audio.currentTime/audio.duration,filled=Math.floor(pct*bars.length);
                bars.forEach((b,i)=>i<filled?b.classList.add('gvm-p'):b.classList.remove('gvm-p'));
                durEl.textContent=fmtMs(Math.max(0,(audio.duration-audio.currentTime)*1000));
            }
        }

        socket.on('voice_message',msg=>{
            if(String(msg.group_id)!==String(groupId)) return;
            if(String(msg.sender)===String(myPhone)){
                // Find the uploading temp bubble (may have marker or uploading class)
                const tmpEl=document.querySelector('.gvm-bubble.gvm-uploading');
                if(tmpEl){
                    // Only wireAudio once — check it hasn't been wired already
                    if(!tmpEl.dataset.wired){
                        tmpEl.dataset.wired='1';
                        tmpEl.dataset.vmId=String(msg.id);
                        tmpEl.dataset.file=msg.file_name;
                        tmpEl.dataset.messageId='v_'+String(msg.id);
                        tmpEl.classList.remove('gvm-uploading');
                        if(tmpEl.parentElement) tmpEl.parentElement.dataset.messageId='v_'+String(msg.id);
                        wireAudio(tmpEl,msg.file_name,msg.duration_ms||0,msg.waveform||[],true,msg);
                    }
                }
                return;
            }
            if(msg.id && document.querySelector('[data-message-id="'+msg.id+'"]')) return;
            const el=renderBubble(msg);
            attachBubbleEvents(el);
            grpChat.appendChild(el); scrollGrpToBottom(true);
        });

        function drawLive(){
            const c=cvs(); if(!c) return;
            const ctx=c.getContext('2d'); const W=c.width,H=c.height;
            const buf=new Uint8Array(analyser.frequencyBinCount);
            (function frame(){
                if(!isRec) return; animFrame=requestAnimationFrame(frame);
                analyser.getByteFrequencyData(buf);
                const amp=buf.reduce((s,v)=>s+v,0)/(buf.length*255);
                ampHistory.push(amp); if(ampHistory.length>200) ampHistory.shift();
                ctx.clearRect(0,0,W,H);
                const bars=56,barW=W/bars-2;
                for(let i=0;i<bars;i++){
                    const idx=Math.min(Math.floor(i*ampHistory.length/bars),ampHistory.length-1);
                    const a=ampHistory[idx]||0,bH=Math.max(4,a*(H-8));
                    ctx.fillStyle=`rgba(255,255,255,${0.35+a*0.65})`;
                    ctx.beginPath(); ctx.roundRect(i*(barW+2),(H-bH)/2,barW,bH,2); ctx.fill();
                }
            })();
        }

        function deriveWave(bars=40){
            if(!ampHistory.length) return Array(bars).fill(0.5);
            const out=[],step=ampHistory.length/bars;
            for(let i=0;i<bars;i++){
                const s=Math.floor(i*step),e=Math.min(Math.floor((i+1)*step),ampHistory.length);
                let sum=0; for(let j=s;j<e;j++) sum+=ampHistory[j];
                out.push(Math.round(Math.min(1,(e>s?sum/(e-s):0)*2.5)*1000)/1000);
            }
            return out;
        }

        function cleanup(){
            isRec=false; clearInterval(timerInterval); cancelAnimationFrame(animFrame);
            if(mediaRecorder&&mediaRecorder.state!=='inactive') mediaRecorder.stop();
            mediaRecorder?.stream?.getTracks().forEach(t=>t.stop());
            if(audioCtx){ audioCtx.close(); audioCtx=null; }
            analyser=null; liveSource=null; timerEl().textContent='0:00';
        }

        function fmtMs(ms){ const s=Math.ceil(ms/1000); return Math.floor(s/60)+':'+String(s%60).padStart(2,'0'); }
        function pi(){ return '<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>'; }
        function pauseI(){ return '<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>'; }

        return { toggle, cancel, stopAndSend, renderBubble };
    })();
    // Expose GVM renderBubble for loadMessages (must be after GVM is defined)
    function GVM_renderBubble(msg){ return GVM.renderBubble(msg); }
    // Now safe to load messages — GVM_renderBubble is available
    loadMessages();
    // ─────────────────────────────────────────────────────────────
</script>
</body>
</html>"""


# ----------------- Group API Routes -----------------

@app.route("/api/groups")
def api_groups():
    phone = request.args.get("phone")
    if not phone:
        return jsonify([]), 400
    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("""
                SELECT g.id, g.name, g.avatar_letter, g.created_by,
                       COUNT(gm2.user_phone) as member_count,
                       (SELECT gm3.message FROM group_messages gm3
                        WHERE gm3.group_id = g.id ORDER BY gm3.timestamp DESC LIMIT 1) as last_message
                FROM groups g
                JOIN group_members gm ON g.id = gm.group_id AND gm.user_phone = ?
                LEFT JOIN group_members gm2 ON g.id = gm2.group_id
                GROUP BY g.id
                ORDER BY g.created_at DESC
            """, (phone,))
            rows = c.fetchall()
        finally:
            return_db_connection(conn)
        groups = [{"id": r[0], "name": r[1], "avatar_letter": r[2],
                   "created_by": r[3], "member_count": r[4], "last_message": r[5]} for r in rows]
        return jsonify(groups)
    except Exception as e:
        print(f"Error in api_groups: {e}")
        return jsonify([]), 500


@app.route("/api/create_group", methods=["POST"])
def api_create_group():
    try:
        data = request.get_json()
        name = data.get("name", "").strip()
        created_by = data.get("created_by", "").strip()
        members = data.get("members", [])

        if not name or not created_by:
            return jsonify({"success": False, "error": "Missing name or creator"}), 400
        if len(name) > 50:
            return jsonify({"success": False, "error": "Group name too long"}), 400

        avatar_letter = name[0].upper()
        members_sorted = sorted([str(m).strip() for m in members if str(m).strip() and str(m).strip() != created_by])
        members_key = ','.join(members_sorted)

        conn = get_db_connection()
        try:
            c = conn.cursor()
            # Duplicate prevention: check if same group (name+creator+members) was created in last 10 seconds
            c.execute("""
                SELECT g.id FROM groups g
                WHERE g.name=? AND g.created_by=?
                AND g.created_at >= datetime('now', '-10 seconds')
            """, (name, created_by))
            existing = c.fetchone()
            if existing:
                return jsonify({"success": True, "group_id": existing[0]})

            c.execute("INSERT INTO groups (name, created_by, avatar_letter) VALUES (?, ?, ?)",
                      (name, created_by, avatar_letter))
            group_id = c.lastrowid

            # Add creator as admin
            c.execute("INSERT INTO group_members (group_id, user_phone, role) VALUES (?, ?, 'admin')",
                      (group_id, created_by))
            # Add members
            for m in members:
                m = str(m).strip()
                if m and m != created_by:
                    c.execute("INSERT OR IGNORE INTO users(phone, last_online) VALUES(?, ?)",
                              (m, datetime.now().isoformat()))
                    c.execute("INSERT OR IGNORE INTO group_members (group_id, user_phone) VALUES (?, ?)",
                              (group_id, m))
            conn.commit()
        finally:
            return_db_connection(conn)

        return jsonify({"success": True, "group_id": group_id})
    except Exception as e:
        print(f"Error in create_group: {e}")
        return jsonify({"success": False, "error": "Server error"}), 500


@app.route("/api/group_messages")
def api_group_messages():
    group_id = request.args.get("group_id", type=int)
    user_phone = request.args.get("user_phone")
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 50, type=int)
    offset = (page - 1) * limit

    if not group_id or not user_phone:
        return jsonify([]), 400

    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            # Verify membership
            c.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_phone=?", (group_id, user_phone))
            if not c.fetchone():
                return jsonify([]), 403

            c.execute("""
                SELECT gm.id, gm.sender, gm.message, gm.message_type,
                       gm.file_path, gm.file_name, gm.file_size, gm.timestamp,
                       COALESCE(con.contact_name, gm.sender) as sender_name
                FROM group_messages gm
                LEFT JOIN contacts con ON con.user_phone=? AND con.contact_phone=gm.sender
                WHERE gm.group_id=?
                ORDER BY gm.timestamp ASC
                LIMIT ? OFFSET ?
            """, (user_phone, group_id, limit, offset))
            rows = c.fetchall()

            # Fetch reactions for all returned messages in one query
            msg_ids = [r[0] for r in rows]
            reactions_by_msg = {}
            if msg_ids:
                placeholders = ','.join('?' * len(msg_ids))
                c.execute(f"""
                    SELECT message_id, user_phone, emoji
                    FROM message_reactions
                    WHERE message_id IN ({placeholders})
                """, msg_ids)
                for rxn in c.fetchall():
                    reactions_by_msg.setdefault(rxn[0], []).append(
                        {'user_phone': rxn[1], 'emoji': rxn[2]}
                    )
        finally:
            return_db_connection(conn)

        messages = []
        for r in rows:
            messages.append({
                "id": r[0], "sender": r[1], "message": r[2],
                "message_type": r[3], "file_path": r[4],
                "file_name": r[5], "file_size": r[6],
                "timestamp": r[7], "sender_name": r[8],
                "reactions": reactions_by_msg.get(r[0], [])
            })
        return jsonify(messages)
    except Exception as e:
        print(f"Error in group_messages: {e}")
        return jsonify([]), 500


@app.route("/api/group_info")
def api_group_info():
    group_id = request.args.get("group_id", type=int)
    user_phone = request.args.get("user_phone")
    if not group_id or not user_phone:
        return jsonify({}), 400
    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("SELECT id, name, avatar_letter, created_by FROM groups WHERE id=?", (group_id,))
            g = c.fetchone()
            if not g:
                return jsonify({}), 404
            c.execute("""
                SELECT gm.user_phone, COALESCE(con.contact_name, gm.user_phone) as display_name, gm.role
                FROM group_members gm
                LEFT JOIN contacts con ON con.user_phone=? AND con.contact_phone=gm.user_phone
                WHERE gm.group_id=?
            """, (user_phone, group_id))
            members = [{"phone": r[0], "name": r[1], "role": r[2]} for r in c.fetchall()]
        finally:
            return_db_connection(conn)
        return jsonify({"id": g[0], "name": g[1], "avatar_letter": g[2],
                        "created_by": g[3], "members": members})
    except Exception as e:
        print(f"Error in group_info: {e}")
        return jsonify({}), 500


@app.route("/api/add_group_members", methods=["POST"])
def api_add_group_members():
    try:
        data = request.get_json()
        group_id = data.get("group_id")
        added_by = str(data.get("added_by", "")).strip()
        members = data.get("members", [])

        if not group_id or not added_by or not members:
            return jsonify({"success": False, "error": "Missing data"}), 400

        conn = get_db_connection()
        try:
            c = conn.cursor()
            # Only admins can add members
            c.execute("SELECT role FROM group_members WHERE group_id=? AND user_phone=?", (group_id, added_by))
            row = c.fetchone()
            if not row or row[0] != 'admin':
                return jsonify({"success": False, "error": "Only admins can add members"}), 403

            now_iso = datetime.now().isoformat()
            added = 0
            for phone in members:
                phone = str(phone).strip()
                if not phone:
                    continue
                c.execute("INSERT OR IGNORE INTO users(phone, last_online) VALUES(?,?)", (phone, now_iso))
                result = c.execute(
                    "INSERT OR IGNORE INTO group_members (group_id, user_phone, role) VALUES (?,?,'member')",
                    (group_id, phone)
                )
                if result.rowcount:
                    added += 1
            conn.commit()
        finally:
            return_db_connection(conn)

        return jsonify({"success": True, "added": added})
    except Exception as e:
        print(f"Error in add_group_members: {e}")
        return jsonify({"success": False, "error": "Server error"}), 500


@app.route("/group/<int:group_id>")
def group_chat_page(group_id):
    phone = request.args.get("phone")
    if not phone:
        return redirect(url_for('signin'))
    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_phone=?", (group_id, phone))
            if not c.fetchone():
                return "Access denied", 403
            c.execute("SELECT name, avatar_letter FROM groups WHERE id=?", (group_id,))
            g = c.fetchone()
            if not g:
                return "Group not found", 404
            group_name = g[0]
            avatar_letter = g[1] or g[0][0].upper()
        finally:
            return_db_connection(conn)
        return render_template_string(group_chat_html,
                                      phone=phone,
                                      group_id=group_id,
                                      group_name=group_name,
                                      avatar_letter=avatar_letter)
    except Exception as e:
        print(f"Error in group_chat_page: {e}")
        return "An error occurred", 500


# ─────────────────────────────────────────────────────────────────────────────
# VOICE MESSAGING ROUTES
# ─────────────────────────────────────────────────────────────────────────────

def _voice_waveform(seed, bars=40):
    import random
    rng = random.Random(hashlib.md5(seed.encode()).hexdigest())
    return [round(rng.uniform(0.15, 1.0), 3) for _ in range(bars)]

@app.route('/api/voice/upload', methods=['POST'])
def voice_upload():
    if 'audio' not in request.files:
        return jsonify({'success': False, 'error': 'No audio file'}), 400
    audio_file  = request.files['audio']
    sender      = request.form.get('sender', '').strip()
    receiver    = request.form.get('receiver', '').strip()
    group_id    = request.form.get('group_id', type=int)
    duration_ms = request.form.get('duration_ms', 0, type=int)
    waveform    = request.form.get('waveform')
    if not sender:
        return jsonify({'success': False, 'error': 'Missing sender'}), 400
    if not receiver and not group_id:
        return jsonify({'success': False, 'error': 'Missing receiver or group_id'}), 400
    ext = (audio_file.filename.rsplit('.', 1)[-1].lower()
           if '.' in (audio_file.filename or '') else 'webm')
    if ext not in ALLOWED_AUDIO_EXTENSIONS:
        ext = 'webm'
    audio_data = audio_file.read()
    if len(audio_data) > MAX_VOICE_FILE_SIZE:
        return jsonify({'success': False, 'error': 'File too large (max 10 MB)'}), 413
    unique_name = f"{uuid.uuid4().hex}.{ext}"
    file_path   = os.path.join(VOICE_UPLOAD_FOLDER, unique_name)

    # Parse/validate waveform first — cheap, no I/O
    if waveform:
        try:
            bars = json.loads(waveform)
            assert isinstance(bars, list) and len(bars) > 0
            waveform_json = json.dumps([max(0.0, min(1.0, float(b))) for b in bars[:60]])
        except Exception:
            waveform_json = json.dumps(_voice_waveform(unique_name))
    else:
        waveform_json = json.dumps(_voice_waveform(unique_name))

    timestamp = datetime.now().isoformat()
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("""
            INSERT INTO voice_messages
                (sender,receiver,group_id,file_path,file_name,file_size,
                 duration_ms,waveform_data,status,timestamp)
            VALUES (?,?,?,?,?,?,?,?,'sent',?)
        """, (sender, receiver or None, group_id, file_path, unique_name,
              len(audio_data), duration_ms, waveform_json, timestamp))
        conn.commit()
        voice_id = c.lastrowid
    finally:
        return_db_connection(conn)

    payload = {
        'success': True, 'id': voice_id, 'sender': sender,
        'receiver': receiver or None, 'group_id': group_id,
        'file_name': unique_name, 'file_size': len(audio_data),
        'duration_ms': duration_ms, 'waveform': json.loads(waveform_json),
        'timestamp': timestamp, 'status': 'sent', 'message_type': 'voice',
    }

    # Emit to room BEFORE writing file to disk — receivers get notified immediately
    if group_id:
        socketio.emit('voice_message', payload, room=f'group_{group_id}')
        # Invalidate voice history cache for this group
        cache.delete(f"voice_history_group_{group_id}_0_30")
        cache.delete(f"voice_history_group_{group_id}_0_50")
    else:
        users = sorted([sender, receiver], key=str.lower)
        socketio.emit('voice_message', payload, room=f'room_{users[0]}_{users[1]}')
        cache.delete(f"voice_history_dm_{'_'.join(users)}_0_30")
        cache.delete(f"voice_history_dm_{'_'.join(users)}_0_50")

    # Write file after emitting — client already has the response, disk I/O doesn't block UX
    with open(file_path, 'wb') as f:
        f.write(audio_data)

    return jsonify(payload)

@app.route('/api/voice/file/<filename>')
def serve_voice_file(filename):
    try:
        from flask import make_response
        safe = os.path.basename(filename)
        ext = safe.rsplit('.', 1)[-1].lower() if '.' in safe else 'webm'
        mime_map = {'webm': 'audio/webm', 'ogg': 'audio/ogg', 'm4a': 'audio/mp4', 'mp4': 'audio/mp4', 'aac': 'audio/aac'}
        content_type = mime_map.get(ext, 'audio/webm')
        resp = make_response(send_from_directory(VOICE_UPLOAD_FOLDER, safe))
        resp.headers['Content-Type'] = content_type
        resp.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        resp.headers['Accept-Ranges'] = 'bytes'
        return resp
    except FileNotFoundError:
        return "File not found", 404

@app.route('/api/voice/history')
def voice_history():
    sender     = request.args.get('sender', '').strip()
    receiver   = request.args.get('receiver', '').strip()
    group_id   = request.args.get('group_id', type=int)
    user_phone = request.args.get('user_phone', '').strip()
    limit      = request.args.get('limit', 30, type=int)
    offset     = request.args.get('offset', 0, type=int)

    # Serve from cache when possible
    if group_id:
        cache_key = f"voice_history_group_{group_id}_{offset}_{limit}"
    else:
        users = sorted([sender, receiver], key=str.lower)
        cache_key = f"voice_history_dm_{'_'.join(users)}_{offset}_{limit}"
    cached = cache.get(cache_key)
    if cached:
        return jsonify(cached)

    conn = get_db_connection()
    try:
        c = conn.cursor()
        if group_id:
            c.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_phone=?", (group_id, user_phone))
            if not c.fetchone():
                return jsonify([]), 403
            c.execute("""SELECT id,sender,receiver,group_id,file_name,file_size,
                                duration_ms,waveform_data,status,timestamp,listened_at
                         FROM voice_messages WHERE group_id=?
                         ORDER BY timestamp ASC LIMIT ? OFFSET ?""", (group_id, limit, offset))
        else:
            if not sender or not receiver:
                return jsonify([]), 400
            c.execute("""SELECT id,sender,receiver,group_id,file_name,file_size,
                                duration_ms,waveform_data,status,timestamp,listened_at
                         FROM voice_messages
                         WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
                         ORDER BY timestamp ASC LIMIT ? OFFSET ?""",
                      (sender, receiver, receiver, sender, limit, offset))
        rows = c.fetchall()

        # Fetch reactions for these voice messages (stored with 'v_' prefix)
        reactions_dict = {}
        if rows:
            voice_ids = [f"v_{r[0]}" for r in rows]
            placeholders = ','.join('?' * len(voice_ids))
            c.execute(f"SELECT message_id, user_phone, emoji FROM message_reactions WHERE message_id IN ({placeholders})", voice_ids)
            for mid, rphone, remoji in c.fetchall():
                reactions_dict.setdefault(mid, []).append({'user_phone': rphone, 'emoji': remoji})
    finally:
        return_db_connection(conn)

    result = [{
        'id': r[0], 'sender': r[1], 'receiver': r[2], 'group_id': r[3],
        'file_name': r[4], 'file_size': r[5], 'duration_ms': r[6],
        'waveform': json.loads(r[7]) if r[7] else [],
        'status': r[8], 'timestamp': r[9], 'listened_at': r[10],
        'message_type': 'voice',
        'reactions': reactions_dict.get(f"v_{r[0]}", []),
    } for r in rows]
    cache.set(cache_key, result)
    return jsonify(result)

@app.route('/api/voice/listened', methods=['POST'])
def voice_listened():
    data       = request.get_json() or {}
    voice_id   = data.get('id')
    user_phone = data.get('user_phone', '').strip()
    if not voice_id or not user_phone:
        return jsonify({'success': False}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("UPDATE voice_messages SET status='listened',listened_at=? WHERE id=? AND receiver=?",
                  (datetime.now().isoformat(), voice_id, user_phone))
        conn.commit()
    finally:
        return_db_connection(conn)
    socketio.emit('voice_listened', {'id': voice_id, 'listener': user_phone})
    return jsonify({'success': True})

@app.route('/api/voice/delete', methods=['POST'])
def voice_delete():
    data       = request.get_json() or {}
    voice_id   = data.get('id')
    user_phone = data.get('user_phone', '').strip()
    if not voice_id or not user_phone:
        return jsonify({'success': False}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT file_path,sender FROM voice_messages WHERE id=?", (voice_id,))
        row = c.fetchone()
        if not row:
            return jsonify({'success': False, 'error': 'Not found'}), 404
        if row[1] != user_phone:
            return jsonify({'success': False, 'error': 'Forbidden'}), 403
        try:
            os.remove(row[0])
        except OSError:
            pass
        c.execute("DELETE FROM voice_messages WHERE id=?", (voice_id,))
        conn.commit()
    finally:
        return_db_connection(conn)
    return jsonify({'success': True})

@app.route('/api/presence/<phone>')
def api_presence(phone):
    if _user_online(phone):
        return jsonify({'phone': phone, 'status': 'online', 'last_online': None})
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT last_online FROM users WHERE phone=?", (phone,))
        row = c.fetchone()
        last_online = row[0] if row else None
    finally:
        return_db_connection(conn)
    return jsonify({'phone': phone, 'status': 'offline', 'last_online': last_online})

# ─────────────────────────────────────────────────────────────────────────────

# ----------------- Security Information -----------------
@app.route("/security")
def security_info():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Exomnia Security</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            h1 { color: #0E4950; }
            .feature { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 8px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Exomnia Security Features</h1>

            <div class="feature">
                <h3>End-to-End Encryption</h3>
                <p>All messages are encrypted with AES-256-GCM before being stored or transmitted.</p>
            </div>

            <div class="feature">
                <h3>Secure Key Derivation</h3>
                <p>Unique encryption keys are derived for each user using PBKDF2 with 100,000 iterations.</p>
            </div>

            <div class="feature">
                <h3>Forward Secrecy</h3>
                <p>Each conversation uses a unique key combination from both participants.</p>
            </div>

            <div class="feature">
                <h3>Message Integrity</h3>
                <p>AES-GCM provides authentication ensuring messages cannot be tampered with.</p>
            </div>

            <div class="feature">
                <h3>Message Reactions</h3>
                <p>React to messages with emojis that are synced across all users in real-time.</p>
            </div>

            <div class="feature">
                <h3>File Sharing</h3>
                <p>Securely share images, videos, and documents with end-to-end encryption.</p>
            </div>

            <div class="feature">
                <h3>Enhanced Performance</h3>
                <p>Connection pooling, caching, and infinite scroll for optimal user experience.</p>
            </div>
        </div>
    </body>
    </html>
    """

# Initialize DB when loaded by gunicorn
with app.app_context():
    init_db()
    _opt_conn = get_db_connection()
    try:
        _opt_conn.execute("PRAGMA optimize")
        _opt_conn.commit()
    finally:
        return_db_connection(_opt_conn)

# ----------------- Server Run -----------------
if __name__=="__main__":
    print("Exomnia Super App on http://0.0.0.0:5000")
    print("Main App: http://0.0.0.0:5000/main")
    print("Chat Login: http://0.0.0.0:5000/")
    print("Security Info: http://0.0.0.0:5000/security")
    print("All systems integrated")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
 
