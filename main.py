import asyncio
import json
import re
import uuid
import time
import secrets
import base64
import mimetypes
from collections import defaultdict
from typing import Optional, Dict, List
from datetime import datetime, timezone, timedelta

import uvicorn

# nodriver for undetectable browser automation (replaces Camoufox)
try:
    import nodriver
    HAS_NODRIVER = True
except ImportError:
    HAS_NODRIVER = False
    print("=" * 60)
    print("❌ ERROR: nodriver not installed!")
    print("")
    print("   PROBLEM: nodriver is required for reCAPTCHA bypassing.")
    print("")
    print("   SOLUTION:")
    print("   1. Run: pip install nodriver")
    print("   2. Restart LMArenaBridge")
    print("=" * 60)

from fastapi import FastAPI, HTTPException, Depends, status, Form, Request, Response, Header, BackgroundTasks
from starlette.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.security import APIKeyHeader

import httpx

# In-memory storage for async media generation jobs
media_jobs = {}


# curl_cffi for TLS fingerprint mimicking (bypasses Cloudflare JA3 detection)
try:
    from curl_cffi.requests import AsyncSession as CurlAsyncSession
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False
    CurlAsyncSession = None
    print("⚠️  curl_cffi not installed. Install with: pip install curl_cffi")
    print("   (Falling back to httpx - may trigger bot detection)")


# ============================================================
# CONFIGURATION
# ============================================================
# Set to True for detailed logging, False for minimal logging
DEBUG = True

# Port to run the server on
import os
PORT = int(os.environ.get("PORT", 7860))
HEADLESS = os.environ.get("HEADLESS", "false").lower() == "true"

# HTTP Status Codes
class HTTPStatus:
    # 1xx Informational
    CONTINUE = 100
    SWITCHING_PROTOCOLS = 101
    PROCESSING = 102
    EARLY_HINTS = 103
    
    # 2xx Success
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NON_AUTHORITATIVE_INFORMATION = 203
    NO_CONTENT = 204
    RESET_CONTENT = 205
    PARTIAL_CONTENT = 206
    MULTI_STATUS = 207
    
    # 3xx Redirection
    MULTIPLE_CHOICES = 300
    MOVED_PERMANENTLY = 301
    MOVED_TEMPORARILY = 302
    SEE_OTHER = 303
    NOT_MODIFIED = 304
    USE_PROXY = 305
    TEMPORARY_REDIRECT = 307
    PERMANENT_REDIRECT = 308
    
    # 4xx Client Errors
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    PAYMENT_REQUIRED = 402
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    NOT_ACCEPTABLE = 406
    PROXY_AUTHENTICATION_REQUIRED = 407
    REQUEST_TIMEOUT = 408
    CONFLICT = 409
    GONE = 410
    LENGTH_REQUIRED = 411
    PRECONDITION_FAILED = 412
    REQUEST_TOO_LONG = 413
    REQUEST_URI_TOO_LONG = 414
    UNSUPPORTED_MEDIA_TYPE = 415
    REQUESTED_RANGE_NOT_SATISFIABLE = 416
    EXPECTATION_FAILED = 417
    IM_A_TEAPOT = 418
    INSUFFICIENT_SPACE_ON_RESOURCE = 419
    METHOD_FAILURE = 420
    MISDIRECTED_REQUEST = 421
    UNPROCESSABLE_ENTITY = 422
    LOCKED = 423
    FAILED_DEPENDENCY = 424
    UPGRADE_REQUIRED = 426
    PRECONDITION_REQUIRED = 428
    TOO_MANY_REQUESTS = 429
    REQUEST_HEADER_FIELDS_TOO_LARGE = 431
    UNAVAILABLE_FOR_LEGAL_REASONS = 451
    
    # 5xx Server Errors
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504
    HTTP_VERSION_NOT_SUPPORTED = 505
    INSUFFICIENT_STORAGE = 507
    NETWORK_AUTHENTICATION_REQUIRED = 511

# Status code descriptions for logging
STATUS_MESSAGES = {
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",
    103: "Early Hints",
    200: "OK - Success",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    207: "Multi-Status",
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Moved Temporarily",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request - Invalid request syntax",
    401: "Unauthorized - Invalid or expired token",
    402: "Payment Required",
    403: "Forbidden - Access denied",
    404: "Not Found - Resource doesn't exist",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone - Resource permanently deleted",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Request Too Long - Payload too large",
    414: "Request URI Too Long",
    415: "Unsupported Media Type",
    416: "Requested Range Not Satisfiable",
    417: "Expectation Failed",
    418: "I'm a Teapot",
    419: "Insufficient Space on Resource",
    420: "Method Failure",
    421: "Misdirected Request",
    422: "Unprocessable Entity",
    423: "Locked",
    424: "Failed Dependency",
    426: "Upgrade Required",
    428: "Precondition Required",
    429: "Too Many Requests - Rate limit exceeded",
    431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    507: "Insufficient Storage",
    511: "Network Authentication Required"
}

def get_status_emoji(status_code: int) -> str:
    """Get emoji for status code"""
    if 200 <= status_code < 300:
        return "✅"
    elif 300 <= status_code < 400:
        return "↪️"
    elif 400 <= status_code < 500:
        if status_code == 401:
            return "🔒"
        elif status_code == 403:
            return "🚫"
        elif status_code == 404:
            return "❓"
        elif status_code == 429:
            return "⏱️"
        return "⚠️"
    elif 500 <= status_code < 600:
        return "❌"
    return "ℹ️"

def log_http_status(status_code: int, context: str = ""):
    """Log HTTP status with readable message"""
    emoji = get_status_emoji(status_code)
    message = STATUS_MESSAGES.get(status_code, f"Unknown Status {status_code}")
    if context:
        debug_print(f"{emoji} HTTP {status_code}: {message} ({context})")
    else:
        debug_print(f"{emoji} HTTP {status_code}: {message}")
# ============================================================

def debug_print(*args, **kwargs):
    """Print debug messages only if DEBUG is True"""
    if DEBUG:
        print(*args, **kwargs)

# --- New reCAPTCHA Functions ---

# Updated constants from gpt4free/g4f/Provider/needs_auth/LMArena.py
RECAPTCHA_SITEKEY = "6Led_uYrAAAAAKjxDIF58fgFtX3t8loNAK85bW9I"
RECAPTCHA_ACTION = "chat_submit"

async def initialize_nodriver_browser():
    """
    Opens a visible Chrome browser and navigates to LMArena.
    User must solve CAPTCHA manually. Browser stays open for session duration.
    """
    global NODRIVER_BROWSER, NODRIVER_TAB, BROWSER_READY
    
    if not HAS_NODRIVER:
        print("=" * 60)
        print("❌ ERROR: Chrome browser not found!")
        print("")
        print("   PROBLEM: nodriver requires Google Chrome to be installed.")
        print("")
        print("   SOLUTION:")
        print("   1. Download Chrome from: https://www.google.com/chrome/")
        print("   2. Install Chrome")
        print("   3. Restart LMArenaBridge")
        print("=" * 60)
        return False
    
    if BROWSER_READY and NODRIVER_TAB is not None:
        debug_print("   └── Browser already initialized, reusing session")
        return True
    
    print("")
    print("🌐 STEP 1/3: Launching Chrome browser...")
    print("   ├── Looking for Chrome installation...")
    
    # Create chrome profile directory path (for persistent login)
    import os
    chrome_profile_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "chrome_profile")
    
    try:
        # Start nodriver with visible browser and PERSISTENT profile
        NODRIVER_BROWSER = await nodriver.start(
            headless=HEADLESS,  # Toggleable via environment variable
            user_data_dir=chrome_profile_dir,  # 💾 Saves login across restarts!
            browser_args=[
                '--disable-blink-features=AutomationControlled',
                '--no-first-run',
                '--no-default-browser-check',
                '--no-sandbox',
                '--disable-dev-shm-usage',
            ]
        )
        print("   ├── ✅ Chrome launched successfully")
        print(f"   ├── 💾 Using persistent profile: {chrome_profile_dir}")
        print("   └── 🔄 Navigating to lmarena.ai...")
        
        # Navigate to LMArena
        NODRIVER_TAB = await NODRIVER_BROWSER.get("https://arena.ai/?mode=direct")
        
        # Capture User-Agent from the actual browser
        global USER_AGENT
        try:
            ua = await NODRIVER_TAB.evaluate("navigator.userAgent")
            if ua:
                USER_AGENT = ua
                debug_print(f"🕵️  Captured User-Agent: {USER_AGENT[:50]}...")
        except Exception as e:
            debug_print(f"⚠️  Failed to captures User-Agent: {e}")
            
        # Wait for page to settle
        await asyncio.sleep(3)
        
        print("")
        print("⏳ STEP 2/3: Waiting for CAPTCHA verification...")
        print("   ┌────────────────────────────────────────────────────────┐")
        print("   │  👆 ACTION REQUIRED: Please click the reCAPTCHA        │")
        print("   │     checkbox in the Chrome window that just opened!    │")
        print("   │                                                        │")
        print("   │  ⏱️  Timeout in 120 seconds...                         │")
        print("   └────────────────────────────────────────────────────────┘")
        
        # Wait for reCAPTCHA library to load and get first token
        captcha_solved = await wait_for_recaptcha_ready(timeout=120)
        
        if captcha_solved:
            print("")
            print("✅ STEP 2/3: CAPTCHA verified successfully!")
            BROWSER_READY = True
            return True
        else:
            print("")
            print("❌ ERROR: CAPTCHA verification timed out (120 seconds)")
            print("")
            print("   PROBLEM: You didn't click the reCAPTCHA checkbox in time.")
            print("")
            print("   SOLUTION:")
            print("   1. Restart the server: python src/main.py")
            print("   2. When Chrome opens, quickly click the \"I'm not a robot\" checkbox")
            print("   3. You have 2 minutes to complete this")
            return False
            
    except Exception as e:
        print(f"❌ ERROR: Failed to launch Chrome browser!")
        print(f"   └── Details: {e}")
        print("")
        print("   POSSIBLE CAUSES:")
        print("   1. Chrome not installed → Install from google.com/chrome")
        print("   2. Chrome in use by another process → Close other Chrome windows")
        print("   3. Permission issue → Run as administrator")
        return False


async def wait_for_recaptcha_ready(timeout: int = 120) -> bool:
    """
    Wait for user to complete CAPTCHA verification.
    Returns True when reCAPTCHA library is loaded and we can get tokens.
    """
    global NODRIVER_TAB, RECAPTCHA_TOKEN, RECAPTCHA_EXPIRY
    
    start_time = time.time()
    last_status_time = 0
    
    while time.time() - start_time < timeout:
        elapsed = int(time.time() - start_time)
        
        # Print status every 10 seconds
        if elapsed > 0 and elapsed % 10 == 0 and elapsed != last_status_time:
            last_status_time = elapsed
            remaining = timeout - elapsed
            print(f"⏳ Waiting for CAPTCHA... ({elapsed}s elapsed, {remaining}s remaining)")
        
        try:
            # Check if grecaptcha enterprise is available
            lib_ready = await NODRIVER_TAB.evaluate(
                "!!(window.grecaptcha && window.grecaptcha.enterprise)"
            )
            
            if lib_ready:
                # Try to get a token
                debug_print("   └── reCAPTCHA library detected, requesting token...")
                token = await get_recaptcha_token_from_browser()
                
                if token:
                    RECAPTCHA_TOKEN = token
                    RECAPTCHA_EXPIRY = datetime.now(timezone.utc) + timedelta(seconds=110)
                    print(f"   └── reCAPTCHA token acquired ({len(token)} chars)")
                    return True
                    
        except Exception as e:
            debug_print(f"   └── Check failed (normal during load): {e}")
        
        await asyncio.sleep(2)
    
    return False


async def get_recaptcha_token_from_browser() -> Optional[str]:
    """
    Gets a reCAPTCHA token from the persistent browser session.
    Uses a side-channel approach: sets global variable, triggers execute, polls for result.
    """
    global NODRIVER_TAB
    
    if NODRIVER_TAB is None:
        debug_print("❌ Browser tab not available")
        return None
    
    try:
        # Step 1: Initialize the global variable
        await NODRIVER_TAB.evaluate("window.__recaptcha_token = 'PENDING';")
        
        # Step 2: Trigger the reCAPTCHA execution (don't await the Promise)
        trigger_script = f"""
            (function() {{
                try {{
                    window.grecaptcha.enterprise.execute('{RECAPTCHA_SITEKEY}', {{ action: '{RECAPTCHA_ACTION}' }})
                    .then(function(token) {{
                        window.__recaptcha_token = token;
                    }})
                    .catch(function(err) {{
                        window.__recaptcha_token = 'ERROR: ' + err.toString();
                    }});
                }} catch (e) {{
                    window.__recaptcha_token = 'SYNC_ERROR: ' + e.toString();
                }}
            }})();
        """
        await NODRIVER_TAB.evaluate(trigger_script)
        
        # Step 3: Poll for the result
        for i in range(15):  # Max 15 seconds
            await asyncio.sleep(1)
            result = await NODRIVER_TAB.evaluate("window.__recaptcha_token")
            
            if result and result != 'PENDING':
                if isinstance(result, str) and result.startswith('ERROR'):
                    debug_print(f"   └── JS Error: {result}")
                    return None
                elif isinstance(result, str) and result.startswith('SYNC_ERROR'):
                    debug_print(f"   └── Sync Error: {result}")
                    return None
                elif isinstance(result, str) and len(result) > 100:
                    # Valid token!
                    return result
                else:
                    debug_print(f"   └── Unexpected result: {result}")
                    return None
        
        debug_print("   └── Token polling timed out")
        return None
            
    except Exception as e:
        debug_print(f"   └── Token request failed: {e}")
        return None


async def get_recaptcha_v3_token() -> Optional[str]:
    """
    Gets reCAPTCHA v3 token using the persistent nodriver browser session.
    If browser not initialized, returns None.
    """
    global RECAPTCHA_TOKEN, RECAPTCHA_EXPIRY, BROWSER_READY
    
    if not BROWSER_READY or NODRIVER_TAB is None:
        debug_print("❌ Browser not ready. Token refresh unavailable.")
        print("")
        print("❌ ERROR: Browser connection lost!")
        print("")
        print("   PROBLEM: The Chrome window was closed or crashed.")
        print("")
        print("   SOLUTION:")
        print("   1. Restart the server: python src/main.py")
        print("   2. When Chrome opens, click the CAPTCHA")
        print("   3. DO NOT close the Chrome window while using the bridge")
        return None
    
    current_time = datetime.now(timezone.utc).strftime("%H:%M:%S")
    debug_print(f"🔄 [{current_time}] Token refresh triggered")
    debug_print("   ├── Requesting new reCAPTCHA token...")
    
    token = await get_recaptcha_token_from_browser()
    
    if token:
        RECAPTCHA_TOKEN = token
        RECAPTCHA_EXPIRY = datetime.now(timezone.utc) + timedelta(seconds=110)
        next_refresh = (datetime.now(timezone.utc) + timedelta(seconds=100)).strftime("%H:%M:%S")
        debug_print(f"   ├── ✅ New token acquired ({len(token)} chars)")
        debug_print(f"   └── Next refresh at: {next_refresh}")
        return token
    else:
        debug_print("   └── ❌ Failed to get token")
        return None


async def refresh_recaptcha_token() -> Optional[str]:
    """
    Gets a FRESH reCAPTCHA token for each request.
    
    IMPORTANT: reCAPTCHA tokens are SINGLE-USE per Google docs.
    Once a token is verified by the server, it becomes immediately invalid.
    We MUST get a fresh token for every LMArena API request.
    """
    global RECAPTCHA_TOKEN, RECAPTCHA_EXPIRY
    
    current_time = datetime.now(timezone.utc)
    time_str = current_time.strftime("%H:%M:%S")
    
    debug_print(f"🔄 [{time_str}] Getting fresh reCAPTCHA token (tokens are single-use)...")
    
    # ALWAYS get a fresh token - tokens are single-use!
    for attempt in range(1, 4):
        new_token = await get_recaptcha_v3_token()
        
        if new_token:
            RECAPTCHA_TOKEN = new_token
            RECAPTCHA_EXPIRY = current_time + timedelta(seconds=110)
            debug_print(f"✅ [{time_str}] Fresh token acquired ({len(new_token)} chars)")
            return new_token
        
        if attempt < 3:
            wait_time = attempt * 2  # Shorter waits: 2s, 4s
            debug_print(f"⚠️ Token fetch failed (attempt {attempt}/3), retrying in {wait_time}s...")
            await asyncio.sleep(wait_time)
    
    # All attempts failed
    print("")
    print("❌ ERROR: Token refresh failed after 3 attempts!")
    print("")
    print("   PROBLEM: Cannot acquire new reCAPTCHA token.")
    print("")
    print("   SOLUTION:")
    print("   1. Check the Chrome window - you may need to solve CAPTCHA again")
    print("   2. If Chrome is unresponsive, restart the server")
    
    return None

# --- End New reCAPTCHA Functions ---

# Custom UUIDv7 implementation (using correct Unix epoch)
def uuid7():
    """
    Generate a UUIDv7 using Unix epoch (milliseconds since 1970-01-01)
    matching the browser's implementation.
    """
    timestamp_ms = int(time.time() * 1000)
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)
    
    uuid_int = timestamp_ms << 80
    uuid_int |= (0x7000 | rand_a) << 64
    uuid_int |= (0x8000000000000000 | rand_b)
    
    hex_str = f"{uuid_int:032x}"
    return f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"

# Image upload helper functions
async def upload_image_to_lmarena(image_data: bytes, mime_type: str, filename: str) -> Optional[tuple]:
    """
    Upload an image to LMArena R2 storage and return the key and download URL.
    
    Args:
        image_data: Binary image data
        mime_type: MIME type of the image (e.g., 'image/png')
        filename: Original filename for the image
    
    Returns:
        Tuple of (key, download_url) if successful, or None if upload fails
    """
    try:
        # Validate inputs
        if not image_data:
            debug_print("❌ Image data is empty")
            return None
        
        if not mime_type or not mime_type.startswith('image/'):
            debug_print(f"❌ Invalid MIME type: {mime_type}")
            return None
        
        # Step 1: Request upload URL
        debug_print(f"📤 Step 1: Requesting upload URL for {filename}")
        
        # Get Next-Action IDs from config
        config = get_config()
        upload_action_id = config.get("next_action_upload")
        signed_url_action_id = config.get("next_action_signed_url")
        
        if not upload_action_id or not signed_url_action_id:
            debug_print("❌ Next-Action IDs not found in config. Please refresh tokens from dashboard.")
            return None
        
        # Prepare headers for Next.js Server Action
        request_headers = get_request_headers()
        request_headers.update({
            "Accept": "text/x-component",
            "Content-Type": "text/plain;charset=UTF-8",
            "Next-Action": upload_action_id,
            "Referer": "https://arena.ai/?mode=direct",
        })
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    "https://arena.ai/?mode=direct",
                    headers=request_headers,
                    content=json.dumps([filename, mime_type]),
                    timeout=30.0
                )
                response.raise_for_status()
            except httpx.TimeoutException:
                debug_print("❌ Timeout while requesting upload URL")
                return None
            except httpx.HTTPError as e:
                debug_print(f"❌ HTTP error while requesting upload URL: {e}")
                return None
            
            # Parse response - format: 0:{...}\n1:{...}\n
            try:
                lines = response.text.strip().split('\n')
                upload_data = None
                for line in lines:
                    if line.startswith('1:'):
                        upload_data = json.loads(line[2:])
                        break
                
                if not upload_data or not upload_data.get('success'):
                    debug_print(f"❌ Failed to get upload URL: {response.text[:200]}")
                    return None
                
                upload_url = upload_data['data']['uploadUrl']
                key = upload_data['data']['key']
                debug_print(f"✅ Got upload URL and key: {key}")
            except (json.JSONDecodeError, KeyError, IndexError) as e:
                debug_print(f"❌ Failed to parse upload URL response: {e}")
                return None
            
            # Step 2: Upload image to R2 storage
            debug_print(f"📤 Step 2: Uploading image to R2 storage ({len(image_data)} bytes)")
            try:
                response = await client.put(
                    upload_url,
                    content=image_data,
                    headers={"Content-Type": mime_type},
                    timeout=60.0
                )
                response.raise_for_status()
                debug_print(f"✅ Image uploaded successfully")
            except httpx.TimeoutException:
                debug_print("❌ Timeout while uploading image to R2 storage")
                return None
            except httpx.HTTPError as e:
                debug_print(f"❌ HTTP error while uploading image: {e}")
                return None
            
            # Step 3: Get signed download URL (uses different Next-Action)
            debug_print(f"📤 Step 3: Requesting signed download URL")
            request_headers_step3 = request_headers.copy()
            request_headers_step3["Next-Action"] = signed_url_action_id
            
            try:
                response = await client.post(
                    "https://arena.ai/?mode=direct",
                    headers=request_headers_step3,
                    content=json.dumps([key]),
                    timeout=30.0
                )
                response.raise_for_status()
            except httpx.TimeoutException:
                debug_print("❌ Timeout while requesting download URL")
                return None
            except httpx.HTTPError as e:
                debug_print(f"❌ HTTP error while requesting download URL: {e}")
                return None
            
            # Parse response
            try:
                lines = response.text.strip().split('\n')
                download_data = None
                for line in lines:
                    if line.startswith('1:'):
                        download_data = json.loads(line[2:])
                        break
                
                if not download_data or not download_data.get('success'):
                    debug_print(f"❌ Failed to get download URL: {response.text[:200]}")
                    return None
                
                download_url = download_data['data']['url']
                debug_print(f"✅ Got signed download URL: {download_url[:100]}...")
                return (key, download_url)
            except (json.JSONDecodeError, KeyError, IndexError) as e:
                debug_print(f"❌ Failed to parse download URL response: {e}")
                return None
            
    except Exception as e:
        debug_print(f"❌ Unexpected error uploading image: {type(e).__name__}: {e}")
        return None

async def process_message_content(content, model_capabilities: dict) -> tuple[str, List[dict]]:
    """
    Process message content, handle images if present and model supports them.
    
    Args:
        content: Message content (string or list of content parts)
        model_capabilities: Model's capability dictionary
    
    Returns:
        Tuple of (text_content, experimental_attachments)
    """
    # Check if model supports image input
    supports_images = model_capabilities.get('inputCapabilities', {}).get('image', False)
    
    # If content is a string, return it as-is
    if isinstance(content, str):
        return content, []
    
    # If content is a list (OpenAI format with multiple parts)
    if isinstance(content, list):
        text_parts = []
        attachments = []
        
        for part in content:
            if isinstance(part, dict):
                if part.get('type') == 'text':
                    text_parts.append(part.get('text', ''))
                    
                elif part.get('type') == 'image_url' and supports_images:
                    image_url = part.get('image_url', {})
                    if isinstance(image_url, dict):
                        url = image_url.get('url', '')
                    else:
                        url = image_url
                    
                    # Handle base64-encoded images
                    if url.startswith('data:'):
                        # Format: data:image/png;base64,iVBORw0KGgo...
                        try:
                            # Validate and parse data URI
                            if ',' not in url:
                                debug_print(f"❌ Invalid data URI format (no comma separator)")
                                continue
                            
                            header, data = url.split(',', 1)
                            
                            # Parse MIME type
                            if ';' not in header or ':' not in header:
                                debug_print(f"❌ Invalid data URI header format")
                                continue
                            
                            mime_type = header.split(';')[0].split(':')[1]
                            
                            # Validate MIME type
                            if not mime_type.startswith('image/'):
                                debug_print(f"❌ Invalid MIME type: {mime_type}")
                                continue
                            
                            # Decode base64
                            try:
                                image_data = base64.b64decode(data)
                            except Exception as e:
                                debug_print(f"❌ Failed to decode base64 data: {e}")
                                continue
                            
                            # Validate image size (max 10MB)
                            if len(image_data) > 10 * 1024 * 1024:
                                debug_print(f"❌ Image too large: {len(image_data)} bytes (max 10MB)")
                                continue
                            
                            # Generate filename
                            ext = mimetypes.guess_extension(mime_type) or '.png'
                            filename = f"upload-{uuid.uuid4()}{ext}"
                            
                            debug_print(f"🖼️  Processing base64 image: {filename}, size: {len(image_data)} bytes")
                            
                            # Upload to LMArena
                            upload_result = await upload_image_to_lmarena(image_data, mime_type, filename)
                            
                            if upload_result:
                                key, download_url = upload_result
                                # Add as attachment in LMArena format
                                attachments.append({
                                    "name": key,
                                    "contentType": mime_type,
                                    "url": download_url
                                })
                                debug_print(f"✅ Image uploaded and added to attachments")
                            else:
                                debug_print(f"⚠️  Failed to upload image, skipping")
                        except Exception as e:
                            debug_print(f"❌ Unexpected error processing base64 image: {type(e).__name__}: {e}")
                    
                    # Handle URL images (direct URLs)
                    elif url.startswith('http://') or url.startswith('https://'):
                        # For external URLs, we'd need to download and re-upload
                        # For now, skip this case
                        debug_print(f"⚠️  External image URLs not yet supported: {url[:100]}")
                        
                elif part.get('type') == 'image_url' and not supports_images:
                    debug_print(f"⚠️  Image provided but model doesn't support images")
        
        # Combine text parts
        text_content = '\n'.join(text_parts).strip()
        return text_content, attachments
    
    # Fallback
    return str(content), []

app = FastAPI()

# --- Constants & Global State ---
CONFIG_FILE = "config.json"
MODELS_FILE = "models.json"
API_KEY_HEADER = APIKeyHeader(name="Authorization", auto_error=False)

# In-memory stores
# { "api_key": { "conversation_id": session_data } }
chat_sessions: Dict[str, Dict[str, dict]] = defaultdict(dict)
# { "session_id": "username" }
dashboard_sessions = {}
# { "api_key": [timestamp1, timestamp2, ...] }
api_key_usage = defaultdict(list)
# { "model_id": count }
model_usage_stats = defaultdict(int)
# Token cycling: current index for round-robin selection
current_token_index = 0
# Track which token is assigned to each conversation (conversation_id -> token)
conversation_tokens: Dict[str, str] = {}
# Track failed tokens per request to avoid retrying with same token
request_failed_tokens: Dict[str, set] = {}

# --- New Global State for reCAPTCHA ---
RECAPTCHA_TOKEN: Optional[str] = None
# Initialize expiry far in the past to force a refresh on startup
RECAPTCHA_EXPIRY: datetime = datetime.now(timezone.utc) - timedelta(days=365)

# --- nodriver Browser Instance (persistent session) ---
# These stay alive for the entire server session
NODRIVER_BROWSER = None  # nodriver.Browser instance
NODRIVER_TAB = None      # nodriver.Tab instance (the page)
BROWSER_READY = False    # Flag to indicate browser is ready for token refresh
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" # Default fallback
LMARENA_REQUEST_LOCK = asyncio.Lock()  # Lock to serialize LMArena requests (prevents rate limiting)
LAST_LMARENA_REQUEST_TIME = 0.0  # Timestamp of last LMArena request (for rate limiting)

# --- Webshare Proxy Pool Configuration ---
# Enable/disable proxy rotation (set to True when proxies are configured)
PROXY_ROTATION_ENABLED = False  # Will be auto-enabled when proxies are added

# When True, each request creates a NEW session instead of reusing existing ones
# This bypasses LMArena's per-session rate limiting (they track by session ID, not just IP)
# Recommended: Enable this when using proxy rotation for unlimited parallel requests
FORCE_NEW_SESSION = True  # Always create fresh session (bypasses per-session rate limits)

# Proxy pool - Add your Webshare proxy credentials here
# Format: {"host": "IP", "port": PORT, "username": "user", "password": "pass"}
WEBSHARE_PROXY_POOL = [
    # Account 1 - 10 Proxies (wlnpiril)
    {"host": "142.111.48.253", "port": 7030, "username": "wlnpiril", "password": "rz8y4an5o6n1"},  # US - Los Angeles
    {"host": "23.95.150.145", "port": 6114, "username": "wlnpiril", "password": "rz8y4an5o6n1"},   # US - Buffalo
    {"host": "198.23.239.134", "port": 6540, "username": "wlnpiril", "password": "rz8y4an5o6n1"},  # US - Buffalo
    {"host": "107.172.163.27", "port": 6543, "username": "wlnpiril", "password": "rz8y4an5o6n1"},  # US - Bloomingdale
    {"host": "198.105.121.200", "port": 6462, "username": "wlnpiril", "password": "rz8y4an5o6n1"}, # UK - London
    {"host": "64.137.96.74", "port": 6641, "username": "wlnpiril", "password": "rz8y4an5o6n1"},    # Spain - Madrid
    {"host": "84.247.60.125", "port": 6095, "username": "wlnpiril", "password": "rz8y4an5o6n1"},   # Poland - Warsaw
    {"host": "216.10.27.159", "port": 6837, "username": "wlnpiril", "password": "rz8y4an5o6n1"},   # US - Dallas
    {"host": "23.26.71.145", "port": 5628, "username": "wlnpiril", "password": "rz8y4an5o6n1"},    # US - Orem
    {"host": "23.27.208.120", "port": 5830, "username": "wlnpiril", "password": "rz8y4an5o6n1"},   # US - Reston
    # Account 2 - 10 Proxies (wfpfhvqd)
    {"host": "142.111.48.253", "port": 7030, "username": "wfpfhvqd", "password": "akmgj7n23qgw"},  # US - Los Angeles
    {"host": "23.95.150.145", "port": 6114, "username": "wfpfhvqd", "password": "akmgj7n23qgw"},   # US - Buffalo
    {"host": "198.23.239.134", "port": 6540, "username": "wfpfhvqd", "password": "akmgj7n23qgw"},  # US - Buffalo
    {"host": "107.172.163.27", "port": 6543, "username": "wfpfhvqd", "password": "akmgj7n23qgw"},  # US - Bloomingdale
    {"host": "198.105.121.200", "port": 6462, "username": "wfpfhvqd", "password": "akmgj7n23qgw"}, # UK - London
    {"host": "64.137.96.74", "port": 6641, "username": "wfpfhvqd", "password": "akmgj7n23qgw"},    # Spain - Madrid
    {"host": "84.247.60.125", "port": 6095, "username": "wfpfhvqd", "password": "akmgj7n23qgw"},   # Poland - Warsaw
    {"host": "216.10.27.159", "port": 6837, "username": "wfpfhvqd", "password": "akmgj7n23qgw"},   # US - Dallas
    {"host": "23.26.71.145", "port": 5628, "username": "wfpfhvqd", "password": "akmgj7n23qgw"},    # US - Orem
    {"host": "23.27.208.120", "port": 5830, "username": "wfpfhvqd", "password": "akmgj7n23qgw"},   # US - Reston
    # Account 3 - 10 Proxies (qbwdhdrw)
    {"host": "142.111.48.253", "port": 7030, "username": "qbwdhdrw", "password": "9f9w1szgq7tu"},  # US - Los Angeles
    {"host": "23.95.150.145", "port": 6114, "username": "qbwdhdrw", "password": "9f9w1szgq7tu"},   # US - Buffalo
    {"host": "198.23.239.134", "port": 6540, "username": "qbwdhdrw", "password": "9f9w1szgq7tu"},  # US - Buffalo
    {"host": "107.172.163.27", "port": 6543, "username": "qbwdhdrw", "password": "9f9w1szgq7tu"},  # US - Bloomingdale
    {"host": "198.105.121.200", "port": 6462, "username": "qbwdhdrw", "password": "9f9w1szgq7tu"}, # UK - London
    {"host": "64.137.96.74", "port": 6641, "username": "qbwdhdrw", "password": "9f9w1szgq7tu"},    # Spain - Madrid
    {"host": "84.247.60.125", "port": 6095, "username": "qbwdhdrw", "password": "9f9w1szgq7tu"},   # Poland - Warsaw
    {"host": "216.10.27.159", "port": 6837, "username": "qbwdhdrw", "password": "9f9w1szgq7tu"},   # US - Dallas
    {"host": "23.26.71.145", "port": 5628, "username": "qbwdhdrw", "password": "9f9w1szgq7tu"},    # US - Orem
    {"host": "23.27.208.120", "port": 5830, "username": "qbwdhdrw", "password": "9f9w1szgq7tu"},   # US - Reston
    # Account 4 - 10 Proxies (vwqxqyew)
    {"host": "142.111.48.253", "port": 7030, "username": "vwqxqyew", "password": "4l6qlayr252q"},  # US - Los Angeles
    {"host": "23.95.150.145", "port": 6114, "username": "vwqxqyew", "password": "4l6qlayr252q"},   # US - Buffalo
    {"host": "198.23.239.134", "port": 6540, "username": "vwqxqyew", "password": "4l6qlayr252q"},  # US - Buffalo
    {"host": "107.172.163.27", "port": 6543, "username": "vwqxqyew", "password": "4l6qlayr252q"},  # US - Bloomingdale
    {"host": "198.105.121.200", "port": 6462, "username": "vwqxqyew", "password": "4l6qlayr252q"}, # UK - London
    {"host": "64.137.96.74", "port": 6641, "username": "vwqxqyew", "password": "4l6qlayr252q"},    # Spain - Madrid
    {"host": "84.247.60.125", "port": 6095, "username": "vwqxqyew", "password": "4l6qlayr252q"},   # Poland - Warsaw
    {"host": "216.10.27.159", "port": 6837, "username": "vwqxqyew", "password": "4l6qlayr252q"},   # US - Dallas
    {"host": "23.26.71.145", "port": 5628, "username": "vwqxqyew", "password": "4l6qlayr252q"},    # US - Orem
    {"host": "23.27.208.120", "port": 5830, "username": "vwqxqyew", "password": "4l6qlayr252q"},   # US - Reston
    # Account 5 - 10 Proxies (ynwjxcuz)
    {"host": "142.111.48.253", "port": 7030, "username": "ynwjxcuz", "password": "l90dlksfzyia"},  # US - Los Angeles
    {"host": "23.95.150.145", "port": 6114, "username": "ynwjxcuz", "password": "l90dlksfzyia"},   # US - Buffalo
    {"host": "198.23.239.134", "port": 6540, "username": "ynwjxcuz", "password": "l90dlksfzyia"},  # US - Buffalo
    {"host": "107.172.163.27", "port": 6543, "username": "ynwjxcuz", "password": "l90dlksfzyia"},  # US - Bloomingdale
    {"host": "198.105.121.200", "port": 6462, "username": "ynwjxcuz", "password": "l90dlksfzyia"}, # UK - London
    {"host": "64.137.96.74", "port": 6641, "username": "ynwjxcuz", "password": "l90dlksfzyia"},    # Spain - Madrid
    {"host": "84.247.60.125", "port": 6095, "username": "ynwjxcuz", "password": "l90dlksfzyia"},   # Poland - Warsaw
    {"host": "216.10.27.159", "port": 6837, "username": "ynwjxcuz", "password": "l90dlksfzyia"},   # US - Dallas
    {"host": "23.26.71.145", "port": 5628, "username": "ynwjxcuz", "password": "l90dlksfzyia"},    # US - Orem
    {"host": "23.27.208.120", "port": 5830, "username": "ynwjxcuz", "password": "l90dlksfzyia"},   # US - Reston
]

# Track which proxy to use next (round-robin)
CURRENT_PROXY_INDEX = 0
PROXY_USAGE_STATS = defaultdict(lambda: {"requests": 0, "errors": 0})

def get_next_proxy():
    """Get the next proxy from the pool in round-robin fashion."""
    global CURRENT_PROXY_INDEX
    
    if not WEBSHARE_PROXY_POOL:
        return None
    
    proxy = WEBSHARE_PROXY_POOL[CURRENT_PROXY_INDEX]
    CURRENT_PROXY_INDEX = (CURRENT_PROXY_INDEX + 1) % len(WEBSHARE_PROXY_POOL)
    
    # Track usage
    proxy_id = f"{proxy['host']}:{proxy['port']}"
    PROXY_USAGE_STATS[proxy_id]["requests"] += 1
    
    return proxy

def format_proxy_url(proxy: dict) -> str:
    """Format proxy dict into URL string for httpx/requests."""
    if not proxy:
        return None
    return f"http://{proxy['username']}:{proxy['password']}@{proxy['host']}:{proxy['port']}"

def get_proxy_for_browser() -> dict:
    """Get proxy configuration formatted for browser use."""
    proxy = get_next_proxy()
    if not proxy:
        return None
    return {
        "server": f"http://{proxy['host']}:{proxy['port']}",
        "username": proxy['username'],
        "password": proxy['password']
    }

# Auto-enable proxy rotation if proxies are configured
if WEBSHARE_PROXY_POOL:
    PROXY_ROTATION_ENABLED = True
    print(f"🔄 Proxy rotation ENABLED with {len(WEBSHARE_PROXY_POOL)} proxies")
else:
    print("⚠️  No proxies configured. Using direct connection (rate limits may apply)")
# --------------------------------------

# --- Helper Functions ---

def get_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        debug_print(f"⚠️  Config file error: {e}, using defaults")
        config = {}
    except Exception as e:
        debug_print(f"⚠️  Unexpected error reading config: {e}, using defaults")
        config = {}

    # Ensure default keys exist
    try:
        config.setdefault("password", "admin")
        config.setdefault("auth_token", "")
        config.setdefault("auth_tokens", [])  # Multiple auth tokens
        config.setdefault("cf_clearance", "")
        config.setdefault("api_keys", [])
        config.setdefault("usage_stats", {})
    except Exception as e:
        debug_print(f"⚠️  Error setting config defaults: {e}")
    
    return config

def load_usage_stats():
    """Load usage stats from config into memory"""
    global model_usage_stats
    try:
        config = get_config()
        model_usage_stats = defaultdict(int, config.get("usage_stats", {}))
    except Exception as e:
        debug_print(f"⚠️  Error loading usage stats: {e}, using empty stats")
        model_usage_stats = defaultdict(int)

def save_config(config):
    try:
        # Persist in-memory stats to the config dict before saving
        config["usage_stats"] = dict(model_usage_stats)
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        debug_print(f"❌ Error saving config: {e}")

def get_models():
    try:
        with open(MODELS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_models(models):
    try:
        with open(MODELS_FILE, "w") as f:
            json.dump(models, f, indent=2)
    except Exception as e:
        debug_print(f"❌ Error saving models: {e}")


def get_request_headers():
    """Get request headers with the first available auth token (for compatibility)"""
    config = get_config()
    
    # Try to get token from auth_tokens first, then fallback to single token
    auth_tokens = config.get("auth_tokens", [])
    if auth_tokens:
        token = auth_tokens[0]  # Just use first token for non-API requests
    else:
        token = config.get("auth_token", "").strip()
        if not token:
            raise HTTPException(status_code=500, detail="Arena auth token not set in dashboard.")
    
    return get_request_headers_with_token(token)

def get_request_headers_with_token(token: str):
    """Get request headers with a specific auth token"""
    config = get_config()
    cf_clearance = config.get("cf_clearance", "").strip()
    
    # Check if the token is a full cookie    # Support raw tokens, tokens prefixed with cookie names, and base64 prefixed tokens
    if "arena-auth-prod-v1" in token and "=" in token:
        # User pasted the whole cookie string
        token = token.split("arena-auth-prod-v1")[-1].split("=", 1)[-1].strip()
        # Ensure cf_clearance is updated if present in the string? 
        # Actually, best to just use what user gave, but we might want to ensure cf_clearance is there.
        # If user gave full string, it likely has everything.
        cookie_header = token
    else:
        # Standard behavior: wrap the value
        cookie_header = f"cf_clearance={cf_clearance}; arena-auth-prod-v1={token}"

    return {
        "Content-Type": "text/plain;charset=UTF-8",
        "Cookie": cookie_header,
        "User-Agent": USER_AGENT,
    }

def get_next_auth_token(exclude_tokens: set = None):
    """Get next auth token using round-robin selection
    
    Args:
        exclude_tokens: Set of tokens to exclude from selection (e.g., already tried tokens)
    """
    global current_token_index
    config = get_config()
    
    # Get all available tokens
    auth_tokens = config.get("auth_tokens", [])
    if not auth_tokens:
        raise HTTPException(status_code=500, detail="No auth tokens configured")
    
    # Filter out excluded tokens
    if exclude_tokens:
        available_tokens = [t for t in auth_tokens if t not in exclude_tokens]
        if not available_tokens:
            raise HTTPException(status_code=500, detail="No more auth tokens available to try")
    else:
        available_tokens = auth_tokens
    
    # Round-robin selection from available tokens
    token = available_tokens[current_token_index % len(available_tokens)]
    current_token_index = (current_token_index + 1) % len(auth_tokens)
    return token

def remove_auth_token(token: str):
    """Remove an expired/invalid auth token from the list"""
    try:
        config = get_config()
        auth_tokens = config.get("auth_tokens", [])
        if token in auth_tokens:
            auth_tokens.remove(token)
            config["auth_tokens"] = auth_tokens
            save_config(config)
            debug_print(f"🗑️  Removed expired token from list: {token[:20]}...")
    except Exception as e:
        debug_print(f"⚠️  Error removing auth token: {e}")


async def make_lmarena_request_browser(url: str, payload: dict, method: str = "POST") -> dict:
    """Make LMArena API request through the real Chrome browser (bypasses all bot detection)
    
    This function uses the nodriver browser to execute JavaScript fetch() calls,
    ensuring the request comes from a real browser with proper cookies, TLS fingerprint,
    and session context.
    
    Args:
        url: Full URL to the LMArena API endpoint
        payload: JSON payload to send
        method: HTTP method (POST or PUT)
    
    Returns:
        dict with 'status_code' and 'text' (response body)
    """
    global NODRIVER_TAB, BROWSER_READY, LAST_LMARENA_REQUEST_TIME
    
    if not BROWSER_READY or NODRIVER_TAB is None:
        raise HTTPException(status_code=503, detail="Browser not ready for API calls")
    
    # Only use lock and rate limiting if proxy rotation is DISABLED
    # With rotating proxies, each request uses different IP = no rate limit concerns
    if not PROXY_ROTATION_ENABLED:
        # Acquire lock to serialize requests (parallel requests will queue up here)
        debug_print(f"🔒 Waiting to acquire request lock...")
        await LMARENA_REQUEST_LOCK.acquire()
        debug_print(f"🔓 Lock acquired!")
    else:
        proxy = get_next_proxy()
        proxy_id = f"{proxy['host']}:{proxy['port']}" if proxy else "direct"
        debug_print(f"🔄 Using rotating proxy: {proxy_id} (no lock needed)")
    
    try:
        # Rate limiting: only if proxy rotation is disabled
        if not PROXY_ROTATION_ENABLED:
            MIN_REQUEST_INTERVAL = 2.5
            current_time = time.time()
            if LAST_LMARENA_REQUEST_TIME > 0:
                elapsed = current_time - LAST_LMARENA_REQUEST_TIME
                if elapsed < MIN_REQUEST_INTERVAL:
                    wait_time = MIN_REQUEST_INTERVAL - elapsed
                    debug_print(f"⏳ Rate limiting: waiting {wait_time:.1f}s before next request")
                    await asyncio.sleep(wait_time)
            LAST_LMARENA_REQUEST_TIME = time.time()
    
        # CRITICAL: Refresh reCAPTCHA token AFTER acquiring lock
        # Token may have expired while waiting in queue
        debug_print(f"🔄 Refreshing reCAPTCHA token after lock...")
        fresh_token = await refresh_recaptcha_token()
        if fresh_token and 'recaptchaV3Token' in payload:
            payload['recaptchaV3Token'] = fresh_token
            debug_print(f"✅ Fresh token applied ({len(fresh_token)} chars)")
    
        debug_print(f"🌐 Making browser-based request to: {url}")
        debug_print(f"🔐 Using REAL Chrome browser (bypasses bot detection)")
    
        # Escape the payload for JavaScript
        payload_json = json.dumps(payload).replace('\\', '\\\\').replace("'", "\\'").replace('\n', '\\n')
    
        # Generate unique request ID to avoid collisions
        request_id = f"lmab_{int(time.time() * 1000)}"
    
        # JavaScript code that stores result in window global (since evaluate() can't return async results)
        js_code = f"""
        (function() {{
            window.{request_id} = null;  // Reset
            fetch('{url}', {{
                method: '{method}',
                headers: {{
                    'Content-Type': 'application/json'
                }},
                body: '{payload_json}',
                credentials: 'include'
            }})
            .then(async (response) => {{
                const text = await response.text();
                window.{request_id} = {{
                    status_code: response.status,
                    text: text,
                    ok: response.ok,
                    done: true
                }};
            }})
            .catch((error) => {{
                window.{request_id} = {{
                    status_code: 0,
                    text: 'Fetch error: ' + error.message,
                    ok: false,
                    done: true
                }};
            }});
            return 'request_started';
        }})();
        """
    
        # Start the fetch request
        start_result = await NODRIVER_TAB.evaluate(js_code)
        debug_print(f"🚀 Browser fetch started: {start_result}")
        
        # Poll for result (timeout after 120 seconds)
        max_wait = 120
        poll_interval = 0.5
        waited = 0
        
        while waited < max_wait:
            await asyncio.sleep(poll_interval)
            waited += poll_interval
            
            # Check if result is ready
            result = await NODRIVER_TAB.evaluate(f"window.{request_id}")
            
            # Debug: log result type
            if result is not None:
                debug_print(f"🔍 Result type: {type(result).__name__}, value: {str(result)[:100]}")
            
            # Handle different return types from nodriver
            if result is not None:
                # nodriver returns JS objects as list of [key, {type, value}] pairs
                # e.g. [['status_code', {'type': 'number', 'value': 200}], ['text', {...}], ...]
                if isinstance(result, list) and len(result) > 0:
                    # Check if it's the nodriver format: list of 2-element lists
                    if isinstance(result[0], list) and len(result[0]) == 2:
                        # Convert nodriver format to dict
                        converted = {}
                        for item in result:
                            if isinstance(item, list) and len(item) == 2:
                                key = item[0]
                                value_wrapper = item[1]
                                if isinstance(value_wrapper, dict) and 'value' in value_wrapper:
                                    converted[key] = value_wrapper['value']
                                else:
                                    converted[key] = value_wrapper
                        result = converted
                        debug_print(f"✅ Converted nodriver format to dict: {list(result.keys())}")
                        debug_print(f"   done={result.get('done')}, status={result.get('status_code')}")
                    # If first element is a dict, take it (old handling)
                    elif isinstance(result[0], dict):
                        result = result[0]
                
                # Now check if it's a dict with 'done' key
                if isinstance(result, dict) and result.get("done"):
                    debug_print(f"🌐 Browser response status: {result.get('status_code', 'unknown')}")
                    
                    # Log first 200 chars of response for debugging
                    response_preview = str(result.get('text', ''))[:200]
                    debug_print(f"📄 Response preview: {response_preview}...")
                    
                    # Clean up window variable
                    await NODRIVER_TAB.evaluate(f"delete window.{request_id}")
                    
                    return {
                        "status_code": result.get("status_code", 500),
                        "text": result.get("text", ""),
                        "ok": result.get("ok", False)
                    }
            
            if waited % 5 == 0:
                debug_print(f"⏳ Waiting for browser response... ({int(waited)}s)")
        
        # Timeout
        debug_print(f"❌ Browser fetch timed out after {max_wait}s")
        await NODRIVER_TAB.evaluate(f"delete window.{request_id}")
        return {"status_code": 504, "text": "Browser request timed out"}
        
    except Exception as e:
        debug_print(f"❌ Browser request failed: {type(e).__name__}: {e}")
        return {"status_code": 500, "text": f"Browser error: {str(e)}"}
    finally:
        # Only release lock if we acquired it (proxy rotation disabled)
        if not PROXY_ROTATION_ENABLED:
            LMARENA_REQUEST_LOCK.release()
            debug_print(f"🔓 Request lock released")


async def make_lmarena_streaming_request_browser(url: str, payload: dict, method: str = "POST"):
    """Stream LMArena API response through the real Chrome browser (bypasses reCAPTCHA).
    
    This is an async generator that yields response chunks as they arrive.
    Uses browser's ReadableStream API to capture streaming data.
    
    Args:
        url: Full URL to the LMArena API endpoint
        payload: JSON payload to send
        method: HTTP method (POST or PUT)
    
    Yields:
        str: Each chunk of the streaming response as it arrives
    """
    global NODRIVER_TAB, BROWSER_READY, LAST_LMARENA_REQUEST_TIME
    
    if not BROWSER_READY or NODRIVER_TAB is None:
        raise HTTPException(status_code=503, detail="Browser not ready for API calls")
    
    # Only use lock and rate limiting if proxy rotation is DISABLED
    if not PROXY_ROTATION_ENABLED:
        # Acquire lock to serialize requests (parallel requests will queue up here)
        debug_print(f"🔒 [STREAM] Waiting to acquire request lock...")
        await LMARENA_REQUEST_LOCK.acquire()
        debug_print(f"🔓 [STREAM] Lock acquired!")
    else:
        proxy = get_next_proxy()
        proxy_id = f"{proxy['host']}:{proxy['port']}" if proxy else "direct"
        debug_print(f"🔄 [STREAM] Using rotating proxy: {proxy_id} (no lock needed)")
    
    # Rate limiting: only if proxy rotation is disabled
    if not PROXY_ROTATION_ENABLED:
        MIN_REQUEST_INTERVAL = 2.5
        current_time = time.time()
        if LAST_LMARENA_REQUEST_TIME > 0:
            elapsed = current_time - LAST_LMARENA_REQUEST_TIME
            if elapsed < MIN_REQUEST_INTERVAL:
                wait_time = MIN_REQUEST_INTERVAL - elapsed
                debug_print(f"⏳ Rate limiting: waiting {wait_time:.1f}s before next streaming request")
                await asyncio.sleep(wait_time)
        LAST_LMARENA_REQUEST_TIME = time.time()
    
    # CRITICAL: Refresh reCAPTCHA token AFTER acquiring lock
    # Token may have expired while waiting in queue
    debug_print(f"🔄 [STREAM] Refreshing reCAPTCHA token after lock...")
    fresh_token = await refresh_recaptcha_token()
    if fresh_token and 'recaptchaV3Token' in payload:
        payload['recaptchaV3Token'] = fresh_token
        debug_print(f"✅ [STREAM] Fresh token applied ({len(fresh_token)} chars)")
    
    debug_print(f"🌐 Making STREAMING browser request to: {url}")
    debug_print(f"🔐 Using REAL Chrome browser for streaming (bypasses reCAPTCHA)")
    
    # Escape the payload for JavaScript
    payload_json = json.dumps(payload).replace('\\', '\\\\').replace("'", "\\'").replace('\n', '\\n')
    
    # Generate unique request ID
    request_id = f"lmab_stream_{int(time.time() * 1000)}"
    
    # JavaScript that uses ReadableStream to collect chunks
    # Stores chunks in an array that Python can poll
    js_code = f"""
    (function() {{
        window.{request_id} = {{
            chunks: [],
            done: false,
            error: null,
            status_code: 0
        }};
        
        fetch('{url}', {{
            method: '{method}',
            headers: {{
                'Content-Type': 'application/json'
            }},
            body: '{payload_json}',
            credentials: 'include'
        }})
        .then(async (response) => {{
            window.{request_id}.status_code = response.status;
            
            if (!response.ok) {{
                const text = await response.text();
                window.{request_id}.error = text;
                window.{request_id}.done = true;
                return;
            }}
            
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            
            while (true) {{
                const {{done, value}} = await reader.read();
                if (done) {{
                    window.{request_id}.done = true;
                    break;
                }}
                const chunk = decoder.decode(value, {{stream: true}});
                window.{request_id}.chunks.push(chunk);
            }}
        }})
        .catch((error) => {{
            window.{request_id}.error = 'Fetch error: ' + error.message;
            window.{request_id}.done = true;
        }});
        return 'streaming_started';
    }})();
    """
    
    try:
        # Start the streaming fetch
        start_result = await NODRIVER_TAB.evaluate(js_code)
        debug_print(f"🚀 Browser streaming started: {start_result}")
        
        # Poll for chunks and yield them as they arrive
        max_wait = 120
        poll_interval = 0.1  # Poll faster for streaming
        waited = 0
        last_chunk_index = 0
        
        while waited < max_wait:
            await asyncio.sleep(poll_interval)
            waited += poll_interval
            
            # Get current state
            state_js = f"""
            (function() {{
                const s = window.{request_id};
                if (!s) return null;
                return {{
                    chunk_count: s.chunks.length,
                    done: s.done,
                    error: s.error,
                    status_code: s.status_code
                }};
            }})();
            """
            state = await NODRIVER_TAB.evaluate(state_js)
            
            if state is None:
                continue
            
            # Handle nodriver list format conversion
            if isinstance(state, list):
                converted = {}
                for item in state:
                    if isinstance(item, list) and len(item) == 2:
                        key = item[0]
                        value_wrapper = item[1]
                        if isinstance(value_wrapper, dict) and 'value' in value_wrapper:
                            converted[key] = value_wrapper['value']
                        else:
                            converted[key] = value_wrapper
                state = converted
            
            if not isinstance(state, dict):
                continue
            
            chunk_count = state.get('chunk_count', 0)
            done = state.get('done', False)
            error = state.get('error')
            status_code = state.get('status_code', 0)
            
            # Check for error (nodriver returns {'type': 'null'} for JS null, which is truthy)
            # Only treat as error if it's an actual error string
            is_real_error = error and isinstance(error, str) and error != ""
            if is_real_error:
                debug_print(f"❌ Stream error: {error}")
                await NODRIVER_TAB.evaluate(f"delete window.{request_id}")
                raise HTTPException(status_code=status_code or 500, detail=f"Browser stream error: {error}")
            
            # Get new chunks if available
            if chunk_count > last_chunk_index:
                # Get all new chunks
                get_chunks_js = f"""
                (function() {{
                    const s = window.{request_id};
                    if (!s) return [];
                    return s.chunks.slice({last_chunk_index});
                }})();
                """
                new_chunks = await NODRIVER_TAB.evaluate(get_chunks_js)
                
                # Handle nodriver format for chunk array
                if isinstance(new_chunks, list):
                    for chunk_item in new_chunks:
                        # Extract chunk text
                        if isinstance(chunk_item, dict) and 'value' in chunk_item:
                            chunk_text = chunk_item['value']
                        elif isinstance(chunk_item, str):
                            chunk_text = chunk_item
                        else:
                            chunk_text = str(chunk_item) if chunk_item else ""
                        
                        if chunk_text:
                            yield chunk_text
                
                last_chunk_index = chunk_count
            
            # Check if done
            if done:
                debug_print(f"✅ Browser streaming completed. Status: {status_code}, Total chunks: {chunk_count}")
                break
            
            # Periodic status log
            if waited % 10 == 0 and waited > 0:
                debug_print(f"⏳ Streaming... ({int(waited)}s, {chunk_count} chunks)")
        
        # Clean up
        await NODRIVER_TAB.evaluate(f"delete window.{request_id}")
        
        if waited >= max_wait:
            debug_print(f"❌ Browser streaming timed out after {max_wait}s")
            raise HTTPException(status_code=504, detail="Browser streaming timed out")
            
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"❌ Browser streaming failed: {type(e).__name__}: {e}")
        try:
            await NODRIVER_TAB.evaluate(f"delete window.{request_id}")
        except:
            pass
        raise HTTPException(status_code=500, detail=f"Browser streaming error: {str(e)}")
    finally:
        # Only release lock if we acquired it (proxy rotation disabled)
        if not PROXY_ROTATION_ENABLED:
            LMARENA_REQUEST_LOCK.release()
            debug_print(f"🔓 [STREAM] Request lock released")


# --- Dashboard Authentication ---

async def get_current_session(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id and session_id in dashboard_sessions:
        return dashboard_sessions[session_id]
    return None

# --- API Key Authentication & Rate Limiting ---

async def rate_limit_api_key(
    auth_header: Optional[str] = Depends(API_KEY_HEADER),
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
):
    api_key_str = None
    
    # Check Authorization header (Bearer token)
    debug_print(f"🔑 Auth Debug: AuthHeader set? {auth_header is not None}, X-API-Key set? {x_api_key is not None}")
    
    if auth_header and auth_header.startswith("Bearer "):
        api_key_str = auth_header[7:].strip()
    
    # Check x-api-key header (Anthropic standard)
    if not api_key_str and x_api_key:
        api_key_str = x_api_key.strip()
        
    if not api_key_str:
        raise HTTPException(
            status_code=401, 
            detail="Missing or invalid authentication. Expected 'Authorization: Bearer KEY' or 'x-api-key: KEY'"
        )
    config = get_config()
    
    key_data = next((k for k in config["api_keys"] if k["key"] == api_key_str), None)
    if not key_data:
        raise HTTPException(status_code=401, detail="Invalid API Key.")

    # Rate Limiting
    rate_limit = key_data.get("rpm", 60)
    current_time = time.time()
    
    # Clean up old timestamps (older than 60 seconds)
    api_key_usage[api_key_str] = [t for t in api_key_usage[api_key_str] if current_time - t < 60]

    if len(api_key_usage[api_key_str]) >= rate_limit:
        # Calculate seconds until oldest request expires (60 seconds window)
        oldest_timestamp = min(api_key_usage[api_key_str])
        retry_after = int(60 - (current_time - oldest_timestamp))
        retry_after = max(1, retry_after)  # At least 1 second
        
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please try again later.",
            headers={"Retry-After": str(retry_after)}
        )
        
    api_key_usage[api_key_str].append(current_time)
    
    return key_data

# --- Core Logic ---

async def get_initial_data():
    """
    Extracts initial data from the nodriver browser session.
    Must be called AFTER initialize_nodriver_browser().
    Extracts: cf_clearance cookie, models list.
    """
    global NODRIVER_TAB
    
    print("")
    print("📦 STEP 3/3: Loading LMArena data...")
    
    if NODRIVER_TAB is None:
        print("   └── ❌ Browser not available, skipping data extraction")
        return
    
    try:
        config = get_config()
        
        # Extract cf_clearance and auth token from cookies
        print("   ├── Extracting session cookies (cf_clearance, auth_token)...")
        try:
            cookies = await NODRIVER_TAB.browser.cookies.get_all()
            cf_clearance_cookie = None
            auth_cookie = None
            for cookie in cookies:
                if cookie.name == "cf_clearance":
                    cf_clearance_cookie = cookie
                elif "arena-auth-prod-v1" in cookie.name:
                    auth_cookie = cookie
            
            if cf_clearance_cookie:
                config["cf_clearance"] = cf_clearance_cookie.value
                print(f"   ├── ✅ cf_clearance found & saved")
            else:
                print("   ├── ⚠️ No cf_clearance cookie found")
                
            if auth_cookie:
                # Add to auth_tokens safely, avoiding duplicates if already exists
                has_token = any(t == auth_cookie.value for t in config.get("auth_tokens", []))
                if not has_token:
                    # Push to front of list
                    tokens = config.get("auth_tokens", [])
                    tokens.insert(0, auth_cookie.value)
                    config["auth_tokens"] = tokens
                print(f"   ├── ✅ Auto-extracted auth token ({auth_cookie.name})")
            
            save_config(config)
        except Exception as e:
            debug_print(f"   ├── ⚠️ Error extracting cookies: {e}")        
        # Extract models from page content
        print("   ├── Extracting available models...")
        try:
            # Get the page HTML content
            body = await NODRIVER_TAB.get_content()
            
            # Try to find models in the page
            match = re.search(r'{\\\"initialModels\\\":(\\[.*?\\]),\\\"initialModel[A-Z]Id', body, re.DOTALL)
            if match:
                models_json = match.group(1).encode().decode('unicode_escape')
                models = json.loads(models_json)
                save_models(models)
                print(f"   ├── ✅ Found {len(models)} models")
            else:
                # Try alternative pattern
                match2 = re.search(r'"initialModels":(\[.*?\]),"initialModel', body, re.DOTALL)
                if match2:
                    models = json.loads(match2.group(1))
                    save_models(models)
                    print(f"   ├── ✅ Found {len(models)} models")
                else:
                    print("   ├── ⚠️ Could not find models in page (using cached)")
        except Exception as e:
            debug_print(f"   ├── ⚠️ Error extracting models: {e}")
        
        print("   └── ✅ Initial data extraction complete")
        
    except Exception as e:
        print(f"   └── ❌ Error during data extraction: {e}")

async def periodic_refresh_task():
    """Background task to refresh cf_clearance and models every 30 minutes"""
    while True:
        try:
            # Wait 30 minutes (1800 seconds)
            await asyncio.sleep(1800)
            debug_print("\n" + "="*60)
            debug_print("🔄 Starting scheduled 30-minute refresh...")
            debug_print("="*60)
            await get_initial_data()
            debug_print("✅ Scheduled refresh completed")
            debug_print("="*60 + "\n")
        except Exception as e:
            debug_print(f"❌ Error in periodic refresh task: {e}")
            # Continue the loop even if there's an error
            continue

@app.on_event("startup")
async def startup_event():
    try:
        # Print startup banner
        print("=" * 60)
        print("🚀 LMArena Bridge Server Starting...")
        print("=" * 60)
        
        # Load configuration
        config = get_config()
        save_config(config)
        save_models(get_models())
        load_usage_stats()
        
        api_key_count = len(config.get("api_keys", []))
        auth_token_count = len(config.get("auth_tokens", [])) or (1 if config.get("auth_token") else 0)
        
        print(f"📋 Configuration loaded from config.json")
        print(f"   ├── API Keys: {api_key_count} configured")
        print(f"   ├── Auth Tokens: {auth_token_count} configured")
        print(f"   └── Debug Mode: {'ON' if DEBUG else 'OFF'}")
        
        # 1. Initialize browser and solve CAPTCHA (this blocks until user solves)
        browser_ready = await initialize_nodriver_browser()
        
        if not browser_ready:
            print("")
            print("⚠️ WARNING: Server starting without browser (limited functionality)")
            print("   └── reCAPTCHA token refresh will not work")
            print("")
        else:
            # 2. Extract initial data from the browser session
            await get_initial_data()
        
        # 3. Start background tasks
        asyncio.create_task(periodic_refresh_task())
        
        # Print ready message
        print("")
        print("=" * 60)
        print("✅ SERVER READY!")
        print("=" * 60)
        print(f"📍 Dashboard:         http://localhost:{PORT}/dashboard")
        print(f"🔐 Login:             http://localhost:{PORT}/dash/login")
        print(f"📚 Universal API:     http://localhost:{PORT}/v1")
        if browser_ready:
            print("💡 Chrome window will stay open (do not close it!)")
        print("=" * 60)
        print("")
        
    except Exception as e:
        print(f"❌ Error during startup: {e}")
        import traceback
        traceback.print_exc()
        # Continue anyway - server should still start

# --- UI Endpoints (Login/Dashboard) ---

@app.get("/")
async def root():
    return {"status": "online", "message": "Arena Bridge is running"}

@app.get("/dash/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None):
    if await get_current_session(request):
        return RedirectResponse(url="/dashboard")
    
    error_msg = '<div class="error-message">Invalid password. Please try again.</div>' if error else ''
    
    return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - LMArena Bridge</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }}
                .login-container {{
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                    width: 100%;
                    max-width: 400px;
                }}
                h1 {{
                    color: #333;
                    margin-bottom: 10px;
                    font-size: 28px;
                }}
                .subtitle {{
                    color: #666;
                    margin-bottom: 30px;
                    font-size: 14px;
                }}
                .form-group {{
                    margin-bottom: 20px;
                }}
                label {{
                    display: block;
                    margin-bottom: 8px;
                    color: #555;
                    font-weight: 500;
                }}
                input[type="password"] {{
                    width: 100%;
                    padding: 12px;
                    border: 2px solid #e1e8ed;
                    border-radius: 6px;
                    font-size: 16px;
                    transition: border-color 0.3s;
                }}
                input[type="password"]:focus {{
                    outline: none;
                    border-color: #667eea;
                }}
                button {{
                    width: 100%;
                    padding: 12px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    border-radius: 6px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: transform 0.2s;
                }}
                button:hover {{
                    transform: translateY(-2px);
                }}
                button:active {{
                    transform: translateY(0);
                }}
                .error-message {{
                    background: #fee;
                    color: #c33;
                    padding: 12px;
                    border-radius: 6px;
                    margin-bottom: 20px;
                    border-left: 4px solid #c33;
                }}
            </style>
        </head>
        <body>
            <div class="login-container">
                <h1>LMArena Bridge</h1>
                <div class="subtitle">Sign in to access the dashboard</div>
                {error_msg}
                <form action="/dash/login" method="post">
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" placeholder="Enter your password" required autofocus>
                    </div>
                    <button type="submit">Sign In</button>
                </form>
            </div>
        </body>
        </html>
    """

@app.post("/dash/login")
async def login_submit(response: Response, password: str = Form(...)):
    config = get_config()
    if password == config.get("password"):
        session_id = str(uuid.uuid4())
        dashboard_sessions[session_id] = "admin"
        response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key="session_id", value=session_id, httponly=True)
        return response
    return RedirectResponse(url="/dash/login?error=1", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/logout")
async def logout(request: Request, response: Response):
    session_id = request.cookies.get("session_id")
    if session_id in dashboard_sessions:
        del dashboard_sessions[session_id]
    response = RedirectResponse(url="/dash/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("session_id")
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(session: str = Depends(get_current_session)):
    if not session:
        return RedirectResponse(url="/dash/login")

    try:
        config = get_config()
        models = get_models()
    except Exception as e:
        debug_print(f"❌ Error loading dashboard data: {e}")
        # Return error page
        return HTMLResponse(f"""
            <html><body style="font-family: sans-serif; padding: 40px; text-align: center;">
                <h1>⚠️ Dashboard Error</h1>
                <p>Failed to load configuration: {str(e)}</p>
                <p><a href="/logout">Logout</a> | <a href="/dashboard">Retry</a></p>
            </body></html>
        """, status_code=500)

    # Render API Keys
    keys_html = ""
    for key in config["api_keys"]:
        created_date = time.strftime('%Y-%m-%d %H:%M', time.localtime(key.get('created', 0)))
        keys_html += f"""
            <tr>
                <td><strong>{key['name']}</strong></td>
                <td><code class="api-key-code">{key['key']}</code></td>
                <td><span class="badge">{key['rpm']} RPM</span></td>
                <td><small>{created_date}</small></td>
                <td>
                    <form action='/delete-key' method='post' style='margin:0;'>
                        <input type='hidden' name='key_id' value='{key['key']}'>
                        <button type='submit' class='btn-delete'>Delete</button>
                    </form>
                </td>
            </tr>
        """

    # Render Models (limit to first 20 with text output)
    text_models = [m for m in models if m.get('capabilities', {}).get('outputCapabilities', {}).get('text')]
    models_html = ""
    for i, model in enumerate(text_models[:20]):
        rank = model.get('rank', '?')
        org = model.get('organization', 'Unknown')
        models_html += f"""
            <div class="model-card">
                <div class="model-header">
                    <span class="model-name">{model.get('publicName', 'Unnamed')}</span>
                    <span class="model-rank">Rank {rank}</span>
                </div>
                <div class="model-org">{org}</div>
            </div>
        """
    
    if not models_html:
        models_html = '<div class="no-data">No models found. Token may be invalid or expired.</div>'

    # Render Stats
    stats_html = ""
    if model_usage_stats:
        for model, count in sorted(model_usage_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            stats_html += f"<tr><td>{model}</td><td><strong>{count}</strong></td></tr>"
    else:
        stats_html = "<tr><td colspan='2' class='no-data'>No usage data yet</td></tr>"

    # Check token status - check BOTH auth_token (legacy single) and auth_tokens (new array)
    has_tokens = config.get("auth_token") or (config.get("auth_tokens") and len(config.get("auth_tokens", [])) > 0)
    token_status = "✅ Configured" if has_tokens else "❌ Not Set"
    token_class = "status-good" if has_tokens else "status-bad"
    
    cf_status = "✅ Configured" if config.get("cf_clearance") else "❌ Not Set"
    cf_class = "status-good" if config.get("cf_clearance") else "status-bad"
    
    # Get recent activity count (last 24 hours)
    recent_activity = sum(1 for timestamps in api_key_usage.values() for t in timestamps if time.time() - t < 86400)

    return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Namo LLM - Dashboard</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"></script>
            <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
            <style>
                :root {{
                    --bg-color: #F0F4FA;
                    --card-bg: #FFFFFF;
                    --purple-light: #E0D9FD;
                    --purple-dark: #C5B5FA;
                    --green-accent: #C9F257;
                    --text-dark: #1A1A2E;
                    --text-grey: #8E92BC;
                    --border-radius: 24px;
                    --shadow: 0 10px 40px rgba(0,0,0,0.03);
                }}
                
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                
                body {{
                    font-family: 'Outfit', sans-serif;
                    background-color: var(--bg-color);
                    color: var(--text-dark);
                    min-height: 100vh;
                    padding: 24px;
                }}

                .bento-container {{
                    display: grid;
                    grid-template-columns: 260px 1fr;
                    gap: 24px;
                    max-width: 1600px;
                    margin: 0 auto;
                    height: calc(100vh - 48px);
                }}

                /* Sidebar */
                .sidebar {{
                    background: var(--card-bg);
                    border-radius: var(--border-radius);
                    padding: 32px;
                    display: flex;
                    flex-direction: column;
                    box-shadow: var(--shadow);
                }}

                .logo {{
                    font-size: 24px;
                    font-weight: 700;
                    margin-bottom: 48px;
                    display: flex;
                    align-items: center;
                    gap: 12px;
                }}
                .logo i {{ color: #764ba2; }}

                .nav-menu {{ display: flex; flex-direction: column; gap: 12px; flex: 1; }}
                
                .nav-item {{
                    display: flex;
                    align-items: center;
                    gap: 16px;
                    padding: 14px 20px;
                    border-radius: 16px;
                    color: var(--text-grey);
                    text-decoration: none;
                    font-weight: 500;
                    transition: all 0.2s;
                }}
                
                .nav-item.active {{
                    background-color: var(--green-accent);
                    color: var(--text-dark);
                    font-weight: 600;
                }}
                
                .nav-item:hover:not(.active) {{
                    background-color: #f8f9fa;
                    color: var(--text-dark);
                }}

                /* Main Content */
                .main-column {{
                    display: flex;
                    flex-direction: column;
                    gap: 24px;
                    overflow-y: auto;
                    padding-right: 5px;
                }}
                
                /* Header */
                .header-card {{
                    background: var(--card-bg);
                    border-radius: var(--border-radius);
                    padding: 20px 32px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    box-shadow: var(--shadow);
                }}
                
                .page-title {{ font-size: 24px; font-weight: 600; }}
                
                .search-bar {{
                    background: #F5F7FA;
                    border-radius: 12px;
                    padding: 12px 20px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    width: 300px;
                    color: var(--text-grey);
                }}
                .search-bar input {{
                    border: none;
                    background: transparent;
                    outline: none;
                    font-family: inherit;
                    width: 100%;
                    color: var(--text-dark);
                }}

                .profile-section {{
                    display: flex;
                    align-items: center;
                    gap: 24px;
                }}
                
                .icon-btn {{
                    font-size: 20px;
                    color: var(--text-dark);
                    cursor: pointer;
                }}

                .user-badge {{
                    background: linear-gradient(135deg, #E0D9FD 0%, #C5B5FA 100%);
                    padding: 8px 16px;
                    border-radius: 50px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    font-weight: 500;
                }}
                
                /* Dashboard Grid */
                .dashboard-grid {{
                    display: grid;
                    grid-template-columns: repeat(3, 1fr);
                    gap: 24px;
                }}

                .card {{
                    background: var(--card-bg);
                    border-radius: var(--border-radius);
                    padding: 24px;
                    box-shadow: var(--shadow);
                }}

                .full-width {{ grid-column: 1 / -1; }}
                .two-thirds {{ grid-column: span 2; }}
                
                /* Purple Hero Card */
                .hero-card {{
                    background: linear-gradient(135deg, #E0D9FD 0%, #C5B5FA 100%);
                    padding: 32px;
                    position: relative;
                    overflow: hidden;
                }}
                
                .hero-stat {{
                    font-size: 48px;
                    font-weight: 700;
                    margin-top: 10px;
                    margin-bottom: 5px;
                    color: #1A1A2E;
                }}
                
                .hero-label {{ font-size: 16px; font-weight: 500; opacity: 0.8; color: #1A1A2E; }}
                .avatars {{ display: flex; margin-top: 20px; }}
                .avatar-stack {{
                    width: 40px; height: 40px; border-radius: 50%; border: 2px solid white; margin-left: -10px; background: #ddd;
                    display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: bold;
                }}
                .avatar-stack:first-child {{ margin-left: 0; background: #FFD166; }}
                
                /* Green Chart Card */
                .usage-card {{
                    background: var(--card-bg);
                }}
                
                .card-title {{
                    font-size: 18px;
                    font-weight: 600;
                    margin-bottom: 24px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}

                /* Status Pills */
                .status-pill {{
                    padding: 6px 12px;
                    border-radius: 8px;
                    font-size: 12px;
                    font-weight: 600;
                }}
                .status-active {{ background: #C9F257; color: #1A1A2E; }}
                .status-inactive {{ background: #FFE5D9; color: #FF5C5C; }}

                /* Form Elements */
                .styled-input {{
                    width: 100%;
                    padding: 12px 16px;
                    border: 2px solid #F0F4FA;
                    border-radius: 12px;
                    font-family: inherit;
                    margin-bottom: 15px;
                    transition: all 0.2s;
                }}
                .styled-input:focus {{ border-color: #764ba2; outline: none; }}
                
                .btn-primary {{
                    background: var(--text-dark);
                    color: white;
                    padding: 12px 24px;
                    border-radius: 12px;
                    border: none;
                    font-weight: 600;
                    cursor: pointer;
                    width: 100%;
                    transition: transform 0.2s;
                }}
                .btn-primary:hover {{ transform: translateY(-2px); }}
                
                .btn-green {{
                    background: var(--green-accent);
                    color: var(--text-dark);
                    padding: 8px 16px;
                    border-radius: 10px;
                    border: none;
                    font-weight: 600;
                    cursor: pointer;
                }}
                .btn-delete {{ 
                    background: #FFF0F0; color: #FF5C5C; 
                    padding: 6px 12px; border-radius: 8px; border: none; cursor: pointer;
                }}
                
                /* Table Styles */
                table {{ width: 100%; border-collapse: separate; border-spacing: 0 8px; }}
                th {{ text-align: left; padding: 0 16px; color: var(--text-grey); font-weight: 500; font-size: 14px; }}
                td {{ background: #F8F9FB; padding: 16px; first-child: border-top-left-radius: 12px; }}
                tr td:first-child {{ border-top-left-radius: 12px; border-bottom-left-radius: 12px; }}
                tr td:last-child {{ border-top-right-radius: 12px; border-bottom-right-radius: 12px; }}

                .token-item {{
                    background: #FAFAFA;
                    border: 1px solid #EEE;
                    padding: 12px;
                    border-radius: 12px;
                    display: flex;
                    gap: 10px;
                    align-items: center;
                    margin-bottom: 8px;
                    width: 100%;
                }}

                .token-item code {{
                    font-family: monospace;
                    font-size: 12px;
                    color: #666;
                    flex: 1;
                    white-space: nowrap;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }}

            </style>
        </head>
        <body>
            <div class="bento-container">
                <!-- Sidebar -->
                <div class="sidebar">
                    <div class="logo">
                        <i class="fa-solid fa-cube"></i>
                        Namo LLM
                    </div>
                    <div class="nav-menu">
                        <a href="#" class="nav-item active"><i class="fa-solid fa-chart-pie"></i> Dashboard</a>
                        <a href="#" class="nav-item"><i class="fa-solid fa-server"></i> Proxies</a>
                        <a href="#" class="nav-item"><i class="fa-solid fa-key"></i> Keys</a>
                        <a href="#" class="nav-item"><i class="fa-solid fa-gear"></i> Settings</a>
                    </div>
                    
                    <div style="margin-top: auto; padding: 20px; background: #F5F7FA; border-radius: 16px;">
                        <div style="font-size: 12px; color: #888; margin-bottom: 5px;">Server Status</div>
                        <div style="display: flex; align-items: center; gap: 8px;">
                             <div style="width: 8px; height: 8px; background: #00CC66; border-radius: 50%;"></div>
                             <span style="font-weight: 600; font-size: 14px;">Online</span>
                        </div>
                    </div>
                    
                    <a href="/logout" class="nav-item" style="margin-top: 10px; color: #FF5C5C;">
                        <i class="fa-solid fa-arrow-right-from-bracket"></i> Logout
                    </a>
                </div>

                <!-- Main Content -->
                <div class="main-column">
                    <!-- Header -->
                    <div class="header-card">
                        <div class="page-title">Dashboard</div>
                        
                        <div class="search-bar">
                            <i class="fa-solid fa-magnifying-glass"></i>
                            <input type="text" placeholder="Search...">
                        </div>
                        
                        <div class="profile-section">
                            <i class="fa-regular fa-bell icon-btn"></i>
                            <div class="user-badge">
                                <i class="fa-solid fa-user-astronaut"></i>
                                <span>Admin User</span>
                                <i class="fa-solid fa-angle-down" style="font-size: 12px;"></i>
                            </div>
                        </div>
                    </div>

                    <div class="dashboard-grid">
                        <!-- Hero Stat Card (Purple) -->
                        <div class="card hero-card">
                            <div class="hero-label">Total Requests</div>
                            <div class="hero-stat">{sum(model_usage_stats.values())}</div>
                            <div style="font-size: 14px; background: rgba(255,255,255,0.3); display: inline-block; padding: 4px 10px; border-radius: 20px;">
                                <i class="fa-solid fa-arrow-trend-up"></i> +12% this week
                            </div>
                            <div class="avatars">
                                <div class="avatar-stack">L</div>
                                <div class="avatar-stack">M</div>
                                <div class="avatar-stack">+3</div>
                            </div>
                        </div>

                        <!-- Secondary Stat Card 1 -->
                        <div class="card">
                            <div class="card-title">
                                <span>Active Models</span>
                                <span class="status-pill status-active" style="background: #E0E7FF; color: #4338CA;">{len(text_models)}</span>
                            </div>
                            <div style="font-size: 32px; font-weight: 700; margin-bottom: 5px;">{len(text_models)}</div>
                            <div style="color: grey; font-size: 13px;">Text generation enabled</div>
                            <div style="margin-top: 20px; height: 6px; background: #F0F0F0; border-radius: 10px; overflow: hidden;">
                                <div style="width: 85%; height: 100%; background: #4338CA;"></div>
                            </div>
                        </div>

                        <!-- Secondary Stat Card 2 (Green) -->
                        <div class="card" style="background: #C9F257;">
                            <div class="card-title">
                                <span>System Health</span>
                                <i class="fa-solid fa-heart-pulse"></i>
                            </div>
                            <div style="font-size: 32px; font-weight: 700; color: #1A1A2E;">98%</div>
                            <div style="color: #1A1A2E; opacity: 0.8; font-size: 13px;">Uptime this session</div>
                            <div style="margin-top: 20px; display: flex; gap: 5px;">
                                <div style="height: 30px; width: 6px; background: rgba(0,0,0,0.1); border-radius: 4px;"></div>
                                <div style="height: 20px; width: 6px; background: rgba(0,0,0,0.1); border-radius: 4px;"></div>
                                <div style="height: 40px; width: 6px; background: rgba(0,0,0,0.2); border-radius: 4px;"></div>
                                <div style="height: 35px; width: 6px; background: rgba(0,0,0,0.1); border-radius: 4px;"></div>
                            </div>
                        </div>

                        <!-- Main Graph Card -->
                        <div class="card two-thirds">
                            <div class="card-title">
                                <span>Proxy Usage</span>
                                <select style="border: none; background: #F5F7FA; padding: 5px 10px; border-radius: 8px; font-family: inherit;">
                                    <option>Last 24 Hours</option>
                                    <option>Last 7 Days</option>
                                </select>
                            </div>
                            <div style="height: 250px;">
                                <canvas id="modelBarChart"></canvas>
                            </div>
                        </div>

                        <!-- Tokens & Auth List -->
                        <div class="card">
                            <div class="card-title">
                                <span>Auth Tokens</span>
                                <form action="/refresh-tokens" method="post" style="display:inline;">
                                    <button style="border: none; background: none; cursor: pointer; color: #666;"><i class="fa-solid fa-sync"></i></button>
                                </form>
                            </div>
                            
                            <div style="max-height: 250px; overflow-y: auto; margin-bottom: 15px;">
                                {''.join([f'''
                                <div class="token-item">
                                    <div style="width: 8px; height: 8px; background: #C9F257; border-radius: 50%;"></div>
                                    <code>{token[:20]}...</code>
                                    <form action="/delete-auth-token" method="post" style="margin: 0;">
                                        <input type="hidden" name="token_index" value="{i}">
                                        <button type="submit" style="color: #FF5C5C; border: none; background: none; cursor: pointer;">x</button>
                                    </form>
                                </div>
                                ''' for i, token in enumerate(config.get("auth_tokens", []))])}
                                
                                {('<div style="text-align: center; color: #AAA; font-size: 13px;">No tokens set</div>' if not config.get("auth_tokens") else '')}
                            </div>

                            <form action="/add-auth-token" method="post">
                                <input type="text" name="new_auth_token" class="styled-input" placeholder="Paste Auth Token..." required style="margin-bottom: 10px; padding: 8px;">
                                <button type="submit" class="btn-green" style="width: 100%;">Add Token</button>
                            </form>
                        </div>
                        
                        <!-- Configuration / API Keys -->
                         <div class="card full-width">
                            <div class="card-title">
                                <span>API Keys Management</span>
                                <span class="status-pill status-active">{len(config['api_keys'])} Active Keys</span>
                            </div>
                            
                            <table>
                                <thead>
                                    <tr>
                                        <th>Name</th>
                                        <th>Key</th>
                                        <th>RPM Limit</th>
                                        <th>Created</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {keys_html if keys_html else '<tr><td colspan="5" style="text-align:center; color:#999;">No keys found</td></tr>'}
                                </tbody>
                            </table>
                            
                            <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #EEE;">
                                <h4 style="margin-bottom: 15px;">Create New Key</h4>
                                <form action="/create-key" method="post" style="display: flex; gap: 15px;">
                                    <input type="text" name="name" class="styled-input" placeholder="Key Name" required style="margin:0; flex: 1;">
                                    <input type="number" name="rpm" class="styled-input" placeholder="RPM" value="60" required style="margin:0; width: 100px;">
                                    <button type="submit" class="btn-primary" style="width: auto;">Generate Key</button>
                                </form>
                            </div>
                        </div>

                    </div>
                </div>
            </div>

            <script>
                // Prepare data for charts
                const statsData = {json.dumps(dict(sorted(model_usage_stats.items(), key=lambda x: x[1], reverse=True)[:10]))};
                const modelNames = Object.keys(statsData);
                const modelCounts = Object.values(statsData);
                
                // Bento Style Chart Config
                Chart.defaults.font.family = "'Outfit', sans-serif";
                Chart.defaults.color = '#8E92BC';
                
                if (modelNames.length > 0) {{
                    const barCtx = document.getElementById('modelBarChart').getContext('2d');
                    // Create gradient
                    const gradient = barCtx.createLinearGradient(0, 0, 0, 400);
                    gradient.addColorStop(0, '#764ba2');
                    gradient.addColorStop(1, '#667eea');

                    new Chart(barCtx, {{
                        type: 'line',
                        data: {{
                            labels: modelNames,
                            datasets: [{{
                                label: 'Requests',
                                data: modelCounts,
                                backgroundColor: 'rgba(118, 75, 162, 0.1)',
                                borderColor: '#764ba2',
                                borderWidth: 3,
                                pointBackgroundColor: '#fff',
                                pointBorderColor: '#764ba2',
                                pointRadius: 6,
                                fill: true,
                                tension: 0.4
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {{
                                legend: {{ display: false }},
                                tooltip: {{
                                    backgroundColor: '#1A1A2E',
                                    padding: 12,
                                    titleFont: {{ size: 13 }},
                                    bodyFont: {{ size: 14, weight: 'bold' }},
                                    cornerRadius: 8,
                                    displayColors: false
                                }}
                            }},
                            scales: {{
                                y: {{
                                    beginAtZero: true,
                                    grid: {{ color: '#F0F0F0', borderDash: [5, 5] }},
                                    border: {{ display: false }}
                                }},
                                x: {{
                                    grid: {{ display: false }},
                                    border: {{ display: false }}
                                }}
                            }}
                        }}
                    }});
                }}
            </script>
        </body>
        </html>
    """

@app.post("/update-auth-token")
async def update_auth_token(session: str = Depends(get_current_session), auth_token: str = Form(...)):
    if not session:
        return RedirectResponse(url="/dash/login")
    config = get_config()
    config["auth_token"] = auth_token.strip()
    save_config(config)
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/create-key")
async def create_key(session: str = Depends(get_current_session), name: str = Form(...), rpm: int = Form(...)):
    if not session:
        return RedirectResponse(url="/dash/login")
    try:
        config = get_config()
        new_key = {
            "name": name.strip(),
            "key": f"sk-lmab-{uuid.uuid4()}",
            "rpm": max(1, min(rpm, 1000)),  # Clamp between 1-1000
            "created": int(time.time())
        }
        config["api_keys"].append(new_key)
        save_config(config)
    except Exception as e:
        debug_print(f"❌ Error creating key: {e}")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/delete-key")
async def delete_key(session: str = Depends(get_current_session), key_id: str = Form(...)):
    if not session:
        return RedirectResponse(url="/dash/login")
    try:
        config = get_config()
        config["api_keys"] = [k for k in config["api_keys"] if k["key"] != key_id]
        save_config(config)
    except Exception as e:
        debug_print(f"❌ Error deleting key: {e}")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/add-auth-token")
async def add_auth_token(session: str = Depends(get_current_session), new_auth_token: str = Form(...)):
    if not session:
        return RedirectResponse(url="/dash/login")
    try:
        config = get_config()
        token = new_auth_token.strip()
        if token and token not in config.get("auth_tokens", []):
            if "auth_tokens" not in config:
                config["auth_tokens"] = []
            config["auth_tokens"].append(token)
            save_config(config)
    except Exception as e:
        debug_print(f"❌ Error adding auth token: {e}")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/delete-auth-token")
async def delete_auth_token(session: str = Depends(get_current_session), token_index: int = Form(...)):
    if not session:
        return RedirectResponse(url="/dash/login")
    try:
        config = get_config()
        auth_tokens = config.get("auth_tokens", [])
        if 0 <= token_index < len(auth_tokens):
            auth_tokens.pop(token_index)
            config["auth_tokens"] = auth_tokens
            save_config(config)
    except Exception as e:
        debug_print(f"❌ Error deleting auth token: {e}")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/refresh-tokens")
async def refresh_tokens(session: str = Depends(get_current_session)):
    if not session:
        return RedirectResponse(url="/dash/login")
    try:
        await get_initial_data()
    except Exception as e:
        debug_print(f"❌ Error refreshing tokens: {e}")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

# --- OpenAI Compatible API Endpoints ---

@app.get("/v1/health")
@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint for monitoring"""
    try:
        models = get_models()
        config = get_config()
        
        # Basic health checks
        has_cf_clearance = bool(config.get("cf_clearance"))
        has_models = len(models) > 0
        has_api_keys = len(config.get("api_keys", [])) > 0
        
        status = "healthy" if (has_cf_clearance and has_models) else "degraded"
        
        return {
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": {
                "cf_clearance": has_cf_clearance,
                "models_loaded": has_models,
                "model_count": len(models),
                "api_keys_configured": has_api_keys
            }
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e)
        }

@app.get("/v1/models")
@app.get("/api/v1/models")
async def list_models(api_key: dict = Depends(rate_limit_api_key)):
    try:
        models = get_models()
        
        # Filter for models with text OR search OR image output capability and an organization (exclude stealth models)
        # Always include image models - no special key needed
        valid_models = [m for m in models 
                       if (m.get('capabilities', {}).get('outputCapabilities', {}).get('text')
                           or m.get('capabilities', {}).get('outputCapabilities', {}).get('search')
                           or m.get('capabilities', {}).get('outputCapabilities', {}).get('image'))
                       and m.get('organization')]
        
        return {
            "object": "list",
            "data": [
                {
                    "id": model.get("publicName"),
                    "object": "model",
                    "created": int(time.time()),
                    "owned_by": model.get("organization", "lmarena")
                } for model in valid_models if model.get("publicName")
            ]
        }
    except Exception as e:
        debug_print(f"❌ Error listing models: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to load models: {str(e)}")

@app.post("/v1/chat/completions")
@app.post("/api/v1/chat/completions")
@app.post("/api/v1/responses")
@app.post("/v1/responses")
@app.post("/v1/v1/responses")
async def api_chat_completions(request: Request, api_key: dict = Depends(rate_limit_api_key)):
    debug_print("\n" + "="*80)
    debug_print("🔵 NEW API REQUEST RECEIVED")
    debug_print("="*80)
    
    try:
        # Parse request body with error handling
        try:
            body = await request.json()
        except json.JSONDecodeError as e:
            debug_print(f"❌ Invalid JSON in request body: {e}")
            raise HTTPException(status_code=400, detail=f"Invalid JSON in request body: {str(e)}")
        except Exception as e:
            debug_print(f"❌ Failed to read request body: {e}")
            raise HTTPException(status_code=400, detail=f"Failed to read request body: {str(e)}")
        
        debug_print(f"📥 Request body keys: {list(body.keys())}")
        
        # Validate required fields
        model_public_name = body.get("model")
        messages = body.get("messages", [])
        stream = body.get("stream", False)
        
        # TEMPORARY WORKAROUND: Force non-streaming mode
        # Streaming now uses browser-based streaming (bypasses reCAPTCHA!)
        # Implemented via make_lmarena_streaming_request_browser()
        

        debug_print(f"🌊 Stream mode: {stream}")
        debug_print(f"🤖 Requested model: {model_public_name}")
        debug_print(f"💬 Number of messages: {len(messages)}")
        
        if not model_public_name:
            debug_print("❌ Missing 'model' in request")
            raise HTTPException(status_code=400, detail="Missing 'model' in request body.")
        
        if not messages:
            debug_print("❌ Missing 'messages' in request")
            raise HTTPException(status_code=400, detail="Missing 'messages' in request body.")
        
        if not isinstance(messages, list):
            debug_print("❌ 'messages' must be an array")
            raise HTTPException(status_code=400, detail="'messages' must be an array.")
        
        if len(messages) == 0:
            debug_print("❌ 'messages' array is empty")
            raise HTTPException(status_code=400, detail="'messages' array cannot be empty.")

        # Find model ID from public name
        try:
            models = get_models()
            debug_print(f"📚 Total models loaded: {len(models)}")
        except Exception as e:
            debug_print(f"❌ Failed to load models: {e}")
            raise HTTPException(
                status_code=503,
                detail="Failed to load model list from LMArena. Please try again later."
            )
        
        model_id = None
        model_org = None
        model_capabilities = {}
        
        for m in models:
            if m.get("publicName") == model_public_name:
                model_id = m.get("id")
                model_org = m.get("organization")
                model_capabilities = m.get("capabilities", {})
                break
        
        if not model_id:
            debug_print(f"❌ Model '{model_public_name}' not found in model list")
            raise HTTPException(
                status_code=404, 
                detail=f"Model '{model_public_name}' not found. Use /api/v1/models to see available models."
            )
        
        # Check if model is a stealth model (no organization)
        if not model_org:
            debug_print(f"❌ Model '{model_public_name}' is a stealth model (no organization)")
            raise HTTPException(
                status_code=403,
                detail="You do not have access to stealth models. Contact cloudwaddie for more info."
            )
        
        debug_print(f"✅ Found model ID: {model_id}")
        debug_print(f"🔧 Model capabilities: {model_capabilities}")
        
        # Determine modality based on model capabilities
        # Priority: image > search > chat
        if model_capabilities.get('outputCapabilities', {}).get('image'):
            modality = "image"
        elif model_capabilities.get('outputCapabilities', {}).get('search'):
            modality = "search"
        else:
            modality = "chat"
        debug_print(f"🔍 Model modality: {modality}")

        # Log usage
        try:
            model_usage_stats[model_public_name] += 1
            # Save stats immediately after incrementing
            config = get_config()
            config["usage_stats"] = dict(model_usage_stats)
            save_config(config)
        except Exception as e:
            # Don't fail the request if usage logging fails
            debug_print(f"⚠️  Failed to log usage stats: {e}")

        # Extract system prompt if present and prepend to first user message
        system_prompt = ""
        system_messages = [m for m in messages if m.get("role") == "system"]
        if system_messages:
            # Handle content that might be a list (Claude CLI format) or string
            system_parts = []
            for m in system_messages:
                content = m.get("content", "")
                if isinstance(content, list):
                    # Extract text from content blocks
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            system_parts.append(str(block.get("text", "")))
                        elif isinstance(block, str):
                            system_parts.append(block)
                else:
                    system_parts.append(str(content))
            system_prompt = "\n\n".join(system_parts)
            debug_print(f"📋 System prompt found: {system_prompt[:100]}..." if len(system_prompt) > 100 else f"📋 System prompt: {system_prompt}")
        
        # Process last message content (may include images)
        try:
            last_message_content = messages[-1].get("content", "")
            prompt, experimental_attachments = await process_message_content(last_message_content, model_capabilities)
            
            # If there's a system prompt and this is the first user message, prepend it
            if system_prompt:
                prompt = f"{system_prompt}\n\n{prompt}"
                debug_print(f"✅ System prompt prepended to user message")
        except Exception as e:
            debug_print(f"❌ Failed to process message content: {e}")
            raise HTTPException(
                status_code=400,
                detail=f"Failed to process message content: {str(e)}"
            )
        
        # Validate prompt
        if not prompt:
            # If no text but has attachments, that's okay for vision models
            if not experimental_attachments:
                debug_print("❌ Last message has no content")
                raise HTTPException(status_code=400, detail="Last message must have content.")
        
        # Log prompt length for debugging character limit issues
        debug_print(f"📝 User prompt length: {len(prompt)} characters")
        debug_print(f"🖼️  Attachments: {len(experimental_attachments)} images")
        debug_print(f"📝 User prompt preview: {prompt[:100]}..." if len(prompt) > 100 else f"📝 User prompt: {prompt}")
        
        # Check for reasonable character limit (LMArena appears to have limits)
        # Typical limit seems to be around 32K-64K characters based on testing
        MAX_PROMPT_LENGTH = 113567  # User hardcoded limit
        if len(prompt) > MAX_PROMPT_LENGTH:
            error_msg = f"Prompt too long ({len(prompt)} characters). LMArena has a character limit of approximately {MAX_PROMPT_LENGTH} characters. Please reduce the message size."
            debug_print(f"❌ {error_msg}")
            raise HTTPException(status_code=400, detail=error_msg)
        
        # Use API key + conversation tracking
        api_key_str = api_key["key"]

        # --- NEW: Get reCAPTCHA v3 Token for Payload ---
        recaptcha_token = await refresh_recaptcha_token()
        if not recaptcha_token:
            debug_print("❌ Cannot proceed, failed to get reCAPTCHA token.")
            raise HTTPException(
                status_code=503,
                detail="Service Unavailable: Failed to acquire reCAPTCHA token. The bridge server may be blocked."
            )
        debug_print(f"🔑 Using reCAPTCHA v3 token: {recaptcha_token[:20]}...")
        # -----------------------------------------------
        
        # Generate conversation ID from context (API key + model + first user message)
        import hashlib
        first_user_message = next((m.get("content", "") for m in messages if m.get("role") == "user"), "")
        if isinstance(first_user_message, list):
            # Handle array content format
            first_user_message = str(first_user_message)
        conversation_key = f"{api_key_str}_{model_public_name}_{first_user_message[:100]}"
        conversation_id = hashlib.sha256(conversation_key.encode()).hexdigest()[:16]
        
        debug_print(f"🔑 API Key: {api_key_str[:20]}...")
        debug_print(f"💭 Auto-generated Conversation ID: {conversation_id}")
        debug_print(f"🔑 Conversation key: {conversation_key[:100]}...")
        
        headers = get_request_headers()
        debug_print(f"📋 Headers prepared (auth token length: {len(headers.get('Cookie', '').split('arena-auth-prod-v1=')[-1].split(';')[0])} chars)")
        
        # Check if conversation exists for this API key
        # When FORCE_NEW_SESSION is enabled, always create new sessions to bypass per-session rate limits
        if FORCE_NEW_SESSION:
            session = None  # Force new session for every request
            debug_print("🔄 FORCE_NEW_SESSION enabled - creating fresh session (bypasses rate limits)")
        else:
            session = chat_sessions[api_key_str].get(conversation_id)
        
        # Detect retry: if session exists and last message is same user message (no assistant response after it)
        is_retry = False
        retry_message_id = None
        
        if session and len(session.get("messages", [])) >= 2:
            stored_messages = session["messages"]
            # Check if last stored message is from user with same content
            if stored_messages[-1]["role"] == "user" and stored_messages[-1]["content"] == prompt:
                # This is a retry - client sent same message again without assistant response
                is_retry = True
                retry_message_id = stored_messages[-1]["id"]
                # Get the assistant message ID that needs to be regenerated
                if len(stored_messages) >= 2 and stored_messages[-2]["role"] == "assistant":
                    # There was a previous assistant response - we'll retry that one
                    retry_message_id = stored_messages[-2]["id"]
                    debug_print(f"🔁 RETRY DETECTED - Regenerating assistant message {retry_message_id}")
        
        if is_retry and retry_message_id:
            debug_print(f"🔁 Using RETRY endpoint")
            # Use LMArena's retry endpoint
            # Format: PUT /nextjs-api/stream/retry-evaluation-session-message/{sessionId}/messages/{messageId}
            payload = {}
            url = f"https://arena.ai/nextjs-api/stream/retry-evaluation-session-message/{session['conversation_id']}/messages/{retry_message_id}"
            debug_print(f"📤 Target URL: {url}")
            debug_print(f"📦 Using PUT method for retry")
            http_method = "PUT"
        elif not session:
            debug_print("🆕 Creating NEW conversation session")
            # New conversation - Generate all IDs at once (like the browser does)
            session_id = str(uuid7())
            user_msg_id = str(uuid7())
            model_msg_id = str(uuid7())
            
            debug_print(f"🔑 Generated session_id: {session_id}")
            debug_print(f"👤 Generated user_msg_id: {user_msg_id}")
            debug_print(f"🤖 Generated model_msg_id: {model_msg_id}")
            
            payload = {
                "id": session_id,
                "mode": "direct",
                "modelAId": model_id,
                "userMessageId": user_msg_id,
                "modelAMessageId": model_msg_id,
                "userMessage": {
                    "content": prompt,
                    "experimental_attachments": experimental_attachments,
                    "metadata": {}
                },
                "modality": modality,
                "recaptchaV3Token": recaptcha_token, # <--- ADD TOKEN HERE
            }
            url = "https://arena.ai/nextjs-api/stream/create-evaluation"
            debug_print(f"📤 Target URL: {url}")
            debug_print(f"📦 Payload structure: Simple userMessage format")
            debug_print(f"🔍 Full payload: {json.dumps(payload, indent=2)}")
            http_method = "POST"
        else:
            debug_print("🔄 Using EXISTING conversation session")
            # Follow-up message - Generate new message IDs
            user_msg_id = str(uuid7())
            debug_print(f"👤 Generated followup user_msg_id: {user_msg_id}")
            model_msg_id = str(uuid7())
            debug_print(f"🤖 Generated followup model_msg_id: {model_msg_id}")
            
            payload = {
                "id": session["conversation_id"],
                "modelAId": model_id,
                "userMessageId": user_msg_id,
                "modelAMessageId": model_msg_id,
                "userMessage": {
                    "content": prompt,
                    "experimental_attachments": experimental_attachments,
                    "metadata": {}
                },
                "modality": modality,
                "recaptchaV3Token": recaptcha_token, # <--- ADD TOKEN HERE
            }
            url = f"https://arena.ai/nextjs-api/stream/post-to-evaluation/{session['conversation_id']}"
            debug_print(f"📤 Target URL: {url}")
            debug_print(f"📦 Payload structure: Simple userMessage format")
            debug_print(f"🔍 Full payload: {json.dumps(payload, indent=2)}")
            http_method = "POST"

        debug_print(f"\n🚀 Making API request to LMArena...")
        debug_print(f"⏱️  Timeout set to: 120 seconds")
        
        # Initialize failed tokens tracking for this request
        request_id = str(uuid.uuid4())
        failed_tokens = set()
        
        # Get initial auth token using round-robin (excluding any failed ones)
        current_token = get_next_auth_token(exclude_tokens=failed_tokens)
        headers = get_request_headers_with_token(current_token)
        debug_print(f"🔑 Using token (round-robin): {current_token[:20]}...")
        
        # Retry logic wrapper
        async def make_request_with_retry(url, payload, http_method, max_retries=3):
            """Make request with automatic retry on 429/401 errors"""
            nonlocal current_token, headers, failed_tokens
            
            for attempt in range(max_retries):
                try:
                    # Use browser-based request (bypasses ALL bot detection)
                    debug_print(f"🌐 Using REAL Chrome browser for API call (attempt {attempt + 1}/{max_retries})")
                    browser_response = await make_lmarena_request_browser(url, payload, method=http_method)
                    
                    # Create a response-like object for compatibility
                    class BrowserResponse:
                        def __init__(self, status_code, text):
                            self.status_code = status_code
                            self.text = text
                            self.headers = {}  # Empty headers for browser requests
                        def raise_for_status(self):
                            if self.status_code >= 400:
                                raise HTTPException(status_code=self.status_code, detail=f"Browser request failed: {self.text[:200]}")
                    
                    response = BrowserResponse(browser_response["status_code"], browser_response["text"])
                    
                    # Log status with human-readable message
                    log_http_status(response.status_code, "LMArena API (via Browser)")
                    
                    # Check for retry-able errors
                    if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                        debug_print(f"⏱️  Attempt {attempt + 1}/{max_retries} - Rate limit")
                        if attempt < max_retries - 1:
                            await asyncio.sleep(2)  # Wait before retry
                            continue
                    
                    elif response.status_code == HTTPStatus.UNAUTHORIZED:
                        # Log the actual LMArena error response
                        debug_print(f"🔒 LMArena 401 Response: {response.text}")
                        debug_print(f"🔒 Attempt {attempt + 1}/{max_retries} - Auth failed")
                        if attempt < max_retries - 1:
                            await asyncio.sleep(1)
                            continue
                    
                    # If we get here, return the response (success or non-retryable error)
                    response.raise_for_status()
                    return response
                        
                except Exception as e:
                    # Catch browser and other exceptions
                    debug_print(f"❌ Request attempt {attempt + 1}/{max_retries} failed: {type(e).__name__}: {e}")
                    if attempt == max_retries - 1:
                        raise HTTPException(status_code=503, detail=f"Max retries exceeded: {type(e).__name__}: {str(e)}")
                    await asyncio.sleep(1)
                    continue
            
            # Should not reach here, but just in case
            raise HTTPException(status_code=503, detail="Max retries exceeded")
        
        # Handle streaming mode
        if stream:
            async def generate_stream():
                nonlocal current_token, headers
                chunk_id = f"chatcmpl-{uuid.uuid4()}"
                
                # Retry logic for streaming
                max_retries = 3
                for attempt in range(max_retries):
                    # Reset response data for each attempt
                    response_text = ""
                    reasoning_text = ""
                    citations = []
                    try:
                        # Use browser-based streaming (bypasses reCAPTCHA!)
                        debug_print(f"📡 Browser Streaming (attempt {attempt + 1}/{max_retries})")
                        debug_print(f"🔐 Using REAL Chrome browser for streaming")
                        
                        # Buffer for accumulating partial lines across chunks
                        line_buffer = ""
                        
                        async for raw_chunk in make_lmarena_streaming_request_browser(url, payload, method=http_method):
                            # Combine buffer with new chunk and split into lines
                            combined = line_buffer + raw_chunk
                            chunk_lines = combined.split('\n')
                            
                            # Keep the last partial line in buffer (if no trailing newline)
                            if not combined.endswith('\n'):
                                line_buffer = chunk_lines[-1]
                                chunk_lines = chunk_lines[:-1]
                            else:
                                line_buffer = ""
                            
                            for line in chunk_lines:
                                line = line.strip()
                                if not line:
                                    continue
                                
                                # Parse thinking/reasoning chunks: ag:"thinking text"
                                if line.startswith("ag:"):
                                    chunk_data = line[3:]
                                    try:
                                        reasoning_chunk = json.loads(chunk_data)
                                        reasoning_text += reasoning_chunk
                                        
                                        # Send SSE-formatted chunk with reasoning_content
                                        chunk_response = {
                                            "id": chunk_id,
                                            "object": "chat.completion.chunk",
                                            "created": int(time.time()),
                                            "model": model_public_name,
                                            "choices": [{
                                                "index": 0,
                                                "delta": {
                                                    "reasoning_content": reasoning_chunk
                                                },
                                                "finish_reason": None
                                            }]
                                        }
                                        yield f"data: {json.dumps(chunk_response)}\n\n"
                                        
                                    except json.JSONDecodeError:
                                        continue
                                
                                # Parse text chunks: a0:"Hello "
                                elif line.startswith("a0:"):
                                    chunk_data = line[3:]
                                    try:
                                        text_chunk = json.loads(chunk_data)
                                        response_text += text_chunk
                                        
                                        # Send SSE-formatted chunk
                                        chunk_response = {
                                            "id": chunk_id,
                                            "object": "chat.completion.chunk",
                                            "created": int(time.time()),
                                            "model": model_public_name,
                                            "choices": [{
                                                "index": 0,
                                                "delta": {
                                                    "content": text_chunk
                                                },
                                                "finish_reason": None
                                            }]
                                        }
                                        yield f"data: {json.dumps(chunk_response)}\n\n"
                                        
                                    except json.JSONDecodeError:
                                        continue
                                
                                # Parse image generation: a2:[{...}] (for image models)
                                elif line.startswith("a2:"):
                                    image_data = line[3:]
                                    try:
                                        image_list = json.loads(image_data)
                                        if isinstance(image_list, list) and len(image_list) > 0:
                                            image_obj = image_list[0]
                                            if image_obj.get('type') == 'image':
                                                image_url = image_obj.get('image', '')
                                                response_text = f"![Generated Image]({image_url})"
                                                
                                                chunk_response = {
                                                    "id": chunk_id,
                                                    "object": "chat.completion.chunk",
                                                    "created": int(time.time()),
                                                    "model": model_public_name,
                                                    "choices": [{
                                                        "index": 0,
                                                        "delta": {
                                                            "content": response_text
                                                        },
                                                        "finish_reason": None
                                                    }]
                                                }
                                                yield f"data: {json.dumps(chunk_response)}\n\n"
                                    except json.JSONDecodeError:
                                        pass
                                
                                # Parse citations/tool calls: ac:{...}
                                elif line.startswith("ac:"):
                                    citation_data = line[3:]
                                    try:
                                        citation_obj = json.loads(citation_data)
                                        if 'argsTextDelta' in citation_obj:
                                            args_data = json.loads(citation_obj['argsTextDelta'])
                                            if 'source' in args_data:
                                                source = args_data['source']
                                                if isinstance(source, list):
                                                    citations.extend(source)
                                                elif isinstance(source, dict):
                                                    citations.append(source)
                                        debug_print(f"  🔗 Citation added: {citation_obj.get('toolCallId')}")
                                    except json.JSONDecodeError:
                                        pass
                                
                                # Parse error messages: a3:"error"
                                elif line.startswith("a3:"):
                                    error_data = line[3:]
                                    try:
                                        error_message = json.loads(error_data)
                                        print(f"  ❌ Error in stream: {error_message}")
                                    except json.JSONDecodeError:
                                        pass
                                
                                # Parse metadata for finish: ad:{"finishReason":"stop"}
                                elif line.startswith("ad:"):
                                    metadata_data = line[3:]
                                    try:
                                        metadata = json.loads(metadata_data)
                                        finish_reason = metadata.get("finishReason", "stop")
                                        
                                        # Send final chunk with finish_reason
                                        final_chunk = {
                                            "id": chunk_id,
                                            "object": "chat.completion.chunk",
                                            "created": int(time.time()),
                                            "model": model_public_name,
                                            "choices": [{
                                                "index": 0,
                                                "delta": {},
                                                "finish_reason": finish_reason
                                            }]
                                        }
                                        yield f"data: {json.dumps(final_chunk)}\n\n"
                                    except json.JSONDecodeError:
                                        continue
                        
                        # Update session with completed message
                        assistant_message = {
                            "id": model_msg_id, 
                            "role": "assistant", 
                            "content": response_text.strip()
                        }
                        if reasoning_text:
                            assistant_message["reasoning_content"] = reasoning_text.strip()
                        if citations:
                            unique_citations = []
                            seen_urls = set()
                            for citation in citations:
                                citation_url = citation.get('url')
                                if citation_url and citation_url not in seen_urls:
                                    seen_urls.add(citation_url)
                                    unique_citations.append(citation)
                            assistant_message["citations"] = unique_citations
                        
                        if not session:
                            chat_sessions[api_key_str][conversation_id] = {
                                "conversation_id": session_id,
                                "model": model_public_name,
                                "messages": [
                                    {"id": user_msg_id, "role": "user", "content": prompt},
                                    assistant_message
                                ]
                            }
                            debug_print(f"💾 Saved new session for conversation {conversation_id}")
                        else:
                            chat_sessions[api_key_str][conversation_id]["messages"].append(
                                {"id": user_msg_id, "role": "user", "content": prompt}
                            )
                            chat_sessions[api_key_str][conversation_id]["messages"].append(
                                assistant_message
                            )
                            debug_print(f"💾 Updated existing session for conversation {conversation_id}")
                        
                        yield "data: [DONE]\n\n"
                        debug_print(f"✅ Stream completed - {len(response_text)} chars sent")
                        return  # Success, exit retry loop
                        
                    except HTTPException as e:
                        # Handle HTTPException from browser streaming
                        error_msg = str(e.detail)
                        print(f"❌ Stream error: {error_msg}")
                        
                        # Check for rate limit (429)
                        if e.status_code == 429 and attempt < max_retries - 1:
                            debug_print(f"⏱️  Rate limited, retrying...")
                            await asyncio.sleep(2)
                            continue
                        
                        error_chunk = {
                            "error": {
                                "message": error_msg,
                                "type": "api_error",
                                "code": e.status_code
                            }
                        }
                        yield f"data: {json.dumps(error_chunk)}\n\n"
                        return
                        
                    except Exception as e:
                        print(f"❌ Stream error: {str(e)}")
                        error_chunk = {
                            "error": {
                                "message": str(e),
                                "type": "internal_error"
                            }
                        }
                        yield f"data: {json.dumps(error_chunk)}\n\n"
                        return
            
            return StreamingResponse(generate_stream(), media_type="text/event-stream")
        
        # Handle non-streaming mode with retry
        try:
            response = await make_request_with_retry(url, payload, http_method)
            
            log_http_status(response.status_code, "LMArena API Response")
            debug_print(f"📏 Response length: {len(response.text)} characters")
            debug_print(f"📋 Response headers: {dict(response.headers)}")
            
            debug_print(f"🔍 Processing response...")
            debug_print(f"📄 First 500 chars of response:\n{response.text[:500]}")
            
            # Process response in lmarena format
            # Format: ag:"thinking" for reasoning, a0:"text chunk" for content, ac:{...} for citations, ad:{...} for metadata
            response_text = ""
            reasoning_text = ""
            citations = []
            finish_reason = None
            line_count = 0
            text_chunks_found = 0
            reasoning_chunks_found = 0
            citation_chunks_found = 0
            metadata_found = 0
            
            debug_print(f"📊 Parsing response lines...")
            
            error_message = None
            for line in response.text.splitlines():
                line_count += 1
                line = line.strip()
                if not line:
                    continue
                
                # Parse thinking/reasoning chunks: ag:"thinking text"
                if line.startswith("ag:"):
                    chunk_data = line[3:]  # Remove "ag:" prefix
                    reasoning_chunks_found += 1
                    try:
                        # Parse as JSON string (includes quotes)
                        reasoning_chunk = json.loads(chunk_data)
                        reasoning_text += reasoning_chunk
                        if reasoning_chunks_found <= 3:  # Log first 3 reasoning chunks
                            debug_print(f"  🧠 Reasoning chunk {reasoning_chunks_found}: {repr(reasoning_chunk[:50])}")
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse reasoning chunk on line {line_count}: {chunk_data[:100]} - {e}")
                        continue
                
                # Parse text chunks: a0:"Hello "
                elif line.startswith("a0:"):
                    chunk_data = line[3:]  # Remove "a0:" prefix
                    text_chunks_found += 1
                    try:
                        # Parse as JSON string (includes quotes)
                        text_chunk = json.loads(chunk_data)
                        response_text += text_chunk
                        if text_chunks_found <= 3:  # Log first 3 chunks
                            debug_print(f"  ✅ Chunk {text_chunks_found}: {repr(text_chunk[:50])}")
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse text chunk on line {line_count}: {chunk_data[:100]} - {e}")
                        continue
                
                # Parse image generation: a2:[{...}] (for image models)
                elif line.startswith("a2:"):
                    image_data = line[3:]  # Remove "a2:" prefix
                    try:
                        image_list = json.loads(image_data)
                        # OpenAI format expects URL in content
                        if isinstance(image_list, list) and len(image_list) > 0:
                            image_obj = image_list[0]
                            if image_obj.get('type') == 'image':
                                image_url = image_obj.get('image', '')
                                # Format as markdown
                                response_text = f"![Generated Image]({image_url})"
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse image data on line {line_count}: {image_data[:100]} - {e}")
                        continue
                
                # Parse citations/tool calls: ac:{...} (for search models)
                elif line.startswith("ac:"):
                    citation_data = line[3:]  # Remove "ac:" prefix
                    citation_chunks_found += 1
                    try:
                        citation_obj = json.loads(citation_data)
                        # Extract source information from argsTextDelta
                        if 'argsTextDelta' in citation_obj:
                            args_data = json.loads(citation_obj['argsTextDelta'])
                            if 'source' in args_data:
                                source = args_data['source']
                                # Can be a single source or array of sources
                                if isinstance(source, list):
                                    citations.extend(source)
                                elif isinstance(source, dict):
                                    citations.append(source)
                        if citation_chunks_found <= 3:  # Log first 3 citations
                            debug_print(f"  🔗 Citation chunk {citation_chunks_found}: {citation_obj.get('toolCallId')}")
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse citation chunk on line {line_count}: {citation_data[:100]} - {e}")
                        continue
                
                # Parse error messages: a3:"An error occurred"
                elif line.startswith("a3:"):
                    error_data = line[3:]  # Remove "a3:" prefix
                    try:
                        error_message = json.loads(error_data)
                        debug_print(f"  ❌ Error message received: {error_message}")
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse error message on line {line_count}: {error_data[:100]} - {e}")
                        error_message = error_data
                
                # Parse metadata: ad:{"finishReason":"stop"}
                elif line.startswith("ad:"):
                    metadata_data = line[3:]  # Remove "ad:" prefix
                    metadata_found += 1
                    try:
                        metadata = json.loads(metadata_data)
                        finish_reason = metadata.get("finishReason")
                        debug_print(f"  📋 Metadata found: finishReason={finish_reason}")
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse metadata on line {line_count}: {metadata_data[:100]} - {e}")
                        continue
                elif line.strip():  # Non-empty line that doesn't match expected format
                    if line_count <= 5:  # Log first 5 unexpected lines
                        debug_print(f"  ❓ Unexpected line format {line_count}: {line[:100]}")

            debug_print(f"\n📊 Parsing Summary:")
            debug_print(f"  - Total lines: {line_count}")
            debug_print(f"  - Reasoning chunks found: {reasoning_chunks_found}")
            debug_print(f"  - Text chunks found: {text_chunks_found}")
            debug_print(f"  - Citation chunks found: {citation_chunks_found}")
            debug_print(f"  - Metadata entries: {metadata_found}")
            debug_print(f"  - Final response length: {len(response_text)} chars")
            debug_print(f"  - Final reasoning length: {len(reasoning_text)} chars")
            debug_print(f"  - Citations found: {len(citations)}")
            debug_print(f"  - Finish reason: {finish_reason}")
            
            if not response_text:
                debug_print(f"\n⚠️  WARNING: Empty response text!")
                debug_print(f"📄 Full raw response:\n{response.text}")
                if error_message:
                    error_detail = f"LMArena API error: {error_message}"
                    print(f"❌ {error_detail}")
                    # Return OpenAI-compatible error response
                    return {
                        "error": {
                            "message": error_detail,
                            "type": "upstream_error",
                            "code": "lmarena_error"
                        }
                    }
                else:
                    error_detail = "LMArena API returned empty response. This could be due to: invalid auth token, expired cf_clearance, model unavailable, or API rate limiting."
                    debug_print(f"❌ {error_detail}")
                    # Return OpenAI-compatible error response
                    return {
                        "error": {
                            "message": error_detail,
                            "type": "upstream_error",
                            "code": "empty_response"
                        }
                    }
            else:
                debug_print(f"✅ Response text preview: {response_text[:200]}...")
            
            # Update session - Store message history with IDs (including reasoning and citations if present)
            assistant_message = {
                "id": model_msg_id, 
                "role": "assistant", 
                "content": response_text.strip()
            }
            if reasoning_text:
                assistant_message["reasoning_content"] = reasoning_text.strip()
            if citations:
                # Deduplicate citations by URL
                unique_citations = []
                seen_urls = set()
                for citation in citations:
                    citation_url = citation.get('url')
                    if citation_url and citation_url not in seen_urls:
                        seen_urls.add(citation_url)
                        unique_citations.append(citation)
                assistant_message["citations"] = unique_citations
            
            if not session:
                chat_sessions[api_key_str][conversation_id] = {
                    "conversation_id": session_id,
                    "model": model_public_name,
                    "messages": [
                        {"id": user_msg_id, "role": "user", "content": prompt},
                        assistant_message
                    ]
                }
                debug_print(f"💾 Saved new session for conversation {conversation_id}")
            else:
                # Append new messages to history
                chat_sessions[api_key_str][conversation_id]["messages"].append(
                    {"id": user_msg_id, "role": "user", "content": prompt}
                )
                chat_sessions[api_key_str][conversation_id]["messages"].append(
                    assistant_message
                )
                debug_print(f"💾 Updated existing session for conversation {conversation_id}")

            # Build message object with reasoning and citations if present
            message_obj = {
                "role": "assistant",
                "content": response_text.strip(),
            }
            if reasoning_text:
                message_obj["reasoning_content"] = reasoning_text.strip()
            if citations:
                # Deduplicate citations by URL
                unique_citations = []
                seen_urls = set()
                for citation in citations:
                    citation_url = citation.get('url')
                    if citation_url and citation_url not in seen_urls:
                        seen_urls.add(citation_url)
                        unique_citations.append(citation)
                message_obj["citations"] = unique_citations
                
                # Add citations as markdown footnotes
                if unique_citations:
                    footnotes = "\n\n---\n\n**Sources:**\n\n"
                    for i, citation in enumerate(unique_citations, 1):
                        title = citation.get('title', 'Untitled')
                        url = citation.get('url', '')
                        footnotes += f"{i}. [{title}]({url})\n"
                    message_obj["content"] = response_text.strip() + footnotes
            
            # Image models already have markdown formatting from parsing
            # No additional conversion needed
            
            # Calculate token counts (including reasoning tokens)
            prompt_tokens = len(prompt)
            completion_tokens = len(response_text)
            reasoning_tokens = len(reasoning_text)
            total_tokens = prompt_tokens + completion_tokens + reasoning_tokens
            
            # Build usage object with reasoning tokens if present
            usage_obj = {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens
            }
            if reasoning_tokens > 0:
                usage_obj["reasoning_tokens"] = reasoning_tokens
            
            final_response = {
                "id": f"chatcmpl-{uuid.uuid4()}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model_public_name,
                "conversation_id": conversation_id,
                "choices": [{
                    "index": 0,
                    "message": message_obj,
                    "finish_reason": "stop"
                }],
                "usage": usage_obj
            }
            
            debug_print(f"\n✅ REQUEST COMPLETED SUCCESSFULLY")
            debug_print("="*80)
            # LOG EXACT RESPONSE BEING SENT
            debug_print(f"📤 FINAL RESPONSE TO CLIENT:")
            debug_print(json.dumps(final_response, indent=2)[:1000])  # First 1000 chars
            debug_print("="*80 + "\n")
            
            return final_response


        except httpx.HTTPStatusError as e:
            # Log error status
            log_http_status(e.response.status_code, "Error Response")
            
            # Try to parse JSON error response from LMArena
            lmarena_error = None
            try:
                error_body = e.response.json()
                if isinstance(error_body, dict) and "error" in error_body:
                    lmarena_error = error_body["error"]
                    debug_print(f"📛 LMArena error message: {lmarena_error}")
            except:
                pass
            
            # Provide user-friendly error messages
            if e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                error_detail = "Rate limit exceeded on LMArena. Please try again in a few moments."
                error_type = "rate_limit_error"
            elif e.response.status_code == HTTPStatus.UNAUTHORIZED:
                error_detail = "Unauthorized: Your LMArena auth token has expired or is invalid. Please get a new auth token from the dashboard."
                error_type = "authentication_error"
            elif e.response.status_code == HTTPStatus.FORBIDDEN:
                error_detail = "Forbidden: Access to this resource is denied."
                error_type = "forbidden_error"
            elif e.response.status_code == HTTPStatus.NOT_FOUND:
                error_detail = "Not Found: The requested resource doesn't exist."
                error_type = "not_found_error"
            elif e.response.status_code == HTTPStatus.BAD_REQUEST:
                # Use LMArena's error message if available
                if lmarena_error:
                    error_detail = f"Bad Request: {lmarena_error}"
                else:
                    error_detail = "Bad Request: Invalid request parameters."
                error_type = "bad_request_error"
            elif e.response.status_code >= 500:
                error_detail = f"Server Error: LMArena API returned {e.response.status_code}"
                error_type = "server_error"
            else:
                # Use LMArena's error message if available
                if lmarena_error:
                    error_detail = f"LMArena API error: {lmarena_error}"
                else:
                    error_detail = f"LMArena API error: {e.response.status_code}"
                    try:
                        error_body = e.response.json()
                        error_detail += f" - {error_body}"
                    except:
                        error_detail += f" - {e.response.text[:200]}"
                error_type = "upstream_error"
            
            print(f"\n❌ HTTP STATUS ERROR")
            print(f"📛 Error detail: {error_detail}")
            print(f"📤 Request URL: {url}")
            debug_print(f"📤 Request payload (truncated): {json.dumps(payload, indent=2)[:500]}")
            debug_print(f"📥 Response text: {e.response.text[:500]}")
            print("="*80 + "\n")
            
            # Return OpenAI-compatible error response
            return {
                "error": {
                    "message": error_detail,
                    "type": error_type,
                    "code": f"http_{e.response.status_code}"
                }
            }
        
        except httpx.TimeoutException as e:
            print(f"\n⏱️  TIMEOUT ERROR")
            print(f"📛 Request timed out after 120 seconds")
            print(f"📤 Request URL: {url}")
            print("="*80 + "\n")
            # Return OpenAI-compatible error response
            return {
                "error": {
                    "message": "Request to LMArena API timed out after 120 seconds",
                    "type": "timeout_error",
                    "code": "request_timeout"
                }
            }
        
        except Exception as e:
            print(f"\n❌ UNEXPECTED ERROR IN HTTP CLIENT")
            print(f"📛 Error type: {type(e).__name__}")
            print(f"📛 Error message: {str(e)}")
            print(f"📤 Request URL: {url}")
            print("="*80 + "\n")
            # Return OpenAI-compatible error response
            return {
                "error": {
                    "message": f"Unexpected error: {str(e)}",
                    "type": "internal_error",
                    "code": type(e).__name__.lower()
                }
            }
                
    except HTTPException:
        raise
    except Exception as e:
        print(f"\n❌ TOP-LEVEL EXCEPTION")
        print(f"📛 Error type: {type(e).__name__}")
        print(f"📛 Error message: {str(e)}")
        print("="*80 + "\n")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# ============================================================
# ANTHROPIC-COMPATIBLE API ENDPOINTS
# ============================================================
# These endpoints allow Claude Code and other Anthropic SDK clients
# to use LMArenaBridge by translating between Anthropic and OpenAI formats.

def convert_anthropic_to_openai_messages(anthropic_messages: list, system: str = None) -> list:
    """Convert Anthropic message format to OpenAI message format"""
    openai_messages = []
    
    # Add system message if present
    if system:
        openai_messages.append({"role": "system", "content": system})
    
    for msg in anthropic_messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        
        # Handle content that could be string or list of content blocks
        if isinstance(content, list):
            # Convert Anthropic content blocks to text
            text_parts = []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        text_value = block.get("text", "")
                        # Handle case where text might be a list
                        if isinstance(text_value, list):
                            text_parts.extend([str(t) for t in text_value])
                        else:
                            text_parts.append(str(text_value))
                    elif block.get("type") == "image":
                        # Handle image content if present
                        source = block.get("source", {})
                        if source.get("type") == "base64":
                            media_type = source.get("media_type", "image/png")
                            data = source.get("data", "")
                            # Convert to OpenAI image_url format
                            openai_messages.append({
                                "role": role,
                                "content": [{
                                    "type": "image_url",
                                    "image_url": {
                                        "url": f"data:{media_type};base64,{data}"
                                    }
                                }]
                            })
                            continue
                elif isinstance(block, str):
                    text_parts.append(block)
                elif isinstance(block, list):
                    # Handle nested lists
                    text_parts.extend([str(item) for item in block])
            
            if text_parts:
                final_content = "\n".join(text_parts)
                openai_messages.append({"role": role, "content": final_content})
        else:
            openai_messages.append({"role": role, "content": str(content)})
    
    return openai_messages

def convert_openai_to_anthropic_response(openai_response: dict, model: str) -> dict:
    """Convert OpenAI response format to Anthropic response format"""
    # Handle error responses
    if "error" in openai_response:
        return {
            "type": "error",
            "error": {
                "type": "api_error",
                "message": openai_response["error"].get("message", "Unknown error")
            }
        }
    
    # Extract content from OpenAI response
    choices = openai_response.get("choices", [])
    if not choices:
        return {
            "type": "error",
            "error": {
                "type": "api_error", 
                "message": "No response from model"
            }
        }
    
    message = choices[0].get("message", {})
    content_text = message.get("content", "")
    finish_reason = choices[0].get("finish_reason", "end_turn")
    
    # Map OpenAI finish reasons to Anthropic stop reasons
    stop_reason_map = {
        "stop": "end_turn",
        "length": "max_tokens",
        "content_filter": "end_turn",
        "tool_calls": "tool_use",
        None: "end_turn"
    }
    stop_reason = stop_reason_map.get(finish_reason, "end_turn")
    
    # Build Anthropic response
    return {
        "id": f"msg_{uuid.uuid4().hex[:24]}",
        "type": "message",
        "role": "assistant",
        "content": [
            {
                "type": "text",
                "text": content_text
            }
        ],
        "model": model,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {
            "input_tokens": openai_response.get("usage", {}).get("prompt_tokens", 0),
            "output_tokens": openai_response.get("usage", {}).get("completion_tokens", 0)
        }
    }

@app.post("/v1/images/generations")
@app.post("/api/v1/images/generations")
async def api_images_generations(request: Request, api_key: dict = Depends(rate_limit_api_key)):
    """
    OpenAI-compatible /v1/images/generations endpoint.
    Translates request to OpenAI chat format, calls internal endpoint, and returns image URL.
    """
    debug_print("\n" + "="*80)
    debug_print("🖼️  NEW IMAGE GENERATION REQUEST RECEIVED")
    debug_print("="*80)
    
    try:
        body = await request.json()
        prompt = body.get("prompt", "")
        model = body.get("model", "dall-e-3")
        
        if not prompt:
            raise HTTPException(status_code=400, detail="Missing 'prompt' in request body.")
            
        # Build internal OpenAI-compatible chat request
        chat_body = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False
        }
        
        # Build headers
        auth_header = request.headers.get("Authorization", "")
        internal_headers = {"Content-Type": "application/json"}
        if auth_header:
            internal_headers["Authorization"] = auth_header
            
        # Call internal chat API
        async with httpx.AsyncClient(timeout=180.0) as client:
            response = await client.post(
                f"http://localhost:{PORT}/api/v1/chat/completions",
                headers=internal_headers,
                json=chat_body
            )
            
            if response.status_code != 200:
                error_text = response.text
                debug_print(f"❌ Internal generation error: {response.status_code}")
                raise HTTPException(status_code=response.status_code, detail=f"Image generation failed: {error_text[:200]}")
                
            openai_response = response.json()
            content = openai_response.get("choices", [{}])[0].get("message", {}).get("content", "")
            
            # Extract image URL from markdown ![Alt](URL)
            import re
            img_match = re.search(r'!\[.*?\]\((.*?)\)', content)
            
            if img_match:
                img_url = img_match.group(1)
            else:
                # If no markdown, maybe it returned direct URL or raw text
                debug_print(f"⚠️ Could not find markdown image in response: {content[:100]}")
                img_url = content
                
            return {
                "created": int(time.time()),
                "data": [
                    {
                        "url": img_url
                    }
                ]
            }
            
    except Exception as e:
        debug_print(f"❌ Error in image generation wrapper: {e}")
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/jobs/media")
@app.post("/api/v1/jobs/media")
async def api_media_job_create(request: Request, background_tasks: BackgroundTasks, api_key: dict = Depends(rate_limit_api_key)):
    """
    Creates an async media generation job (Image or Video) and returns a job_id for polling.
    Useful for heavy models or platforms that timeout on synchronous requests.
    """
    debug_print("\n" + "="*80)
    debug_print("🎥 NEW ASYNC MEDIA GENERATION JOB RECEIVED")
    debug_print("="*80)
    
    try:
        body = await request.json()
        prompt = body.get("prompt", "")
        model = body.get("model", "dall-e-3")
        
        if not prompt:
            raise HTTPException(status_code=400, detail="Missing 'prompt' in request body.")
            
        job_id = f"job-{uuid.uuid4().hex}"
        media_jobs[job_id] = {
            "id": job_id,
            "status": "pending",
            "url": None,
            "error": None,
            "created_at": time.time(),
            "model": model
        }
        
        # Build headers for background task
        auth_header = request.headers.get("Authorization", "")
        
        debug_print(f"✅ Job {job_id} created for {model}. Starting background generation...")
        background_tasks.add_task(process_media_job, job_id, model, prompt, auth_header)
        
        return {"id": job_id, "status": "pending"}
    except Exception as e:
        debug_print(f"❌ Error creating media job: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def process_media_job(job_id: str, model: str, prompt: str, auth_header: str):
    """Background task to execute media generation and process the URL result."""
    try:
        chat_body = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False
        }
        internal_headers = {"Content-Type": "application/json"}
        if auth_header:
            internal_headers["Authorization"] = auth_header
            
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(
                f"http://localhost:{PORT}/api/v1/chat/completions",
                headers=internal_headers,
                json=chat_body
            )
            
            if response.status_code != 200:
                media_jobs[job_id]["status"] = "failed"
                media_jobs[job_id]["error"] = response.text[:200]
                debug_print(f"❌ Background job {job_id} failed: {response.text[:100]}")
                return
                
            openai_response = response.json()
            content = openai_response.get("choices", [{}])[0].get("message", {}).get("content", "")
            
            import re
            
            # Extract markdown wrapped URLs (either image ![alt](url) or generic link [alt](url))
            media_url = None
            url_match = re.search(r'!\[.*?\]\((.*?)\)', content)
            if not url_match:
                url_match = re.search(r'\[.*?\]\((.*?)\)', content)
                
            if url_match:
                media_url = url_match.group(1)
            else:
                # Fallback to finding raw link in text
                urls = re.findall(r'(https?://[^\s]+)', content)
                if urls:
                    media_url = urls[0]
                else:
                    media_url = content
            
            media_jobs[job_id]["status"] = "completed"
            media_jobs[job_id]["url"] = media_url
            debug_print(f"✅ Background job {job_id} completed successfully!")
            
    except Exception as e:
        media_jobs[job_id]["status"] = "failed"
        media_jobs[job_id]["error"] = str(e)
        debug_print(f"❌ Background job {job_id} encountered exception: {e}")

@app.get("/v1/jobs/media/{job_id}")
@app.get("/api/v1/jobs/media/{job_id}")
async def api_media_job_status(job_id: str, api_key: dict = Depends(rate_limit_api_key)):
    """
    Polls the status of an async media generation job by ID.
    Returns JSON containing the status ('pending', 'completed', 'failed') and 'url' if completed.
    Storage is 100% in-memory and holds only URLs - requires zero disk space.
    """
    job = media_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
        
    return job

@app.post("/v1/messages")
@app.post("/api/v1/messages")
async def anthropic_messages(request: Request, api_key: dict = Depends(rate_limit_api_key)):
    """
    Anthropic-compatible /v1/messages endpoint.
    Translates Anthropic API format to OpenAI format, calls the internal OpenAI endpoint,
    then translates the response back to Anthropic format.
    """
    debug_print("\n" + "="*80)
    debug_print("🔷 NEW ANTHROPIC API REQUEST RECEIVED")
    debug_print("="*80)
    
    try:
        # Parse request body
        try:
            body = await request.json()
        except json.JSONDecodeError as e:
            debug_print(f"❌ Invalid JSON in request body: {e}")
            raise HTTPException(status_code=400, detail=f"Invalid JSON in request body: {str(e)}")
        
        debug_print(f"📥 Anthropic request body keys: {list(body.keys())}")
        
        # Extract Anthropic-specific fields
        model = body.get("model", "")
        messages = body.get("messages", [])
        system = body.get("system", "")
        max_tokens = body.get("max_tokens", 4096)
        stream = body.get("stream", False)
        
        debug_print(f"🤖 Requested model: {model}")
        debug_print(f"💬 Number of messages: {len(messages)}")
        debug_print(f"🌊 Stream mode: {stream}")
        
        if not model:
            raise HTTPException(status_code=400, detail="Missing 'model' in request body.")
        
        if not messages:
            raise HTTPException(status_code=400, detail="Missing 'messages' in request body.")
        
        # Convert Anthropic messages to OpenAI format
        openai_messages = convert_anthropic_to_openai_messages(messages, system)
        debug_print(f"🔄 Converted to {len(openai_messages)} OpenAI messages")
        
        # Build OpenAI-compatible request
        openai_body = {
            "model": model,
            "messages": openai_messages,
            "max_tokens": max_tokens,
            "stream": stream
        }
        
        # Get auth headers from the original request (support both Authorization and x-api-key)
        auth_header = request.headers.get("Authorization", "")
        x_api_key = request.headers.get("x-api-key", "")
        
        # Build headers for internal request
        internal_headers = {"Content-Type": "application/json"}
        if auth_header:
            internal_headers["Authorization"] = auth_header
        if x_api_key:
            internal_headers["x-api-key"] = x_api_key
        
        # Call the internal OpenAI endpoint
        debug_print(f"🔀 Forwarding to internal OpenAI endpoint...")
        
        if stream:
            # For streaming, we need to forward the stream and translate it
            async def anthropic_stream_generator():
                try:
                    async with httpx.AsyncClient(timeout=180.0) as client:
                        async with client.stream(
                            "POST",
                            f"http://localhost:{PORT}/api/v1/chat/completions",
                            headers=internal_headers,
                            json=openai_body
                        ) as response:
                            if response.status_code != 200:
                                error_text = await response.aread()
                                debug_print(f"❌ Internal OpenAI endpoint error: {response.status_code}")
                                error_event = {
                                    "type": "error",
                                    "error": {
                                        "type": "api_error",
                                        "message": error_text.decode()[:500]
                                    }
                                }
                                yield f"event: error\ndata: {json.dumps(error_event)}\n\n"
                                return
                            
                            # Send Anthropic message_start event
                            msg_id = f"msg_{uuid.uuid4().hex[:24]}"
                            start_event = {
                                "type": "message_start",
                                "message": {
                                    "id": msg_id,
                                    "type": "message",
                                    "role": "assistant",
                                    "content": [],
                                    "model": model,
                                    "stop_reason": None,
                                    "stop_sequence": None,
                                    "usage": {"input_tokens": 0, "output_tokens": 0}
                                }
                            }
                            yield f"event: message_start\ndata: {json.dumps(start_event)}\n\n"
                            
                            # Send content_block_start
                            block_start = {
                                "type": "content_block_start",
                                "index": 0,
                                "content_block": {"type": "text", "text": ""}
                            }
                            yield f"event: content_block_start\ndata: {json.dumps(block_start)}\n\n"
                            
                            output_tokens = 0
                            async for line in response.aiter_lines():
                                if not line:
                                    continue
                                
                                # OpenAI SSE format: data: {...}
                                if line.startswith("data: "):
                                    data_str = line[6:]
                                    if data_str == "[DONE]":
                                        break
                                    
                                    try:
                                        chunk = json.loads(data_str)
                                        # Extract content delta
                                        choices = chunk.get("choices", [])
                                        if choices:
                                            delta = choices[0].get("delta", {})
                                            content = delta.get("content", "")
                                            if content:
                                                output_tokens += 1
                                                # Send content_block_delta
                                                delta_event = {
                                                    "type": "content_block_delta",
                                                    "index": 0,
                                                    "delta": {"type": "text_delta", "text": content}
                                                }
                                                yield f"event: content_block_delta\ndata: {json.dumps(delta_event)}\n\n"
                                    except json.JSONDecodeError:
                                        pass
                            
                            # Send content_block_stop
                            yield f"event: content_block_stop\ndata: {{\"type\": \"content_block_stop\", \"index\": 0}}\n\n"
                            
                            # Send message_delta
                            message_delta = {
                                "type": "message_delta",
                                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                                "usage": {"output_tokens": output_tokens}
                            }
                            yield f"event: message_delta\ndata: {json.dumps(message_delta)}\n\n"
                            
                            # Send message_stop
                            yield f"event: message_stop\ndata: {{\"type\": \"message_stop\"}}\n\n"
                            
                except Exception as e:
                    debug_print(f"❌ Streaming error: {e}")
                    error_event = {
                        "type": "error",
                        "error": {"type": "api_error", "message": str(e)}
                    }
                    yield f"event: error\ndata: {json.dumps(error_event)}\n\n"
            
            return StreamingResponse(
                anthropic_stream_generator(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "X-Accel-Buffering": "no"
                }
            )
        
        else:
            # Non-streaming - call internal endpoint and convert response
            try:
                async with httpx.AsyncClient(timeout=180.0) as client:
                    response = await client.post(
                        f"http://localhost:{PORT}/api/v1/chat/completions",
                        headers=internal_headers,
                        json=openai_body
                    )
                    
                    if response.status_code != 200:
                        debug_print(f"❌ Internal OpenAI endpoint error: {response.status_code}")
                        raise HTTPException(
                            status_code=response.status_code,
                            detail=response.text[:500]
                        )
                    
                    openai_response = response.json()
                    debug_print(f"✅ Got OpenAI response, converting to Anthropic format...")
                    
                    # Convert to Anthropic format
                    anthropic_response = convert_openai_to_anthropic_response(openai_response, model)
                    return anthropic_response
                    
            except httpx.TimeoutException:
                raise HTTPException(status_code=504, detail="Request timed out")
            except httpx.HTTPError as e:
                raise HTTPException(status_code=502, detail=f"Internal request failed: {str(e)}")
    
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"❌ Anthropic endpoint error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 LMArena Bridge Server Starting...")
    print("=" * 60)
    print(f"📍 Dashboard: http://localhost:{PORT}/dashboard")
    print(f"🔐 Login:     http://localhost:{PORT}/dash/login")
    print(f"📚 API Base URL: http://localhost:{PORT}/v1")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=PORT)
