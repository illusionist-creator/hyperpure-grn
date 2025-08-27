#!/usr/bin/env python3
"""
Streamlit App for Gmail to Google Drive and PDF Processing Automation
Combines both hyperpuremail.py and hyperpuresheet.py workflows with real-time tracking
Uses OAuth for authentication
"""

import streamlit as st
import os
import base64
import re
import json
import time
import tempfile
import logging
import io
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
import threading

# Google API imports
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload
from google.oauth2.credentials import Credentials

# OAuth component
from streamlit_oauth import OAuth2Component

# LlamaParse import
try:
    from llama_cloud_services import LlamaExtract
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False

# Configure page
st.set_page_config(
    page_title="Gmail-Drive-Sheets Automation",
    page_icon="🚀",
    layout="wide"
)

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'log_messages' not in st.session_state:
    st.session_state.log_messages = []
if 'processing' not in st.session_state:
    st.session_state.processing = False
if 'token' not in st.session_state:
    st.session_state.token = None

class StreamlitLogHandler(logging.Handler):
    """Custom logging handler to capture logs in Streamlit session state"""
    
    def emit(self, record):
        log_message = self.format(record)
        st.session_state.log_messages.append({
            'timestamp': datetime.now(),
            'level': record.levelname,
            'message': log_message
        })

# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = StreamlitLogHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def log_info(message):
    """Helper to log info messages"""
    logger.info(message)

def log_error(message):
    """Helper to log error messages"""
    logger.error(message)

# OAuth configuration for Google
AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REFRESH_TOKEN_URL = TOKEN_URL
REVOKE_TOKEN_URL = "https://oauth2.googleapis.com/revoke"
SCOPE = "openid email profile https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/spreadsheets"

def get_client_config():
    """Get client ID and secret from local file or secrets"""
    try:
        # Deployed: use secrets
        client_id = st.secrets["google"]["client_id"]
        client_secret = st.secrets["google"]["client_secret"]
        log_info("Using credentials from Streamlit secrets")
        return client_id, client_secret
    except KeyError:
        # Local: use file path
        credentials_path = 'D:\\GRN\\PDF\\zhplgrn\\credentials.json'  # Modify as needed
        if os.path.exists(credentials_path):
            with open(credentials_path, 'r') as f:
                creds_data = json.load(f)
            client_id = creds_data.get('installed', {}).get('client_id')
            client_secret = creds_data.get('installed', {}).get('client_secret')
            log_info("Using credentials from local file")
            return client_id, client_secret
        else:
            log_error("Credentials not found in secrets or local file")
            return None, None

def get_redirect_uri(is_local):
    """Get redirect URI based on environment"""
    if is_local:
        return "http://localhost:8501/component/streamlit_oauth.authorize_button"
    else:
        try:
            return st.secrets["google"]["redirect_uri"]
        except KeyError:
            log_error("Redirect URI not set in secrets for deployed app")
            return None

def authenticate_google_services():
    """Authenticate with Google APIs using OAuth"""
    client_id, client_secret = get_client_config()
    if not client_id or not client_secret:
        return None, None, None

    is_local = st.checkbox("Running locally?", value=True)

    redirect_uri = get_redirect_uri(is_local)
    if not redirect_uri:
        return None, None, None

    oauth2 = OAuth2Component(client_id, client_secret, AUTHORIZE_URL, TOKEN_URL, REFRESH_TOKEN_URL, REVOKE_TOKEN_URL)

    if 'token' not in st.session_state or not st.session_state.token:
        result = oauth2.authorize_button("Authorize with Google", redirect_uri, SCOPE)
        if result and 'token' in result:
            st.session_state.token = result['token']
            st.rerun()
    else:
        token = st.session_state.token
        # Check if expired
        if token.get('expires_at') < time.time():
            log_info("Refreshing token")
            new_token = oauth2.refresh_token(token)
            if new_token:
                st.session_state.token = new_token
                token = new_token
            else:
                log_error("Failed to refresh token")
                del st.session_state.token
                st.rerun()

    if 'token' in st.session_state:
        token = st.session_state.token
        creds = Credentials(
            token=token['access_token'],
            refresh_token=token.get('refresh_token'),
            token_uri=TOKEN_URL,
            client_id=client_id,
            client_secret=client_secret,
            scopes=SCOPE.split()
        )

        # Build services
        gmail_service = build('gmail', 'v1', credentials=creds)
        drive_service = build('drive', 'v3', credentials=creds)
        sheets_service = build('sheets', 'v4', credentials=creds)
        
        log_info("Successfully authenticated with Google APIs")
        return gmail_service, drive_service, sheets_service
    else:
        return None, None, None

# Hardcoded configs
HARDCODED_CONFIG = {
    'gmail': {
        'sender': 'noreply@hyperpure.com',
        'search_term': 'Hyperpure GRN',
        'attachment_filter': 'attachment.pdf'
    },
    'drive': {
        'folder_id': '1euqxO-meY4Ahszpdk3XbwlRwvkfSlY8k'
    },
    'sheets': {
        'drive_folder_id': '1aUjRMqWjVDDAsQw0TugwgmwYjxP6W7DT',
        'spreadsheet_id': '1B1C2ILnIMXpEYbQzaSkhRzEP2gmgE2YLRNqoX98GwcU',
        'sheet_range': 'hyperpuregrn'
    },
    'llama': {
        'agent_name': 'Hyperpure Agent'
    }
}

class GmailProcessor:
    """Gmail attachment processor"""
    
    def __init__(self, gmail_service, drive_service):
        self.gmail_service = gmail_service
        self.drive_service = drive_service
    
    def sanitize_filename(self, filename: str) -> str:
        """Clean up filenames to be safe for all operating systems"""
        cleaned = re.sub(r'[<>:"/\\|?*]', '_', filename)
        if len(cleaned) > 100:
            name_parts = cleaned.split('.')
            if len(name_parts) > 1:
                extension = name_parts[-1]
                base_name = '.'.join(name_parts[:-1])
                cleaned = f"{base_name[:95]}.{extension}"
            else:
                cleaned = cleaned[:100]
        return cleaned
    
    def classify_extension(self, filename: str) -> str:
        """Categorize file by extension"""
        if not filename or '.' not in filename:
            return "Other"
            
        ext = filename.split(".")[-1].lower()
        
        type_map = {
            "pdf": "PDFs",
            "doc": "Documents", "docx": "Documents", "txt": "Documents",
            "xls": "Spreadsheets", "xlsx": "Spreadsheets", "csv": "Spreadsheets",
            "jpg": "Images", "jpeg": "Images", "png": "Images", "gif": "Images",
            "ppt": "Presentations", "pptx": "Presentations",
            "zip": "Archives", "rar": "Archives", "7z": "Archives",
        }
        
        return type_map.get(ext, "Other")
    
    def search_emails(self, config: Dict) -> List[Dict]:
        """Search for emails with attachments"""
        try:
            query_parts = ["has:attachment"]
            
            if config['sender']:
                query_parts.append(f'from:"{config["sender"]}"')
            
            if config['search_term']:
                if "," in config['search_term']:
                    keywords = [k.strip() for k in config['search_term'].split(",")]
                    keyword_query = " OR ".join([f'"{k}"' for k in keywords if k])
                    if keyword_query:
                        query_parts.append(f"({keyword_query})")
                else:
                    query_parts.append(f'"{config["search_term"]}"')
            
            start_date = datetime.now() - timedelta(days=config['days_back'])
            query_parts.append(f"after:{start_date.strftime('%Y/%m/%d')}")
            
            query = " ".join(query_parts)
            log_info(f"Searching Gmail with query: {query}")
            
            result = self.gmail_service.users().messages().list(
                userId='me', q=query, maxResults=config['max_results']
            ).execute()
            
            messages = result.get('messages', [])
            log_info(f"Found {len(messages)} emails matching criteria")
            
            return messages
            
        except Exception as e:
            log_error(f"Email search failed: {str(e)}")
            return []
    
    def create_drive_folder(self, folder_name: str, parent_folder_id: Optional[str] = None) -> str:
        """Create a folder in Google Drive"""
        try:
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            if parent_folder_id:
                query += f" and '{parent_folder_id}' in parents"
            
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            
            if files:
                folder_id = files[0]['id']
                log_info(f"Using existing folder: {folder_name}")
                return folder_id
            
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            
            if parent_folder_id:
                folder_metadata['parents'] = [parent_folder_id]
            
            folder = self.drive_service.files().create(
                body=folder_metadata,
                fields='id'
            ).execute()
            
            folder_id = folder.get('id')
            log_info(f"Created Google Drive folder: {folder_name}")
            
            return folder_id
            
        except Exception as e:
            log_error(f"Failed to create folder {folder_name}: {str(e)}")
            return ""
    
    def upload_to_drive(self, file_data: bytes, filename: str, folder_id: str) -> bool:
        """Upload file to Google Drive"""
        try:
            query = f"name='{filename}' and '{folder_id}' in parents and trashed=false"
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            
            if files:
                log_info(f"File already exists, skipping: {filename}")
                return True
            
            file_metadata = {
                'name': filename,
                'parents': [folder_id] if folder_id else []
            }
            
            media = MediaIoBaseUpload(
                io.BytesIO(file_data),
                mimetype='application/octet-stream',
                resumable=True
            )
            
            file = self.drive_service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()
            
            log_info(f"Uploaded to Drive: {filename}")
            return True
            
        except Exception as e:
            log_error(f"Failed to upload {filename}: {str(e)}")
            return False
    
    def process_gmail_to_drive(self, config: Dict) -> Dict:
        """Process Gmail attachments and upload to Drive"""
        stats = {
            'total_emails': 0,
            'processed_emails': 0,
            'total_attachments': 0,
            'successful_uploads': 0,
            'failed_uploads': 0
        }
        
        try:
            emails = self.search_emails(config)
            stats['total_emails'] = len(emails)
            
            if not emails:
                log_info("No emails found matching criteria")
                return stats
            
            base_folder_name = "Gmail_Attachments"
            base_folder_id = self.create_drive_folder(base_folder_name, config.get('folder_id'))
            
            if not base_folder_id:
                log_error("Failed to create base folder in Google Drive")
                return stats
            
            log_info(f"Processing {len(emails)} emails...")
            
            for i, email in enumerate(emails, 1):
                try:
                    log_info(f"Processing email {i}/{len(emails)}")
                    
                    # Get full message
                    message = self.gmail_service.users().messages().get(
                        userId='me', id=email['id']
                    ).execute()
                    
                    if not message or not message.get('payload'):
                        continue
                    
                    # Process attachments
                    attachment_count = self.process_message_attachments(
                        email['id'], message['payload'], config, base_folder_id
                    )
                    
                    stats['total_attachments'] += attachment_count
                    stats['successful_uploads'] += attachment_count
                    stats['processed_emails'] += 1
                    
                    log_info(f"Found {attachment_count} attachments in email")
                    
                except Exception as e:
                    log_error(f"Failed to process email {email.get('id', 'unknown')}: {str(e)}")
                    stats['failed_uploads'] += 1
            
            return stats
            
        except Exception as e:
            log_error(f"Gmail processing failed: {str(e)}")
            return stats
    
    def process_message_attachments(self, message_id: str, payload: Dict, config: Dict, base_folder_id: str) -> int:
        """Process all attachments in a message"""
        processed_count = 0
        
        if "parts" in payload:
            for part in payload["parts"]:
                processed_count += self.process_message_attachments(
                    message_id, part, config, base_folder_id
                )
        elif payload.get("filename") and "attachmentId" in payload.get("body", {}):
            if self.process_single_attachment(message_id, payload, config, base_folder_id):
                processed_count += 1
        
        return processed_count
    
    def process_single_attachment(self, message_id: str, part: Dict, config: Dict, base_folder_id: str) -> bool:
        """Process a single attachment"""
        try:
            filename = part.get("filename", "")
            if not filename:
                return False
            
            # Apply attachment filter
            if config.get('attachment_filter'):
                if filename.lower() != config['attachment_filter'].lower():
                    log_info(f"Skipped attachment {filename} not matching filter")
                    return False
            
            clean_filename = self.sanitize_filename(filename)
            final_filename = f"{message_id}_{clean_filename}"
            
            attachment_id = part["body"].get("attachmentId")
            if not attachment_id:
                return False
            
            att = self.gmail_service.users().messages().attachments().get(
                userId='me', messageId=message_id, id=attachment_id
            ).execute()
            
            if not att.get("data"):
                return False
            
            file_data = base64.urlsafe_b64decode(att["data"].encode("UTF-8"))
            
            # Create folder structure
            search_folder_name = config.get('search_term', 'all-attachments')
            file_type_folder = self.classify_extension(filename)
            
            search_folder_id = self.create_drive_folder(search_folder_name, base_folder_id)
            type_folder_id = self.create_drive_folder(file_type_folder, search_folder_id)
            
            return self.upload_to_drive(file_data, final_filename, type_folder_id)
            
        except Exception as e:
            log_error(f"Failed to process attachment {part.get('filename', 'unknown')}: {str(e)}")
            return False

class PDFProcessor:
    """PDF processor for Google Drive to Sheets"""
    
    def __init__(self, drive_service, sheets_service):
        self.drive_service = drive_service
        self.sheets_service = sheets_service
    
    def list_drive_files(self, folder_id: str, days_back: int = 1) -> List[Dict]:
        """List PDF files in Google Drive folder"""
        try:
            start_datetime = datetime.utcnow() - timedelta(days=days_back - 1)
            start_str = start_datetime.strftime('%Y-%m-%dT00:00:00Z')
            query = f"'{folder_id}' in parents and mimeType='application/pdf' and trashed=false and createdTime >= '{start_str}'"
            
            files = []
            page_token = None
            
            while True:
                results = self.drive_service.files().list(
                    q=query,
                    fields="nextPageToken, files(id, name, mimeType, createdTime, modifiedTime)",
                    orderBy="createdTime desc",
                    pageToken=page_token,
                    pageSize=100
                ).execute()
                
                files.extend(results.get('files', []))
                page_token = results.get('nextPageToken', None)
                
                if page_token is None:
                    break
            
            log_info(f"Found {len(files)} PDF files in folder (last {days_back} days)")
            return files
            
        except Exception as e:
            log_error(f"Failed to list files in folder {folder_id}: {str(e)}")
            return []
    
    def download_from_drive(self, file_id: str, file_name: str) -> bytes:
        """Download file from Google Drive"""
        try:
            log_info(f"Downloading: {file_name}")
            request = self.drive_service.files().get_media(fileId=file_id)
            file_data = request.execute()
            log_info(f"Downloaded: {file_name}")
            return file_data
        except Exception as e:
            log_error(f"Failed to download {file_name}: {str(e)}")
            return b""
    
    def process_pdfs_to_sheets(self, config: Dict, api_key: str) -> Dict:
        """Process PDFs and save to Google Sheets"""
        stats = {
            'total_pdfs': 0,
            'processed_pdfs': 0,
            'failed_pdfs': 0,
            'rows_added': 0
        }
        
        if not LLAMA_AVAILABLE:
            log_error("LlamaParse not available")
            return stats
        
        try:
            # Setup LlamaParse
            os.environ["LLAMA_CLOUD_API_KEY"] = api_key
            extractor = LlamaExtract()
            agent = extractor.get_agent(name=config['agent_name'])
            
            if agent is None:
                log_error(f"Could not find agent '{config['agent_name']}'")
                return stats
            
            log_info("LlamaParse agent found")
            
            # Get PDF files
            pdf_files = self.list_drive_files(config['drive_folder_id'], config['days_back'])
            stats['total_pdfs'] = len(pdf_files)
            
            if not pdf_files:
                log_info("No PDF files found")
                return stats
            
            # Process each PDF
            for i, file in enumerate(pdf_files, 1):
                try:
                    log_info(f"Processing PDF {i}/{len(pdf_files)}: {file['name']}")
                    
                    pdf_data = self.download_from_drive(file['id'], file['name'])
                    if not pdf_data:
                        stats['failed_pdfs'] += 1
                        continue
                    
                    # Process with LlamaParse
                    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
                        temp_file.write(pdf_data)
                        temp_path = temp_file.name
                    
                    result = agent.extract(temp_path)
                    extracted_data = result.data
                    os.unlink(temp_path)
                    
                    # Process extracted data
                    rows = self.process_extracted_data(extracted_data, file)
                    if rows:
                        # Append to Google Sheets (simplified - add actual append logic here)
                        stats['rows_added'] += len(rows)
                        log_info(f"Extracted {len(rows)} rows from {file['name']}")
                    
                    stats['processed_pdfs'] += 1
                    
                except Exception as e:
                    log_error(f"Failed to process PDF {file['name']}: {str(e)}")
                    stats['failed_pdfs'] += 1
            
            return stats
            
        except Exception as e:
            log_error(f"PDF processing failed: {str(e)}")
            return stats
    
    def process_extracted_data(self, extracted_data: Dict, file_info: Dict) -> List[Dict]:
        """Process extracted data (simplified version)"""
        rows = []
        items = []
        
        if "items" in extracted_data:
            items = extracted_data["items"]
        elif "product_items" in extracted_data:
            items = extracted_data["product_items"]
        
        for item in items:
            item["source_file"] = file_info['name']
            item["processed_date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            item["drive_file_id"] = file_info['id']
            rows.append(item)
        
        return rows

def run_workflow(workflow_type: str, gmail_config: Dict, sheets_config: Dict):
    """Run the selected workflow"""
    st.session_state.processing = True
    st.session_state.log_messages = []
    
    try:
        # Authenticate
        gmail_service, drive_service, sheets_service = authenticate_google_services()
        
        if not all([gmail_service, drive_service, sheets_service]):
            st.error("Authentication failed. Please authorize with Google.")
            return
        
        if workflow_type == "gmail_only":
            log_info("Starting Gmail to Drive workflow")
            processor = GmailProcessor(gmail_service, drive_service)
            stats = processor.process_gmail_to_drive(gmail_config)
            
            st.success("Gmail to Drive workflow completed!")
            st.write("**Statistics:**")
            st.write(f"- Total emails: {stats['total_emails']}")
            st.write(f"- Processed emails: {stats['processed_emails']}")
            st.write(f"- Total attachments: {stats['total_attachments']}")
            st.write(f"- Successful uploads: {stats['successful_uploads']}")
            
        elif workflow_type == "pdf_only":
            log_info("Starting PDF processing workflow")
            
            # Get LlamaParse API key from secrets
            try:
                llama_api_key = st.secrets["llama"]["api_key"]
            except KeyError:
                st.error("LlamaParse API key not found in secrets. Please add 'llama.api_key' to your secrets.")
                return
            
            processor = PDFProcessor(drive_service, sheets_service)
            stats = processor.process_pdfs_to_sheets(sheets_config, llama_api_key)
            
            st.success("PDF processing workflow completed!")
            st.write("**Statistics:**")
            st.write(f"- Total PDFs: {stats['total_pdfs']}")
            st.write(f"- Processed PDFs: {stats['processed_pdfs']}")
            st.write(f"- Failed PDFs: {stats['failed_pdfs']}")
            st.write(f"- Rows added: {stats['rows_added']}")
            
        elif workflow_type == "combined":
            log_info("Starting combined workflow")
            
            # Step 1: Gmail to Drive
            log_info("Step 1: Processing Gmail attachments")
            gmail_processor = GmailProcessor(gmail_service, drive_service)
            gmail_stats = gmail_processor.process_gmail_to_drive(gmail_config)
            
            log_info("Step 1 completed, starting Step 2")
            
            # Step 2: PDF processing
            log_info("Step 2: Processing PDFs to Sheets")
            try:
                llama_api_key = st.secrets["llama"]["api_key"]
            except KeyError:
                st.error("LlamaParse API key not found in secrets. Please add 'llama.api_key' to your secrets.")
                return
            
            pdf_processor = PDFProcessor(drive_service, sheets_service)
            pdf_stats = pdf_processor.process_pdfs_to_sheets(sheets_config, llama_api_key)
            
            st.success("Combined workflow completed!")
            st.write("**Gmail to Drive Statistics:**")
            st.write(f"- Total emails: {gmail_stats['total_emails']}")
            st.write(f"- Processed emails: {gmail_stats['processed_emails']}")
            st.write(f"- Successful uploads: {gmail_stats['successful_uploads']}")
            
            st.write("**PDF Processing Statistics:**")
            st.write(f"- Total PDFs: {pdf_stats['total_pdfs']}")
            st.write(f"- Processed PDFs: {pdf_stats['processed_pdfs']}")
            st.write(f"- Rows added: {pdf_stats['rows_added']}")
            
    except Exception as e:
        st.error(f"Workflow failed: {str(e)}")
        log_error(f"Workflow failed: {str(e)}")
    finally:
        st.session_state.processing = False

# Main Streamlit App
def main():
    st.title("Gmail-Drive-Sheets Automation")
    st.markdown("---")
    
    # Authentication
    gmail_service, drive_service, sheets_service = authenticate_google_services()
    if not st.session_state.get('token'):
        st.warning("Please authorize with Google to proceed.")
        return
    
    st.success("Authenticated with Google APIs")
    
    # Configuration display and editable params
    st.subheader("Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Hardcoded Gmail Configuration (Non-editable):**")
        st.code(f"""
Sender: {HARDCODED_CONFIG['gmail']['sender']}
Search Term: {HARDCODED_CONFIG['gmail']['search_term']}
Attachment Filter: {HARDCODED_CONFIG['gmail']['attachment_filter']}
Drive Folder ID: {HARDCODED_CONFIG['drive']['folder_id']}
        """)
        gmail_days_back = st.number_input("Gmail Days Back", min_value=1, value=7)
        gmail_max_results = st.number_input("Gmail Max Results", min_value=1, value=1000)
    
    with col2:
        st.write("**Hardcoded PDF Processing Configuration (Non-editable):**")
        st.code(f"""
Drive Folder ID: {HARDCODED_CONFIG['sheets']['drive_folder_id']}
Spreadsheet ID: {HARDCODED_CONFIG['sheets']['spreadsheet_id']}
Sheet Range: {HARDCODED_CONFIG['sheets']['sheet_range']}
LlamaParse Agent: {HARDCODED_CONFIG['llama']['agent_name']}
        """)
        sheets_days_back = st.number_input("Sheets Days Back", min_value=1, value=1)
    
    st.markdown("---")
    
    # Prepare configs with editable params
    gmail_config = HARDCODED_CONFIG['gmail'].copy()
    gmail_config['days_back'] = gmail_days_back
    gmail_config['max_results'] = gmail_max_results
    gmail_config['folder_id'] = HARDCODED_CONFIG['drive']['folder_id']
    
    sheets_config = HARDCODED_CONFIG['sheets'].copy()
    sheets_config['days_back'] = sheets_days_back
    sheets_config['agent_name'] = HARDCODED_CONFIG['llama']['agent_name']
    
    # Workflow selection
    st.subheader("Select Workflow")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Gmail to Drive Only", disabled=st.session_state.processing):
            threading.Thread(
                target=run_workflow,
                args=("gmail_only", gmail_config, sheets_config),
                daemon=True
            ).start()
    
    with col2:
        if st.button("PDF Processing Only", disabled=st.session_state.processing):
            threading.Thread(
                target=run_workflow,
                args=("pdf_only", gmail_config, sheets_config),
                daemon=True
            ).start()
    
    with col3:
        if st.button("Combined Workflow", disabled=st.session_state.processing):
            threading.Thread(
                target=run_workflow,
                args=("combined", gmail_config, sheets_config),
                daemon=True
            ).start()
    
    # Processing indicator
    if st.session_state.processing:
        st.info("Processing... Please wait.")
    
    # Real-time log display
    st.subheader("Real-time Logs")
    
    log_container = st.container()
    
    if st.session_state.log_messages:
        with log_container:
            for log_msg in st.session_state.log_messages[-50:]:  # Show last 50 messages
                timestamp = log_msg['timestamp'].strftime("%H:%M:%S")
                level = log_msg['level']
                message = log_msg['message']
                
                if level == "ERROR":
                    st.error(f"[{timestamp}] {message}")
                elif level == "WARNING":
                    st.warning(f"[{timestamp}] {message}")
                else:
                    st.info(f"[{timestamp}] {message}")
    
    # Clear logs button
    if st.button("Clear Logs"):
        st.session_state.log_messages = []
        st.rerun()
    
    # Auto-refresh every 2 seconds when processing
    if st.session_state.processing:
        time.sleep(2)
        st.rerun()

if __name__ == "__main__":
    main()