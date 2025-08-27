#!/usr/bin/env python3
"""
Zepto Google Drive PDF Processor with LlamaParse to Google Sheets
Processes PDFs from Google Drive with LlamaParse and appends data to Google Sheets
Uses the extraction logic from ZeptoAgent with OAuth2 authentication
"""

import os
import json
import time
import logging
import tempfile
import ssl
import socket
from typing import List, Dict, Any
from datetime import datetime, timedelta

from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# Add LlamaParse import
try:
    from llama_cloud_services import LlamaExtract
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False
    print("LlamaParse not available. Install with: pip install llama-cloud-services")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('zepto_drive_processor.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ZeptoDriveProcessor:
    def __init__(self, credentials_path: str):
        """
        Initialize the PDF processor
        
        Args:
            credentials_path: Path to the Google credentials JSON file
        """
        self.credentials_path = credentials_path
        self.drive_service = None
        self.sheets_service = None
        
        # API scopes
        self.drive_scopes = ['https://www.googleapis.com/auth/drive.readonly']
        self.sheets_scopes = ['https://www.googleapis.com/auth/spreadsheets']
        
    def test_network_connection(self) -> bool:
        """Test network and SSL connectivity to Google APIs"""
        try:
            socket.create_connection(("www.google.com", 443), timeout=10)
            print("✅ Basic network connectivity test passed")
            
            context = ssl.create_default_context()
            with socket.create_connection(("www.google.com", 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname="www.google.com") as ssock:
                    print("✅ SSL handshake successful")
            return True
        except Exception as e:
            print(f"❌ Network connectivity test failed: {str(e)}")
            logger.error(f"[NETWORK] Connection test failed: {str(e)}")
            return False
    
    def authenticate(self):
        """Authenticate with Google Drive and Google Sheets APIs"""
        if not self.test_network_connection():
            return False
            
        try:
            with open(self.credentials_path, 'r') as f:
                creds_data = json.load(f)
            
            if 'type' in creds_data and creds_data['type'] == 'service_account':
                print("🔑 Using service account authentication")
                credentials = service_account.Credentials.from_service_account_file(
                    self.credentials_path,
                    scopes=self.drive_scopes + self.sheets_scopes
                )
                self.drive_service = self._build_service_with_retry('drive', 'v3', credentials)
                self.sheets_service = self._build_service_with_retry('sheets', 'v4', credentials)
            else:
                print("🔑 Using OAuth2 authentication")
                combined_scopes = self.drive_scopes + self.sheets_scopes
                creds = self._oauth2_authenticate(combined_scopes, 'combined')
                self.drive_service = self._build_service_with_retry('drive', 'v3', creds)
                self.sheets_service = self._build_service_with_retry('sheets', 'v4', creds)
            
            if self.drive_service and self.sheets_service:
                logger.info("[SUCCESS] Successfully authenticated with Google Drive and Sheets")
                print("✅ Authentication successful")
                return True
            else:
                logger.error("[ERROR] Failed to build one or more services")
                print("❌ Failed to build one or more services")
                return False
        except Exception as e:
            logger.error(f"[ERROR] Authentication failed: {str(e)}")
            print(f"❌ Authentication failed: {str(e)}")
            return False
    
    def _build_service_with_retry(self, service_name: str, version: str, credentials, max_retries: int = 3) -> Any:
        """Build service with retry mechanism for network issues"""
        for attempt in range(1, max_retries + 1):
            try:
                service = build(service_name, version, credentials=credentials)
                print(f"✅ Successfully built {service_name} service")
                return service
            except Exception as e:
                if attempt < max_retries:
                    print(f"⚠️ Failed to build {service_name} service (attempt {attempt}/{max_retries}): {str(e)}")
                    time.sleep(2)
                else:
                    print(f"❌ Failed to build {service_name} service after {max_retries} attempts: {str(e)}")
                    logger.error(f"[ERROR] Failed to build {service_name} service: {str(e)}")
                    return None
    
    def _oauth2_authenticate(self, scopes: List[str], service_name: str) -> Credentials:
        """Handle OAuth2 authentication flow"""
        creds = None
        token_file = f'token_{service_name}.json'
        
        if os.path.exists(token_file):
            try:
                creds = Credentials.from_authorized_user_file(token_file, scopes)
                print("✅ Loaded existing OAuth2 token")
            except Exception as e:
                print(f"⚠️ Error loading token file: {str(e)}")
                creds = None
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    print("✅ Refreshed OAuth2 token")
                except Exception as e:
                    print(f"⚠️ Token refresh failed: {str(e)}")
                    creds = None
            
            if not creds:
                try:
                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.credentials_path, scopes)
                    creds = flow.run_local_server(port=0)
                    print("✅ Completed OAuth2 authentication flow")
                except Exception as e:
                    print(f"❌ OAuth flow failed: {str(e)}")
                    raise
            
            try:
                with open(token_file, 'w') as token:
                    token.write(creds.to_json())
                print("✅ Saved OAuth2 token for future use")
            except Exception as e:
                print(f"⚠️ Failed to save token: {str(e)}")
        
        return creds
    
    def list_drive_files(self, folder_id: str, days_back: int = 1) -> List[Dict]:
        """List all PDF files in a Google Drive folder filtered by creation date"""
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

            print(f"📂 Found {len(files)} PDF files in folder (last {days_back} days)")
            logger.info(f"[DRIVE] Found {len(files)} PDF files in folder {folder_id} (last {days_back} days)")
            
            for file in files:
                print(f"   - {file['name']}")
                logger.info(f"[DRIVE] Found file: {file['name']} (ID: {file['id']})")
            
            return files
        except Exception as e:
            print(f"❌ Failed to list files: {str(e)}")
            logger.error(f"[ERROR] Failed to list files in folder {folder_id}: {str(e)}")
            return []
    
    def download_from_drive(self, file_id: str, file_name: str) -> bytes:
        """Download a file from Google Drive"""
        try:
            print(f"⬇️ Downloading: {file_name}")
            request = self.drive_service.files().get_media(fileId=file_id)
            file_data = request.execute()
            print(f"✅ Downloaded: {file_name}")
            return file_data
        except Exception as e:
            print(f"❌ Failed to download {file_name}: {str(e)}")
            logger.error(f"[ERROR] Failed to download file {file_name}: {str(e)}")
            return b""
    
    def append_to_google_sheet(self, spreadsheet_id: str, range_name: str, values: List[List[Any]]) -> bool:
        """Append data to a Google Sheet with retry mechanism"""
        max_retries = 3
        wait_time = 2
        
        for attempt in range(1, max_retries + 1):
            try:
                body = {'values': values}
                result = self.sheets_service.spreadsheets().values().append(
                    spreadsheetId=spreadsheet_id, 
                    range=range_name,
                    valueInputOption='USER_ENTERED', 
                    body=body
                ).execute()
                
                updated_cells = result.get('updates', {}).get('updatedCells', 0)
                print(f"💾 Appended {updated_cells} cells to Google Sheet")
                logger.info(f"[SHEETS] Appended {updated_cells} cells to Google Sheet")
                return True
            except Exception as e:
                if attempt < max_retries:
                    print(f"⚠️ Failed to append to Google Sheet (attempt {attempt}/{max_retries}): {str(e)}")
                    logger.warning(f"[SHEETS] Attempt {attempt} failed: {str(e)}")
                    time.sleep(wait_time)
                else:
                    print(f"❌ Failed to append to Google Sheet after {max_retries} attempts: {str(e)}")
                    logger.error(f"[ERROR] Failed to append to Google Sheet: {str(e)}")
                    return False
        return False
    
    def get_sheet_headers(self, spreadsheet_id: str, sheet_name: str) -> List[str]:
        """Get existing headers from Google Sheet"""
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A1:Z1",
                majorDimension="ROWS"
            ).execute()
            values = result.get('values', [])
            return values[0] if values else []
        except Exception as e:
            print(f"ℹ️ No existing headers found or error: {str(e)}")
            logger.info(f"[SHEETS] No existing headers or error: {str(e)}")
            return []
    
    def get_value(self, data, possible_keys, default=""):
        """Return the first found key value from dict."""
        for key in possible_keys:
            if key in data:
                return data[key]
        return default
    
    def safe_extract(self, agent, file_path: str, retries: int = 3, wait_time: int = 2):
        """Retry-safe extraction to handle server disconnections"""
        for attempt in range(1, retries + 1):
            try:
                print(f"🔍 Extracting data (attempt {attempt}/{retries})...")
                result = agent.extract(file_path)
                print("✅ Extraction successful")
                return result
            except Exception as e:
                print(f"⚠️ Attempt {attempt} failed: {e}")
                logger.error(f"⚠️ Attempt {attempt} failed for {file_path}: {e}")
                time.sleep(wait_time)
        raise Exception(f"❌ Extraction failed after {retries} attempts for {file_path}")
    
    def process_extracted_data(self, extracted_data: Dict, file_info: Dict) -> List[Dict]:
        """
        Process extracted data using ZeptoAgent logic
        Returns a list of dictionaries (rows) for Google Sheets
        """
        rows = []
        items = []
        if "items" in extracted_data:
            items = extracted_data["items"]
            for item in items:
                item["po_number"] = self.get_value(extracted_data, ["po_number", "purchase_order_number", "PO No"])
                item["vendor_invoice_number"] = self.get_value(extracted_data, ["vendor_invoice_number", "invoice_number", "inv_no", "Invoice No"])
                item["supplier"] = self.get_value(extracted_data, ["supplier", "vendor", "Supplier Name"])
                item["shipping_address"] = self.get_value(extracted_data, ["shipping_address", "receiver_address", "Shipping Address"])
                item["grn_date"] = self.get_value(extracted_data, ["grn_date", "delivered_on", "GRN Date"])
                item["source_file"] = file_info['name']
                item["processed_date"] = time.strftime("%Y-%m-%d %H:%M:%S")
                item["drive_file_id"] = file_info['id']
        elif "product_items" in extracted_data:
            items = extracted_data["product_items"]
            for item in items:
                item["po_number"] = self.get_value(extracted_data, ["purchase_order_number", "po_number", "PO No"])
                item["vendor_invoice_number"] = self.get_value(extracted_data, ["supplier_bill_number", "vendor_invoice_number", "invoice_number"])
                item["supplier"] = self.get_value(extracted_data, ["supplier", "vendor", "Supplier Name"])
                item["shipping_address"] = self.get_value(extracted_data, ["Shipping Address", "receiver_address", "shipping_address"])
                item["grn_date"] = self.get_value(extracted_data, ["delivered_on", "grn_date"])
                item["source_file"] = file_info['name']
                item["processed_date"] = time.strftime("%Y-%m-%d %H:%M:%S")
                item["drive_file_id"] = file_info['id']
        else:
            print(f"⚠ Skipping (no recognizable items key): {file_info['name']}")
            return rows
        
        for item in items:
            cleaned_item = {k: v for k, v in item.items() if v not in ["", None]}
            rows.append(cleaned_item)
        return rows
    
    def get_sheet_data(self, spreadsheet_id: str, sheet_name: str) -> List[List[str]]:
        """Get all data from the sheet"""
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=sheet_name,
                majorDimension="ROWS"
            ).execute()
            return result.get('values', [])
        except Exception as e:
            print(f"❌ Failed to get sheet data: {str(e)}")
            logger.error(f"[ERROR] Failed to get sheet data: {str(e)}")
            return []
    
    def get_sheet_id(self, spreadsheet_id: str, sheet_name: str) -> int:
        """Get the numeric sheet ID for the given sheet name"""
        try:
            metadata = self.sheets_service.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
            for sheet in metadata.get('sheets', []):
                if sheet['properties']['title'] == sheet_name:
                    return sheet['properties']['sheetId']
            print(f"❌ Sheet '{sheet_name}' not found")
            return 0
        except Exception as e:
            print(f"❌ Failed to get sheet metadata: {str(e)}")
            return 0
    
    def update_headers(self, spreadsheet_id: str, sheet_name: str, new_headers: List[str]) -> bool:
        """Update the header row with new columns"""
        try:
            body = {'values': [new_headers]}
            result = self.sheets_service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A1:{chr(64 + len(new_headers))}1",
                valueInputOption='USER_ENTERED',
                body=body
            ).execute()
            print(f"✅ Updated headers with {len(new_headers)} columns")
            logger.info(f"[SHEETS] Updated headers with {len(new_headers)} columns")
            return True
        except Exception as e:
            print(f"❌ Failed to update headers: {str(e)}")
            logger.error(f"[ERROR] Failed to update headers: {str(e)}")
            return False
    
    def replace_rows_for_file(self, spreadsheet_id: str, sheet_name: str, file_id: str, 
                             headers: List[str], new_rows: List[List[Any]], sheet_id: int) -> bool:
        """Delete existing rows for the file if any, and append new rows"""
        try:
            values = self.get_sheet_data(spreadsheet_id, sheet_name)
            if not values:
                return self.append_to_google_sheet(spreadsheet_id, sheet_name, new_rows)
            
            current_headers = values[0]
            data_rows = values[1:]
            
            try:
                file_id_col = current_headers.index('drive_file_id')
            except ValueError:
                print("ℹ️ No 'drive_file_id' column found, appending new rows")
                return self.append_to_google_sheet(spreadsheet_id, sheet_name, new_rows)
            
            rows_to_delete = []
            for idx, row in enumerate(data_rows, 2):
                if len(row) > file_id_col and row[file_id_col] == file_id:
                    rows_to_delete.append(idx)
            
            if rows_to_delete:
                rows_to_delete.sort(reverse=True)
                requests = []
                for row_idx in rows_to_delete:
                    requests.append({
                        'deleteDimension': {
                            'range': {
                                'sheetId': sheet_id,
                                'dimension': 'ROWS',
                                'startIndex': row_idx - 1,
                                'endIndex': row_idx
                            }
                        }
                    })
                body = {'requests': requests}
                self.sheets_service.spreadsheets().batchUpdate(
                    spreadsheetId=spreadsheet_id,
                    body=body
                ).execute()
                print(f"🗑️ Deleted {len(rows_to_delete)} existing rows for file {file_id}")
                logger.info(f"[SHEETS] Deleted {len(rows_to_delete)} rows for file {file_id}")
            
            return self.append_to_google_sheet(spreadsheet_id, sheet_name, new_rows)
        except Exception as e:
            print(f"❌ Failed to replace rows: {str(e)}")
            logger.error(f"[ERROR] Failed to replace rows: {str(e)}")
            return False
    
    def process_pdfs(self, drive_folder_id: str, api_key: str, agent_name: str, 
                    spreadsheet_id: str, sheet_range: str = "Sheet1", days_back: int = 1) -> Dict:
        """
        Process PDFs from Google Drive with LlamaParse and save to Google Sheets
        Using ZeptoAgent extraction logic
        
        Args:
            drive_folder_id: Google Drive folder ID containing PDFs
            api_key: LlamaParse API key
            agent_name: LlamaParse agent name
            spreadsheet_id: Google Sheets ID to save results to
            sheet_range: Sheet name to update (default: "Sheet1")
            days_back: Number of days back to fetch files (1 = today only, 2 = today + yesterday, etc.)
        """
        stats = {
            'total_pdfs': 0,
            'processed_pdfs': 0,
            'failed_pdfs': 0,
            'rows_added': 0
        }
        
        if not LLAMA_AVAILABLE:
            print("❌ LlamaParse not available. Install with: pip install llama-cloud-services")
            logger.error("[ERROR] LlamaParse not available. Install with: pip install llama-cloud-services")
            return stats
        
        try:
            print("🔑 Setting up LlamaParse...")
            os.environ["LLAMA_CLOUD_API_KEY"] = api_key
            extractor = LlamaExtract()
            agent = extractor.get_agent(name=agent_name)
            
            if agent is None:
                print(f"❌ Could not find agent '{agent_name}'. Check dashboard.")
                logger.error(f"[ERROR] Could not find agent '{agent_name}'. Check dashboard.")
                return stats
            
            print("✅ LlamaParse agent found")
            
            sheet_name = sheet_range.split('!')[0]
            sheet_id = self.get_sheet_id(spreadsheet_id, sheet_name)
            
            print(f"📂 Searching for PDFs in folder ID: {drive_folder_id} (last {days_back} days)")
            pdf_files = self.list_drive_files(drive_folder_id, days_back)
            stats['total_pdfs'] = len(pdf_files)
            
            if not pdf_files:
                print("❌ No PDF files found in the specified folder")
                logger.info("[INFO] No PDF files found in the specified folder")
                return stats
            
            print(f"📊 Found {len(pdf_files)} PDF files to process")
            
            # Get initial headers
            print("📋 Checking existing sheet headers...")
            headers = self.get_sheet_headers(spreadsheet_id, sheet_name)
            headers_set = False
            
            for i, file in enumerate(pdf_files, 1):
                try:
                    print(f"\n📄 Processing PDF {i}/{len(pdf_files)}: {file['name']}")
                    print(f"📊 Progress: {i}/{len(pdf_files)} files processed")
                    logger.info(f"[LLAMA] Processing PDF {i}/{len(pdf_files)}: {file['name']}")
                    
                    pdf_data = self.download_from_drive(file['id'], file['name'])
                    if not pdf_data:
                        print(f"❌ Failed to download PDF: {file['name']}")
                        logger.error(f"[ERROR] Failed to download PDF: {file['name']}")
                        stats['failed_pdfs'] += 1
                        continue
                    
                    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
                        temp_file.write(pdf_data)
                        temp_path = temp_file.name
                    
                    result = self.safe_extract(agent, temp_path)
                    extracted_data = result.data
                    os.unlink(temp_path)
                    
                    rows = self.process_extracted_data(extracted_data, file)
                    if not rows:
                        print(f"⚠️ No rows extracted from: {file['name']}")
                        continue
                    
                    stats['processed_pdfs'] += 1
                    print(f"✅ Successfully processed: {file['name']}")
                    print(f"📈 Extracted {len(rows)} rows from this PDF")
                    logger.info(f"[LLAMA] Successfully processed: {file['name']}")
                    
                    # Set headers from first file if none exist
                    if not headers and not headers_set:
                        headers = list(set().union(*(row.keys() for row in rows)))
                        self.update_headers(spreadsheet_id, sheet_name, headers)
                        headers_set = True
                    
                    # Prepare values using established headers
                    values = [[row.get(h, "") for h in headers] for row in rows]
                    
                    # Replace rows for this file
                    success = self.replace_rows_for_file(
                        spreadsheet_id=spreadsheet_id,
                        sheet_name=sheet_name,
                        file_id=file['id'],
                        headers=headers,
                        new_rows=values,
                        sheet_id=sheet_id
                    )
                    
                    if success:
                        stats['rows_added'] += len(rows)
                        print(f"💾 Successfully saved {len(rows)} rows for this PDF")
                    else:
                        print(f"❌ Failed to save rows for {file['name']}")
                    
                except Exception as e:
                    print(f"❌ Error processing {file['name']}: {e}")
                    logger.error(f"[ERROR] Failed to process PDF {file['name']}: {str(e)}")
                    stats['failed_pdfs'] += 1
            
            return stats
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            logger.error(f"[ERROR] LlamaParse processing failed: {str(e)}")
            return stats

def main():
    """Run the PDF processing from Google Drive to Google Sheets"""
    
    print("=== Zepto Google Drive PDF Processor with LlamaParse ===")
    print("Processing PDFs from Google Drive and saving to Google Sheets")
    print("Using ZeptoAgent extraction logic with OAuth2 authentication")
    print()
    
    # Configuration - MODIFY THESE VALUES
    CONFIG = {
        'credentials_path': 'D:\\GRN\\PDF\\zhplgrn\\credentials.json',
        'drive_folder_id': '1aUjRMqWjVDDAsQw0TugwgmwYjxP6W7DT',
        'llama_api_key': 'llx-ZBUTlOe0JLY3ny0FSs5mSJTMgOZU7RV3x3TGyQPNQQ0XPhyO',
        'llama_agent': 'Hyperpure Agent',
        'spreadsheet_id': '1B1C2ILnIMXpEYbQzaSkhRzEP2gmgE2YLRNqoX98GwcU', 
        'sheet_range': 'hyperpuregrn',
        'days_back': 1
    }
    
    # Validate configuration
    if not os.path.exists(CONFIG['credentials_path']):
        print(f"[ERROR] Credentials file not found: {CONFIG['credentials_path']}")
        print()
        print("SETUP INSTRUCTIONS:")
        print("1. Go to https://console.cloud.google.com")
        print("2. Create a new project or select existing one")
        print("3. Enable Google Drive API and Google Sheets API")
        print("4. Go to 'Credentials' > 'Create Credentials' > 'OAuth client ID'")
        print("5. Choose 'Desktop application' as application type")
        print("6. Download the JSON file and save it as 'credentials.json'")
        print()
        print("Required packages:")
        print("pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client")
        print("pip install llama-cloud-services")
        return
    
    # Initialize processor
    processor = ZeptoDriveProcessor(
        credentials_path=CONFIG['credentials_path']
    )
    
    # Authenticate
    print("🔐 Authenticating with Google APIs...")
    if not processor.authenticate():
        print("❌ Authentication failed")
        return
    
    # Process PDFs
    print("🚀 Starting PDF processing...")
    stats = processor.process_pdfs(
        drive_folder_id=CONFIG['drive_folder_id'],
        api_key=CONFIG['llama_api_key'],
        agent_name=CONFIG['llama_agent'],
        spreadsheet_id=CONFIG['spreadsheet_id'],
        sheet_range=CONFIG['sheet_range'],
        days_back=CONFIG['days_back']
    )
    
    # Print final results
    print("\n" + "="*50)
    print("📊 PROCESSING COMPLETE - FINAL STATISTICS")
    print("="*50)
    print(f"Total PDFs found: {stats['total_pdfs']}")
    print(f"Successfully processed: {stats['processed_pdfs']}")
    print(f"Failed to process: {stats['failed_pdfs']}")
    print(f"Rows added to Google Sheets: {stats['rows_added']}")
    print("="*50)
    
    if stats['failed_pdfs'] > 0:
        print("❌ Some PDFs failed to process. Check the log file for details.")
    elif stats['processed_pdfs'] > 0:
        print("✅ All PDFs processed successfully!")
    else:
        print("ℹ️ No PDFs were processed.")

if __name__ == "__main__":
    main()