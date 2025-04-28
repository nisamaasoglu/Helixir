import sys
import cv2
import numpy as np
import sqlite3
import time
import hashlib
from datetime import datetime # For timestamp display
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QComboBox, QLineEdit, QGridLayout, QMessageBox, QSizePolicy,
    QListWidget, QListWidgetItem, QSplitter # Added ListWidget, ListWidgetItem, Splitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject, QTimer
from PyQt6.QtGui import QImage, QPixmap, QFont

# --- Encryption Functions (Same as before) ---

def encrypt_block_transpose(image, key_str, block_size=16):
    try:
        h, w, c = image.shape
        h_crop = (h // block_size) * block_size
        w_crop = (w // block_size) * block_size
        if h_crop == 0 or w_crop == 0: return image # Prevent empty crop
        img_cropped = image[:h_crop, :w_crop]

        blocks = []
        for i in range(0, h_crop, block_size):
            for j in range(0, w_crop, block_size):
                blocks.append(img_cropped[i:i+block_size, j:j+block_size].copy()) # Use copy

        num_blocks = len(blocks)
        if num_blocks == 0: return image

        seed = int(hashlib.sha256(key_str.encode('utf-8')).hexdigest(), 16) % (2**32)
        rng = np.random.RandomState(seed)
        shuffled_indices = rng.permutation(num_blocks)

        encrypted_img = np.zeros_like(img_cropped)
        block_idx = 0
        for i in range(0, h_crop, block_size):
            for j in range(0, w_crop, block_size):
                if block_idx < num_blocks:
                    original_block_index = shuffled_indices[block_idx]
                    if original_block_index < len(blocks): # Bounds check
                         encrypted_img[i:i+block_size, j:j+block_size] = blocks[original_block_index]
                    block_idx += 1

        final_image = image.copy()
        final_image[:h_crop, :w_crop] = encrypted_img
        return final_image
    except Exception as e:
        print(f"Block Transpose Encrypt Error: {e}")
        return image

def encrypt_pixel_xor(image, key_str):
    try:
        h, w, c = image.shape
        key_bytes = key_str.encode('utf-8')
        if not key_bytes: key_bytes = b'default'

        key_pattern = np.tile(np.frombuffer(key_bytes, dtype=np.uint8), (h * w * c // len(key_bytes) + 1))
        key_pattern = key_pattern[:h * w * c].reshape(h, w, c)

        encrypted_img = cv2.bitwise_xor(image, key_pattern)
        return encrypted_img
    except Exception as e:
        print(f"XOR Encrypt Error: {e}")
        return image

def encrypt_add_noise(image, key_str):
    try:
        noise_intensity = len(key_str) * 5
        if noise_intensity <= 0: noise_intensity = 25

        # Ensure noise is generated with same dtype as image if not uint8
        noise = np.random.normal(0, noise_intensity, image.shape)
        # Add noise and clip to valid range for image dtype
        noisy_image = np.clip(image.astype(np.float32) + noise, 0, 255).astype(image.dtype)
        # noisy_image = cv2.add(image, noise.astype(image.dtype)) # cv2.add handles saturation
        return noisy_image
    except Exception as e:
        print(f"Noise Encrypt Error: {e}")
        return image

# --- Decryption Functions ---

def decrypt_block_transpose(encrypted_image, key_str, block_size=16):
    """ Reverses the block transpose encryption. """
    try:
        h, w, c = encrypted_image.shape
        h_crop = (h // block_size) * block_size
        w_crop = (w // block_size) * block_size
        if h_crop == 0 or w_crop == 0: return encrypted_image
        encrypted_cropped = encrypted_image[:h_crop, :w_crop]

        encrypted_blocks = []
        for i in range(0, h_crop, block_size):
            for j in range(0, w_crop, block_size):
                encrypted_blocks.append(encrypted_cropped[i:i+block_size, j:j+block_size].copy()) # Use copy

        num_blocks = len(encrypted_blocks)
        if num_blocks == 0: return encrypted_image

        # Generate the SAME permutation order as encryption
        seed = int(hashlib.sha256(key_str.encode('utf-8')).hexdigest(), 16) % (2**32)
        rng = np.random.RandomState(seed)
        shuffled_indices = rng.permutation(num_blocks)

        # Create the inverse mapping: where did the block at this shuffled position originally come from?
        inverse_indices = np.argsort(shuffled_indices)

        decrypted_img = np.zeros_like(encrypted_cropped)
        shuffled_block_idx = 0
        for i in range(0, h_crop, block_size):
            for j in range(0, w_crop, block_size):
                if shuffled_block_idx < num_blocks:
                    original_block_index = inverse_indices[shuffled_block_idx]
                    if original_block_index < len(encrypted_blocks): # Bounds check
                        decrypted_img[i:i+block_size, j:j+block_size] = encrypted_blocks[original_block_index]
                    shuffled_block_idx += 1

        final_image = encrypted_image.copy()
        final_image[:h_crop, :w_crop] = decrypted_img
        return final_image
    except Exception as e:
        print(f"Block Transpose Decrypt Error: {e}")
        return encrypted_image # Return encrypted on error

def decrypt_pixel_xor(encrypted_image, key_str):
    """ Reverses XOR encryption (which is just applying XOR again). """
    # XOR is its own inverse
    return encrypt_pixel_xor(encrypted_image, key_str)

def decrypt_add_noise(encrypted_image, key_str):
    """ Noise is generally irreversible. Returns the input. """
    print("Warning: Noise addition is generally irreversible. Returning noisy image.")
    # Optional: Apply a simple denoiser, but it won't be the original
    # return cv2.medianBlur(encrypted_image, 5)
    return encrypted_image

# --- Camera Worker Thread (Same as before) ---
class CameraWorker(QObject):
    frameReady = pyqtSignal(np.ndarray)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, camera_index=0):
        super().__init__()
        self.camera_index = camera_index
        self.running = False
        self.cap = None

    def run(self):
        self.running = True
        # Try MSMF first, then DSHOW, then default
        backends = [cv2.CAP_MSMF, cv2.CAP_DSHOW, -1] # -1 for default/any
        success = False
        for backend in backends:
             print(f"Trying camera {self.camera_index} with backend {backend if backend != -1 else 'Default'}...")
             if backend != -1:
                 self.cap = cv2.VideoCapture(self.camera_index, backend)
             else:
                  self.cap = cv2.VideoCapture(self.camera_index) # Try default
             if self.cap.isOpened():
                 print(f"Successfully opened camera {self.camera_index} with backend {backend if backend != -1 else 'Default'}.")
                 success = True
                 break
             else:
                 self.cap.release() # Release failed attempt

        if not success:
            self.error.emit(f"Error: Could not open camera {self.camera_index} using any backend.")
            self.running = False
            self.finished.emit()
            return

        while self.running:
            ret, frame = self.cap.read()
            if not ret:
                # Don't emit error immediately, could be temporary glitch
                time.sleep(0.1)
                ret, frame = self.cap.read() # Retry once
                if not ret:
                    print("Error: Could not read frame from camera (retry failed). Stopping.")
                    self.error.emit("Error: Could not read frame from camera.")
                    self.running = False
                    break # Exit loop on persistent read error
            if self.running and ret: # Check running flag again after potential sleep/retry
                self.frameReady.emit(frame)
            # time.sleep(0.01) # Optional small delay

        if self.cap:
            self.cap.release()
        self.finished.emit()

    def stop(self):
        self.running = False


# --- Main Application Window ---
class MainWindow(QMainWindow):
    DB_NAME = "encryption_log.db"

    def __init__(self):
        super().__init__()
        self.current_frame = None
        self.encrypted_frame = None
        self.camera_thread = None
        self.camera_worker = None
        self.is_recording = False

        self.setWindowTitle("Real-Time Visual Cryptography System")
        self.setGeometry(100, 100, 1400, 800) # Increased size
        self.setStyleSheet(self.get_dark_style())

        # --- Use QSplitter for Resizable Panes ---
        main_splitter = QSplitter(Qt.Orientation.Vertical)
        self.setCentralWidget(main_splitter)

        # Top Pane: Live Video Feeds
        video_widget = QWidget()
        video_layout = QHBoxLayout(video_widget)
        self.original_video_label = self.create_video_label("Original Image (Live)")
        self.encrypted_video_label = self.create_video_label("Encrypted Image (Live)")
        video_layout.addWidget(self.original_video_label)
        video_layout.addWidget(self.encrypted_video_label)
        main_splitter.addWidget(video_widget)

        # Middle Pane: Controls
        controls_widget = QWidget()
        controls_layout = QGridLayout(controls_widget)
        # --- Control Widgets (Camera, Encryption) ---
        controls_layout.addWidget(QLabel("Camera:"), 0, 0)
        self.camera_combo = QComboBox()
        self.populate_cameras()
        controls_layout.addWidget(self.camera_combo, 0, 1)
        self.start_button = QPushButton("Start Camera")
        self.start_button.clicked.connect(self.start_camera)
        controls_layout.addWidget(self.start_button, 0, 2)
        self.stop_button = QPushButton("Stop Camera")
        self.stop_button.clicked.connect(self.stop_camera)
        controls_layout.addWidget(self.stop_button, 0, 3)

        controls_layout.addWidget(QLabel("Encryption Method:"), 1, 0)
        self.method_combo = QComboBox()
        self.method_combo.addItems(["Block Transpose", "Pixel XOR", "Add Noise"])
        controls_layout.addWidget(self.method_combo, 1, 1)
        controls_layout.addWidget(QLabel("Encryption Key:"), 1, 2)
        self.key_input = QLineEdit("default_key")
        controls_layout.addWidget(self.key_input, 1, 3)
        self.save_button = QPushButton("Save Current Encrypted Frame")
        self.save_button.clicked.connect(self.save_encrypted_frame)
        controls_layout.addWidget(self.save_button, 0, 4, 1, 2) # Span cols 4 and 5

        main_splitter.addWidget(controls_widget)


        # Bottom Pane: Saved Images List and Decryption Area
        saved_area_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_splitter.addWidget(saved_area_splitter)
        main_splitter.setStretchFactor(0, 3) # Give more space to video
        main_splitter.setStretchFactor(1, 1) # Less space to controls
        main_splitter.setStretchFactor(2, 3) # More space to saved area

        # Left side of bottom pane: List and DB controls
        list_control_widget = QWidget()
        list_control_layout = QVBoxLayout(list_control_widget)
        list_control_layout.addWidget(QLabel("Saved Encrypted Images:"))
        self.saved_images_list = QListWidget()
        self.saved_images_list.itemSelectionChanged.connect(self.on_list_selection_change) # Enable button on select
        list_control_layout.addWidget(self.saved_images_list)

        list_button_layout = QHBoxLayout() # Layout for buttons below list
        self.refresh_list_button = QPushButton("Refresh List")
        self.refresh_list_button.clicked.connect(self.load_saved_images_list)
        list_button_layout.addWidget(self.refresh_list_button)
        self.load_decrypt_button = QPushButton("Load & Decrypt Selected")
        self.load_decrypt_button.clicked.connect(self.load_and_decrypt_selected)
        self.load_decrypt_button.setEnabled(False) # Disabled initially
        list_button_layout.addWidget(self.load_decrypt_button)
        self.clear_db_button = QPushButton("Clear DB")
        self.clear_db_button.clicked.connect(self.clear_database)
        list_button_layout.addWidget(self.clear_db_button)
        list_control_layout.addLayout(list_button_layout)

        saved_area_splitter.addWidget(list_control_widget)


        # Right side of bottom pane: Loaded/Decrypted display
        loaded_display_widget = QWidget()
        loaded_display_layout = QHBoxLayout(loaded_display_widget)
        self.loaded_encrypted_label = self.create_video_label("Loaded Encrypted Image")
        self.loaded_decrypted_label = self.create_video_label("Decrypted Image")
        loaded_display_layout.addWidget(self.loaded_encrypted_label)
        loaded_display_layout.addWidget(self.loaded_decrypted_label)
        saved_area_splitter.addWidget(loaded_display_widget)
        saved_area_splitter.setStretchFactor(0, 1) # List area smaller
        saved_area_splitter.setStretchFactor(1, 2) # Display area larger


        # Status Bar
        self.statusBar().showMessage("Ready.")

        # Initialize Database & Load List
        self.init_db()
        self.load_saved_images_list()

        # Set initial state
        self.update_ui_state(camera_running=False)

    def create_video_label(self, title):
        """Helper to create styled labels for video display."""
        label = QLabel(f"{title}\n(No Image)")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setFont(QFont("Arial", 10))
        label.setStyleSheet("border: 1px solid #555; background-color: #222; color: #AAA; padding: 5px;")
        label.setMinimumSize(320, 240)
        label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        label.setScaledContents(False) # Important for aspect ratio preservation
        return label

    def get_dark_style(self):
        # Slightly adjusted style
        return """
            QMainWindow, QSplitter::handle {
                background-color: #2E2E2E;
            }
            QWidget {
                color: #E0E0E0;
                background-color: #3C3C3C;
                font-size: 10pt; /* Slightly smaller default */
            }
            QLabel {
                background-color: transparent;
                padding: 2px;
            }
            QPushButton {
                background-color: #555555;
                color: #FFFFFF;
                border: 1px solid #666666;
                padding: 6px 12px; /* Slightly smaller padding */
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover { background-color: #6A6A6A; }
            QPushButton:pressed { background-color: #4A4A4A; }
            QPushButton:disabled { background-color: #444444; color: #888888; }
            QLineEdit, QComboBox, QListWidget {
                background-color: #555555;
                color: #FFFFFF;
                border: 1px solid #666666;
                padding: 4px;
                border-radius: 4px;
            }
            QListWidget::item { padding: 4px; }
            QListWidget::item:selected { background-color: #0078D7; color: white; }
            QComboBox::drop-down { border: none; }
            QComboBox::down-arrow { image: url(no_arrow.png); width: 14px; height: 14px; }
            QStatusBar { color: #FFFFFF; background-color: #2E2E2E; }
            QSplitter::handle:vertical { height: 5px; }
            QSplitter::handle:horizontal { width: 5px; }
        """

    def populate_cameras(self):
        self.camera_combo.clear()
        index = 0
        while True:
            # Quickly check if camera exists without fully opening if possible
            cap = cv2.VideoCapture(index, cv2.CAP_DSHOW) # DSHOW is often needed for listing
            if cap.isOpened():
                self.camera_combo.addItem(f"Camera {index}", index)
                cap.release()
                index += 1
                if index > 5: break # Limit search depth
            else:
                cap.release()
                break
        if self.camera_combo.count() == 0:
            self.camera_combo.addItem("No Cameras Found", -1)
            self.camera_combo.setEnabled(False)
        else:
             self.camera_combo.setEnabled(True)

    def start_camera(self):
        if self.camera_worker is not None:
            self.statusBar().showMessage("Camera already running.")
            return
        camera_data = self.camera_combo.currentData()
        if camera_data is None or camera_data == -1:
            self.show_error_message("No valid camera selected.")
            return

        self.camera_thread = QThread()
        self.camera_worker = CameraWorker(camera_index=camera_data)
        self.camera_worker.moveToThread(self.camera_thread)
        self.camera_worker.frameReady.connect(self.process_frame)
        self.camera_worker.finished.connect(self.on_camera_finished)
        self.camera_worker.error.connect(self.show_error_message)
        self.camera_thread.started.connect(self.camera_worker.run)
        self.camera_thread.start()
        self.update_ui_state(camera_running=True)
        self.statusBar().showMessage(f"Starting Camera {camera_data}...")
        self.original_video_label.setText("Waiting for frame...")
        self.encrypted_video_label.setText("Waiting for frame...")

    def stop_camera(self):
        if self.camera_worker:
            self.statusBar().showMessage("Stopping camera...")
            self.camera_worker.stop()

    def on_camera_finished(self):
        if self.camera_thread:
            self.camera_thread.quit()
            self.camera_thread.wait()
        self.camera_thread = None
        self.camera_worker = None
        self.update_ui_state(camera_running=False)
        self.statusBar().showMessage("Camera stopped.")
        self.original_video_label.setText("Original Image (Live)\n(Camera Stopped)")
        self.encrypted_video_label.setText("Encrypted Image (Live)\n(Camera Stopped)")
        self.original_video_label.setPixmap(QPixmap())
        self.encrypted_video_label.setPixmap(QPixmap())
        self.current_frame = None
        self.encrypted_frame = None

    def process_frame(self, frame_bgr):
        # --- This function remains largely the same ---
        if frame_bgr is None: return
        self.current_frame = frame_bgr
        frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
        qt_image_original = self.convert_cv_qt(frame_rgb)
        self.display_pixmap(self.original_video_label, qt_image_original)

        method = self.method_combo.currentText()
        key = self.key_input.text()
        encrypted_bgr = None
        if method == "Block Transpose": encrypted_bgr = encrypt_block_transpose(frame_bgr, key)
        elif method == "Pixel XOR": encrypted_bgr = encrypt_pixel_xor(frame_bgr, key)
        elif method == "Add Noise": encrypted_bgr = encrypt_add_noise(frame_bgr, key)
        else: encrypted_bgr = frame_bgr
        self.encrypted_frame = encrypted_bgr

        if encrypted_bgr is not None:
            encrypted_rgb = cv2.cvtColor(encrypted_bgr, cv2.COLOR_BGR2RGB)
            qt_image_encrypted = self.convert_cv_qt(encrypted_rgb)
            self.display_pixmap(self.encrypted_video_label, qt_image_encrypted)

    def convert_cv_qt(self, cv_img):
        """Convert an OpenCV image (RGB) to QPixmap."""
        try:
            rgb_image = cv_img
            h, w, ch = rgb_image.shape
            bytes_per_line = ch * w
            convert_to_Qt_format = QImage(rgb_image.data, w, h, bytes_per_line, QImage.Format.Format_RGB888)
            return QPixmap.fromImage(convert_to_Qt_format)
        except Exception as e:
            print(f"Error converting CV to Qt: {e}")
            return QPixmap() # Return empty pixmap on error

    def display_pixmap(self, label, pixmap):
         """ Scales pixmap to fit label while preserving aspect ratio. """
         if pixmap.isNull():
              label.setPixmap(QPixmap()) # Clear if pixmap is invalid
              label.setText(f"{label.text().splitlines()[0]}\n(No Image)")
              return

         # Scale pixmap to fit label size using KeepAspectRatio
         scaled_pixmap = pixmap.scaled(label.size(),
                                      Qt.AspectRatioMode.KeepAspectRatio,
                                      Qt.TransformationMode.SmoothTransformation)
         label.setPixmap(scaled_pixmap)


    def update_ui_state(self, camera_running):
        self.start_button.setEnabled(not camera_running and self.camera_combo.isEnabled())
        self.stop_button.setEnabled(camera_running)
        self.camera_combo.setEnabled(not camera_running)
        self.save_button.setEnabled(camera_running)
        # Keep encryption settings always enabled for now, applied during processing
        # self.method_combo.setEnabled(not camera_running)
        # self.key_input.setEnabled(not camera_running)

    # --- Database Methods ---
    def init_db(self):
        # --- Same as before ---
        try:
            conn = sqlite3.connect(self.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS encrypted_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    method TEXT NOT NULL,
                    key_used TEXT,
                    image_data BLOB
                )
            """)
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            self.show_error_message(f"Database Init Error: {e}")

    def save_encrypted_frame(self):
        """Saves the current encrypted frame as PNG BLOB."""
        if self.encrypted_frame is None:
            self.statusBar().showMessage("No encrypted frame available to save.")
            return

        method = self.method_combo.currentText()
        key = self.key_input.text()

        try:
            # Encode the image to PNG format in memory
            success, encoded_image = cv2.imencode('.png', self.encrypted_frame)
            if not success:
                self.statusBar().showMessage("Failed to encode image to PNG for saving.")
                return
            img_bytes = encoded_image.tobytes() # Get bytes from the encoded array

            conn = sqlite3.connect(self.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO encrypted_log (method, key_used, image_data)
                VALUES (?, ?, ?)
            """, (method, key, sqlite3.Binary(img_bytes)))
            conn.commit()
            conn.close()
            self.statusBar().showMessage(f"Encrypted frame saved (ID: {cursor.lastrowid}, Method: {method}).")
            self.load_saved_images_list() # Refresh list after saving

        except sqlite3.Error as e:
            self.show_error_message(f"Database Save Error: {e}")
        except Exception as e:
             self.show_error_message(f"Error saving frame: {e}")

    def clear_database(self):
        # --- Same as before, but refresh list after clearing ---
        reply = QMessageBox.question(self, 'Confirm Clear',
                                     'Are you sure you want to delete ALL saved encrypted images?',
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            try:
                conn = sqlite3.connect(self.DB_NAME)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM encrypted_log")
                # Optional: Reset ID counter
                cursor.execute("DELETE FROM sqlite_sequence WHERE name='encrypted_log'")
                conn.commit()
                conn.close()
                self.statusBar().showMessage("Database cleared.")
                self.load_saved_images_list() # Refresh the list
                # Clear loaded image displays as well
                self.loaded_encrypted_label.setPixmap(QPixmap())
                self.loaded_encrypted_label.setText("Loaded Encrypted Image\n(No Image)")
                self.loaded_decrypted_label.setPixmap(QPixmap())
                self.loaded_decrypted_label.setText("Decrypted Image\n(No Image)")

            except sqlite3.Error as e:
                self.show_error_message(f"Database Clear Error: {e}")

    def load_saved_images_list(self):
        """ Fetches image metadata from DB and populates the QListWidget. """
        self.saved_images_list.clear()
        try:
            conn = sqlite3.connect(self.DB_NAME)
            cursor = conn.cursor()
            # Fetch limited info for the list display
            cursor.execute("SELECT id, timestamp, method FROM encrypted_log ORDER BY timestamp DESC")
            records = cursor.fetchall()
            conn.close()

            if not records:
                self.saved_images_list.addItem("No saved images found.")
                self.saved_images_list.setEnabled(False)
                self.load_decrypt_button.setEnabled(False) # Disable button if list is empty
            else:
                self.saved_images_list.setEnabled(True)
                for record in records:
                    db_id, timestamp_str, method = record
                    # Format timestamp nicely
                    try:
                        timestamp_dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                        display_text = f"ID: {db_id} | {timestamp_dt.strftime('%Y-%m-%d %H:%M')} | {method}"
                    except ValueError: # Handle potential timestamp format issues
                         display_text = f"ID: {db_id} | {timestamp_str} | {method}"

                    list_item = QListWidgetItem(display_text)
                    list_item.setData(Qt.ItemDataRole.UserRole, db_id) # Store DB ID in the item
                    self.saved_images_list.addItem(list_item)
                # Don't enable button automatically here, enable on selection change

        except sqlite3.Error as e:
            self.show_error_message(f"Error loading saved images list: {e}")
            self.saved_images_list.addItem("Error loading list.")
            self.saved_images_list.setEnabled(False)
            self.load_decrypt_button.setEnabled(False)

    def on_list_selection_change(self):
        """ Enable the Load/Decrypt button only if a valid item is selected. """
        selected_items = self.saved_images_list.selectedItems()
        if selected_items:
            # Check if it's a real item (not 'No saved images' or 'Error')
            db_id = selected_items[0].data(Qt.ItemDataRole.UserRole)
            self.load_decrypt_button.setEnabled(db_id is not None)
        else:
            self.load_decrypt_button.setEnabled(False)


    def load_and_decrypt_selected(self):
        """ Loads the selected image BLOB, decrypts it, and displays both. """
        selected_items = self.saved_images_list.selectedItems()
        if not selected_items:
            self.statusBar().showMessage("Please select an image from the list first.")
            return

        list_item = selected_items[0]
        db_id = list_item.data(Qt.ItemDataRole.UserRole)
        if db_id is None: # Should not happen if button is enabled correctly
            self.statusBar().showMessage("Invalid item selected.")
            return

        try:
            conn = sqlite3.connect(self.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT method, key_used, image_data FROM encrypted_log WHERE id = ?", (db_id,))
            record = cursor.fetchone()
            conn.close()

            if record is None:
                self.show_error_message(f"Error: Could not find record with ID {db_id} in database.")
                self.load_saved_images_list() # Refresh list in case item was deleted elsewhere
                return

            method, key_used, image_blob = record

            # Decode the image BLOB (assuming it was saved with imencode)
            image_buffer = np.frombuffer(image_blob, dtype=np.uint8)
            loaded_encrypted_bgr = cv2.imdecode(image_buffer, cv2.IMREAD_COLOR)

            if loaded_encrypted_bgr is None:
                self.show_error_message(f"Error: Failed to decode image data for ID {db_id}.")
                self.loaded_encrypted_label.setText("Loaded Encrypted Image\n(Decode Error)")
                self.loaded_encrypted_label.setPixmap(QPixmap())
                self.loaded_decrypted_label.setText("Decrypted Image\n(Decode Error)")
                self.loaded_decrypted_label.setPixmap(QPixmap())
                return

            # Display the loaded encrypted image
            self.loaded_encrypted_label.setText(f"Loaded Encrypted Image\n(ID: {db_id}, Method: {method})")
            loaded_encrypted_rgb = cv2.cvtColor(loaded_encrypted_bgr, cv2.COLOR_BGR2RGB)
            qt_image_loaded_encrypted = self.convert_cv_qt(loaded_encrypted_rgb)
            self.display_pixmap(self.loaded_encrypted_label, qt_image_loaded_encrypted)


            # Decrypt the loaded image
            decrypted_bgr = None
            if method == "Block Transpose":
                decrypted_bgr = decrypt_block_transpose(loaded_encrypted_bgr, key_used)
            elif method == "Pixel XOR":
                decrypted_bgr = decrypt_pixel_xor(loaded_encrypted_bgr, key_used)
            elif method == "Add Noise":
                 decrypted_bgr = decrypt_add_noise(loaded_encrypted_bgr, key_used) # Returns noisy
            else:
                print(f"Warning: Unknown decryption method '{method}' for ID {db_id}.")
                decrypted_bgr = loaded_encrypted_bgr # Show encrypted if method unknown

            # Display the decrypted image
            self.loaded_decrypted_label.setText(f"Decrypted Image\n(ID: {db_id}, Method: {method})")
            if decrypted_bgr is not None:
                decrypted_rgb = cv2.cvtColor(decrypted_bgr, cv2.COLOR_BGR2RGB)
                qt_image_decrypted = self.convert_cv_qt(decrypted_rgb)
                self.display_pixmap(self.loaded_decrypted_label, qt_image_decrypted)
            else:
                 self.loaded_decrypted_label.setPixmap(QPixmap()) # Clear if decryption failed
                 self.loaded_decrypted_label.setText("Decrypted Image\n(Decryption Failed)")


            self.statusBar().showMessage(f"Loaded and decrypted image ID: {db_id}.")

        except sqlite3.Error as e:
            self.show_error_message(f"Database Load/Decrypt Error: {e}")
        except Exception as e:
             self.show_error_message(f"Error loading/decrypting frame ID {db_id}: {e}")
             # Clear display labels on generic error too
             self.loaded_encrypted_label.setText("Loaded Encrypted Image\n(Error)")
             self.loaded_encrypted_label.setPixmap(QPixmap())
             self.loaded_decrypted_label.setText("Decrypted Image\n(Error)")
             self.loaded_decrypted_label.setPixmap(QPixmap())


    def show_error_message(self, message):
        print(f"Error: {message}")
        self.statusBar().showMessage(f"Error: {message}", 5000)
        # Consider using QMessageBox for more critical errors if needed
        # QMessageBox.critical(self, "Error", message)

    def closeEvent(self, event):
        self.stop_camera()
        if self.camera_thread and self.camera_thread.isRunning():
             self.camera_thread.quit()
             self.camera_thread.wait(500) # Shorter wait
        event.accept()

# --- Main Execution ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec())