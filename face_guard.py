"""Webcam owner check.

When this program runs (start it at Windows logon, see README.txt), it takes a few
webcam frames and compares every face with the enrolled owner photos.

  AUTHORIZED     the owner is in front of the camera. Nothing changes.
  UNAUTHORIZED   a face does not match the owner (confirmed on two frames).
                 Protected files are locked, a snapshot is saved, and the owner
                 is emailed a YES/NO question. Access is granted only if the owner
                 answers YES and enters the passphrase on the approval page.
  NO_FACE, INCONCLUSIVE, NO_CAMERA   logged only. Nothing is locked.

Run:  py face_guard.py
"""

import os
import time
import uuid
from datetime import datetime, timedelta

import cv2
import numpy as np

import notifier
import security_store as store
import threat_watch
import vault

YUNET_FILE = "face_detection_yunet_2023mar.onnx"
SFACE_FILE = "face_recognition_sface_2021dec.onnx"
COSINE_THRESHOLD = 0.363  # OpenCV's recommended cosine threshold for SFace
MAX_FRAMES = 4
CONFIRM_FRAMES = 2
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
CAMERA_INDEX = int(os.environ.get("CYBER_ECHO_CAMERA_INDEX", "0"))
CHECK_MINUTES = float(os.environ.get("CYBER_ECHO_CHECK_MINUTES", "10"))
THREAT_MINUTES = float(os.environ.get("CYBER_ECHO_THREAT_CHECK_MINUTES", "5"))
COOLDOWN_MINUTES = float(os.environ.get("CYBER_ECHO_COOLDOWN_MINUTES", "30"))
GRANT_MINUTES = int(os.environ.get("CYBER_ECHO_GRANT_MINUTES", "60"))
REQUEST_TTL_HOURS = 24
APPROVAL_BASE = os.environ.get(
    "CYBER_ECHO_APPROVAL_URL", "http://127.0.0.1:5000"
).rstrip("/")


class ModelsMissing(Exception):
    """The two face model files are not in the models folder."""


class EnrollmentError(Exception):
    """An uploaded photo cannot be used for enrollment."""


_engine = None


def models_present():
    return all(
        os.path.isfile(os.path.join(store.MODELS_DIR, name))
        for name in (YUNET_FILE, SFACE_FILE)
    )


def get_engine():
    global _engine
    if _engine is None:
        if not models_present():
            raise ModelsMissing(
                f"Face models not found in {store.MODELS_DIR}. "
                "See README.txt, section 'Face models'."
            )
        detector = cv2.FaceDetectorYN.create(
            os.path.join(store.MODELS_DIR, YUNET_FILE), "", (320, 320), 0.8, 0.3, 5000
        )
        recognizer = cv2.FaceRecognizerSF.create(
            os.path.join(store.MODELS_DIR, SFACE_FILE), ""
        )
        _engine = (detector, recognizer)
    return _engine


def decide(face_scores, threshold=COSINE_THRESHOLD):
    """Pure decision rule. face_scores holds the best owner-match score for each face."""
    if not face_scores:
        return "NO_FACE"
    if any(score < threshold for score in face_scores):
        return "UNAUTHORIZED"  # at least one face is not the owner
    return "AUTHORIZED"


def face_features(engine, frame):
    detector, recognizer = engine
    height, width = frame.shape[:2]
    detector.setInputSize((width, height))
    _, faces = detector.detect(frame)
    if faces is None:
        return []
    return [recognizer.feature(recognizer.alignCrop(frame, face)) for face in faces]


def score_frame(engine, frame, owner_arrays):
    _, recognizer = engine
    scores = []
    for feature in face_features(engine, frame):
        best = max(
            recognizer.match(feature, owner, cv2.FaceRecognizerSF_FR_COSINE)
            for owner in owner_arrays
        )
        scores.append(float(best))
    return scores


def grab_frames(count, gap_seconds=1.0):
    backend = cv2.CAP_DSHOW if os.name == "nt" else cv2.CAP_ANY
    capture = cv2.VideoCapture(CAMERA_INDEX, backend)
    frames = []
    try:
        if not capture.isOpened():
            return frames
        for _ in range(5):  # let auto-exposure settle
            capture.read()
            time.sleep(0.2)
        for _ in range(count):
            ok, frame = capture.read()
            if ok and frame is not None:
                frames.append(frame)
            time.sleep(gap_seconds)
    finally:
        capture.release()
    return frames


def run_owner_check():
    """Return (result, best_score, face_count, frame)."""
    owner = store.get_owner_features()
    if not owner:
        return "NOT_ENROLLED", None, 0, None
    try:
        engine = get_engine()
    except ModelsMissing as error:
        print(f"[FACE GUARD] {error}")
        return "MODELS_MISSING", None, 0, None

    owner_arrays = [np.array(vector, dtype=np.float32).reshape(1, -1) for vector in owner]
    frames = grab_frames(MAX_FRAMES)
    if not frames:
        return "NO_CAMERA", None, 0, None

    unknown = []
    for frame in frames:
        scores = score_frame(engine, frame, owner_arrays)
        verdict = decide(scores)
        if verdict == "AUTHORIZED":
            return "AUTHORIZED", max(scores), len(scores), frame
        if verdict == "UNAUTHORIZED":
            unknown.append((frame, scores))
            if len(unknown) >= CONFIRM_FRAMES:
                saved_frame, saved_scores = unknown[-1]
                return "UNAUTHORIZED", min(saved_scores), len(saved_scores), saved_frame
    if unknown:
        return "INCONCLUSIVE", min(min(scores) for _, scores in unknown), 0, None
    return "NO_FACE", None, 0, None


def enroll_from_images(blobs):
    """Return one feature vector per uploaded photo. Each photo must show exactly one face."""
    engine = get_engine()
    features = []
    for number, data in enumerate(blobs, start=1):
        if len(data) > MAX_UPLOAD_BYTES:
            raise EnrollmentError(f"Photo {number} is larger than 5 MB.")
        image = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
        if image is None:
            raise EnrollmentError(f"Photo {number} is not a readable image.")
        faces = face_features(engine, image)
        if len(faces) != 1:
            raise EnrollmentError(
                f"Photo {number} must show exactly one face (found {len(faces)})."
            )
        features.append(faces[0].flatten().astype(float).tolist())
    return features


def save_snapshot(frame):
    os.makedirs(store.SNAPSHOT_DIR, exist_ok=True)
    name = f"{datetime.now():%Y%m%d_%H%M%S}_{uuid.uuid4().hex[:8]}.jpg"
    path = os.path.join(store.SNAPSHOT_DIR, name)
    cv2.imwrite(path, frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
    return path


def unauthorized_email(approval_link, locked_names, device, when):
    names = "\n".join(f"  - {name}" for name in locked_names)
    if not names:
        names = "  (no protected files are registered yet)"
    subject = f"[CYBER ECHO] UNAUTHORIZED USER on {device} - do you grant access?"
    body = (
        "CYBER ECHO SECURITY ALERT\n\n"
        "An UNAUTHORIZED user was detected at your device.\n"
        "This user is NOT authorised: the face at the camera does not match the enrolled owner.\n\n"
        f"Device : {device}\n"
        f"Time   : {when}\n"
        "Photo  : attached (taken by the webcam)\n\n"
        "Protected files have been LOCKED automatically:\n"
        f"{names}\n\n"
        "DO YOU WANT TO GRANT ACCESS TO THIS USER?\n\n"
        "Open this link and answer YES or NO:\n"
        f"{approval_link}\n\n"
        "  YES - you choose which protected files to share. Your CYBER ECHO passphrase is required.\n"
        f"        Access ends automatically after {GRANT_MINUTES} minutes.\n"
        "  NO  - the user stays unauthorised. All protected files stay locked.\n\n"
        f"If you do not answer within {REQUEST_TTL_HOURS} hours, the request expires and files stay locked.\n"
        "If you do not recognise this person, check the device now.\n\n"
        "No protected file was deleted in this step. Protected files stay encrypted in the vault.\n"
        "The link works only if CYBER_ECHO_APPROVAL_URL points to an address you can reach.\n"
    )
    return subject, body


def handle_result(result, best_score, face_count, frame):
    store.log_face_check(result, best_score, face_count)
    now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    detail = f" (best match {best_score:.3f})" if best_score is not None else ""
    print(f"[{now_text}] Owner check: {result}{detail}")

    if result != "UNAUTHORIZED":
        return

    store.expire_old_requests()
    if store.approved_grant_active():
        print("An approved access window is open. Not locking again.")
        return

    vault.lock_all("unauthorised user detected")

    if store.pending_exists():
        print("A decision is already waiting for the owner. No new email sent.")
        return
    last = store.last_request_time()
    if last and datetime.now() - last < timedelta(minutes=COOLDOWN_MINUTES):
        print("Inside the notification cooldown. No new email sent.")
        return

    snapshot = save_snapshot(frame)
    token = store.new_token()
    store.create_request(store.hash_token(token), snapshot, REQUEST_TTL_HOURS, best_score)
    link = f"{APPROVAL_BASE}/security/respond/{token}"
    device = notifier.device_name()
    locked_names = [row["file_name"] for row in store.list_protected()]
    subject, body = unauthorized_email(link, locked_names, device, now_text)
    ok, info = notifier.send_email(subject, body, attachments=[snapshot])
    print("Owner email sent." if ok else f"[EMAIL] Not sent: {info}")


def main():
    store.connect().close()
    print()
    print("==========================================")
    print("          CYBER ECHO FACE GUARD")
    print("==========================================")
    print(f"Owner check every {CHECK_MINUTES:g} minutes.")
    print(f"Threat check every {THREAT_MINUTES:g} minutes.")
    print("Press CTRL+C to stop.")
    print()

    next_check = 0.0
    next_threat = 0.0
    try:
        while True:
            now = time.time()
            try:
                vault.sweep_expired()
            except Exception as error:  # keep the guard running
                print(f"[VAULT ERROR] {error}")

            if now >= next_check:
                try:
                    handle_result(*run_owner_check())
                except Exception as error:
                    print(f"[FACE GUARD ERROR] {error}")
                next_check = now + CHECK_MINUTES * 60

            if now >= next_threat:
                try:
                    threat_watch.check_and_notify()
                except Exception as error:
                    print(f"[THREAT WATCH ERROR] {error}")
                next_threat = now + THREAT_MINUTES * 60

            time.sleep(15)
    except KeyboardInterrupt:
        print()
        print("CYBER ECHO face guard stopped.")


if __name__ == "__main__":
    main()
