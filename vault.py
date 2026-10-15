"""Encrypted vault for protected private files.

protect_file()  encrypts a file into vault/, checks the copy, then deletes the original.
grant_files()   decrypts chosen files into granted/ as read-only copies for a time window.
lock_file()     deletes the open copy. The encrypted vault copy is never changed.

The vault key is derived from the owner passphrase, so the vault cannot be read
without it. Only files the owner has granted exist in plain form, and only for a
limited time.
"""

import hashlib
import os
import re
import stat
import uuid
from datetime import datetime, timedelta

from cryptography.fernet import Fernet, InvalidToken

import security_store as store

MAX_BYTES = 200 * 1024 * 1024


class VaultError(Exception):
    """A vault operation failed."""


class PassphraseError(VaultError):
    """The passphrase is wrong, or the owner profile is not set up."""


def _inside(path, folder):
    try:
        return os.path.commonpath(
            [os.path.abspath(path), os.path.abspath(folder)]
        ) == os.path.abspath(folder)
    except ValueError:
        return False


def _safe_name(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120] or "file"


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _write_atomic(path, data):
    temp = path + ".tmp"
    with open(temp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def _remove(path):
    if path and os.path.exists(path):
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)  # clears the read-only flag on Windows
        os.remove(path)


def _fernet(passphrase):
    if not store.owner_configured():
        raise PassphraseError("The owner profile is not set up yet. Open /security first.")
    key = store.unlock_key(passphrase or "")
    if key is None:
        raise PassphraseError("Wrong passphrase.")
    return Fernet(key)


def protect_file(path, passphrase):
    """Encrypt a private file into the vault and delete the original. Returns the file id."""
    fernet = _fernet(passphrase)
    full = os.path.abspath(path)
    if not os.path.isfile(full):
        raise VaultError(f"File not found: {full}")
    if _inside(full, store.PROJECT_DIR):
        raise VaultError("Files inside the CYBER ECHO project folder cannot be protected.")
    size = os.path.getsize(full)
    if size > MAX_BYTES:
        raise VaultError("The file is larger than 200 MB.")
    if store.find_protected_by_path(full):
        raise VaultError("This file is already protected.")

    with open(full, "rb") as handle:
        data = handle.read()
    digest = _digest(data)

    os.makedirs(store.VAULT_DIR, exist_ok=True)
    vault_path = os.path.join(store.VAULT_DIR, uuid.uuid4().hex + ".vault")
    _write_atomic(vault_path, fernet.encrypt(data))

    try:
        with open(vault_path, "rb") as handle:
            try:
                check = fernet.decrypt(handle.read())
            except InvalidToken as error:
                raise VaultError("The encrypted copy could not be read back. Original kept.") from error
        if _digest(check) != digest:
            raise VaultError("The encrypted copy failed verification. Original kept.")
        file_id = store.add_protected(full, os.path.basename(full), vault_path, digest, size)
    except BaseException:
        _remove(vault_path)
        raise

    try:
        _remove(full)
    except OSError as error:
        store.delete_protected(file_id)
        _remove(vault_path)
        raise VaultError(
            f"The original could not be deleted, so protection was cancelled: {error}"
        ) from error
    return file_id


def grant_files(file_ids, passphrase, minutes):
    """Decrypt chosen files into read-only copies that expire after `minutes`."""
    fernet = _fernet(passphrase)
    expires = store.stamp(datetime.now() + timedelta(minutes=minutes))
    os.makedirs(store.GRANTED_DIR, exist_ok=True)
    granted = []
    for file_id in file_ids:
        row = store.get_protected(file_id)
        if row is None:
            continue
        try:
            with open(row["vault_path"], "rb") as handle:
                data = fernet.decrypt(handle.read())
        except (OSError, InvalidToken) as error:
            raise VaultError(f"Could not open the vault copy of {row['file_name']}.") from error
        if _digest(data) != row["sha256"]:
            raise VaultError(f"The vault copy of {row['file_name']} failed verification.")

        target = os.path.join(store.GRANTED_DIR, f"{file_id}_{_safe_name(row['file_name'])}")
        _remove(target)
        _write_atomic(target, data)
        os.chmod(target, stat.S_IREAD)
        store.set_granted(file_id, target, expires)
        granted.append({"id": file_id, "file_name": row["file_name"], "path": target})
    return granted


def lock_file(file_id):
    row = store.get_protected(file_id)
    if row is None:
        return False
    try:
        _remove(row["granted_path"])
    except OSError as error:
        raise VaultError(f"Could not remove the open copy of {row['file_name']}: {error}") from error
    store.set_locked(file_id)
    return True


def lock_all(reason="manual"):
    locked = 0
    for row in store.list_granted():
        try:
            lock_file(row["id"])
            locked += 1
        except VaultError as error:
            print(f"[VAULT WARNING] {error}")
    if locked:
        print(f"[VAULT] Locked {locked} file(s): {reason}.")
    return locked


def sweep_expired():
    for row in store.list_expired_grants(store.stamp()):
        try:
            lock_file(row["id"])
            print(f"[VAULT] Access window ended. Locked {row['file_name']}.")
        except VaultError as error:
            print(f"[VAULT WARNING] {error}")


def restore_file(file_id, passphrase):
    """Put a protected file back at its original location and remove it from the vault.

    Needs the passphrase. Refuses if a file already exists at the original location,
    so nothing is overwritten. Returns the restored path.
    """
    fernet = _fernet(passphrase)
    row = store.get_protected(file_id)
    if row is None:
        raise VaultError("That file is not in the vault.")
    try:
        with open(row["vault_path"], "rb") as handle:
            data = fernet.decrypt(handle.read())
    except (OSError, InvalidToken) as error:
        raise VaultError(f"Could not open the vault copy of {row['file_name']}.") from error
    if _digest(data) != row["sha256"]:
        raise VaultError(f"The vault copy of {row['file_name']} failed verification.")
    original = row["original_path"]
    if os.path.exists(original):
        raise VaultError("A file already exists at the original location. Move it away first.")

    os.makedirs(os.path.dirname(original) or ".", exist_ok=True)
    _write_atomic(original, data)      # write the restored file first
    lock_file(file_id)                 # then remove any open copy
    store.delete_protected(file_id)
    _remove(row["vault_path"])
    return original

