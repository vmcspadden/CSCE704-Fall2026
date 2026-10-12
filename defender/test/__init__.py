import requests

import tarfile
import zipfile
import zlib
import pathlib

import time
import tqdm
import json

import numpy as np
import os

try:
    # optional: the standard zipfile module cannot read AES-encrypted archives
    # (e.g. the ones downloaded from MalwareBazaar); pyzipper can
    import pyzipper
except ImportError:
    pyzipper = None

MAXFILESIZE = 2**21  # 2 MiB
TIMEOUT = 5
ZIP_PASSWORDS = [b'', b'infected']

# CUSTOMIZE: the assignment's goals, used only to print PASS/FAIL in the summary
GOAL_MAX_FPR = 0.01
GOAL_MIN_TPR = 0.95

# TINY PE FILES
MZHEADER = b'MZ'

TINYPE97 = (b'MZ\x00\x00PE\x00\x00L\x01\x01\x00j*X\xc3\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x04\x00\x03\x01\x0b\x01\x08\x00\x04\x00\x00\x00\x00\x00\x00\x00\x04\x00'
            b'\x00\x00\x0c\x00\x00\x00\x04\x00\x00\x00\x0c\x00\x00\x00\x00\x00@\x00\x04'
            b'\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00'
            b'\x00\x00\x00\x00\x00h\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x00\x02')

TINYIMPORT = (b'MZ\x00\x00PE\x00\x00L\x01\x01\x00j*X\xc3\x00\x00\x00\x00\x00\x00\x00\x00'
              b'\x04\x00\x03\x01\x0b\x01\x08\x00\x98\x00\x00\x00\x00\x00\x00\x00\x95\x00'
              b'\x00\x00\x0c\x00\x00\x00\x95\x00\x00\x00\x0c\x00\x00\x00\x00\x00@\x00\x04'
              b'\x00\x00\x00\x04\x00\x00\x00\x94\x00\x00\x00\x8c\x00\x00\x00\x04\x00\x00'
              b'\x00\x00\x00\x00\x00$\x01\x00\x00\x8c\x00\x00\x00\x00\x00\x00\x00\x02\x00'
              b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
              b'\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x008\x00\x00'
              b'\x00(\x00\x00\x00\x01\x00\x00\x80\x00\x00\x00\x00KERNEL32.dll\x00')


def _read_zip_member(archive, info, location, passwords):
    # returns the member's bytes; `passwords` is reordered in place so that the
    # password that worked is tried first for the next member
    if info.compress_type == 99 and pyzipper is None:  # 99 = WinZip AES encryption
        raise RuntimeError(
            f"{location} is AES-encrypted, which Python's zipfile module cannot read. "
            f"Install pyzipper (pip install pyzipper) and run the test again.")
    for ix, pwd in enumerate(passwords):
        try:
            content = archive.read(info.filename, pwd=pwd)
        except NotImplementedError:
            raise RuntimeError(
                f"{location} uses an encryption or compression method that Python's zipfile "
                f"module cannot read (AES-encrypted archives need: pip install pyzipper)")
        except (RuntimeError, zipfile.BadZipFile, zlib.error):
            # wrong password (a wrong one occasionally gets past the first
            # check and then fails the CRC test or the decompression instead)
            continue
        passwords.insert(0, passwords.pop(ix))
        return content
    raise Exception(f"Unable to guess ZIP encryption passwords for {location}")


def file_bytes_generator(location, maxsize, return_filename=True, recursive=False):
    # yields (name,bytes) for files smaller than `maxsize` and that begin with b'MZ'
    # works for tar (including bz2, gz), zip, and directories
    path = pathlib.Path(location)
    if path.is_file():
        if location.lower().endswith('.zip'):
            passwords = list(ZIP_PASSWORDS)
            zip_class = pyzipper.AESZipFile if pyzipper else zipfile.ZipFile
            with zip_class(location, 'r') as f:
                for info in f.infolist():
                    if info.filename.endswith('/'):
                        continue  # a folder entry
                    if info.file_size <= maxsize:
                        content = _read_zip_member(f, info, location, passwords)

                        if content.startswith(b'MZ'):
                            yield (os.path.join(location, info.filename), content) if return_filename else content

        elif location.lower().endswith('.tar') or location.lower().endswith('.tar.bz2') or location.lower().endswith('.tar.gz') or location.lower().endswith('.tgz'):
            with tarfile.open(location, mode='r') as tar:
                for member in tar:
                    if member.size <= maxsize:
                        f = tar.extractfile(member)
                        if f:
                            content = f.read()
                            if content.startswith(b'MZ'):
                                yield (os.path.join(location, member.name), content) if return_filename else content

        else:
            raise ValueError(
                f"{location}: expected a folder or a .zip, .tar, .tar.gz, .tgz or .tar.bz2 archive")

    elif path.is_dir():
        # sorted, so that two runs test the files in the same order
        for filepath in sorted(path.rglob('*') if recursive else path.glob('*')):
            try:
                if filepath.is_file() and filepath.stat().st_size <= maxsize:
                    with open(filepath, 'rb') as infile:
                        content = infile.read()
                    if content.startswith(b'MZ'):
                        yield (str(filepath.relative_to(path)), content) if return_filename else content
            except OSError:
                # unreadable file (permissions, broken link, ...): skip it
                continue


def get_raw_result(bytez, url, timeout):
    return requests.post(url, data=bytez, headers={'Content-Type': 'application/octet-stream'}, timeout=timeout)


def get_result(bytez, url, timeout, raise_exception=False):
    error_msg = None
    res = None
    start = time.time()
    try:
        res = get_raw_result(bytez, url, timeout)
        result = res.json()['result']
        # the answer must be exactly the integer 0 or 1
        if type(result) is not int or result not in (0, 1):
            raise ValueError(f'expected "result" to be 0 or 1, but received {result!r}')
    except (requests.RequestException, KeyError, TypeError, ValueError) as e:
        result = 0  # timeout or other error results in benign
        error_msg = str(e) or type(e).__name__
        # (a response object is "falsy" for HTTP errors, so test against None
        # to also record what a 4xx/5xx response said)
        if res is not None:
            error_msg += f' - HTTP {res.status_code}: {res.text[:200]!r}'
        if raise_exception:
            raise(e)

    elapsed = time.time() - start

    # `timeout` only limits how long the service may stay silent; an answer
    # that arrives after the deadline is still a timeout for the assignment
    if error_msg is None and elapsed > timeout:
        result = 0
        error_msg = f'answer took {elapsed:.2f}s (limit {timeout}s)'

    return result, elapsed, error_msg


def measure_efficacy(benignfiles, maliciousfiles, url, maxfilesize, timeout, silent=False, stop_after=None, raise_exception=False, recursive=False):
    y_true = []
    y_pred = []
    elapsed = []
    error = []
    fps = []
    fns = []
    errors = []

    for i, (fname, bytez) in tqdm.tqdm(enumerate(file_bytes_generator(maliciousfiles, maxfilesize, recursive=recursive)), desc="malicious", disable=silent):
        if stop_after and i >= stop_after:
            break
        y_true.append(1)
        y, t, e = get_result(bytez, url, timeout, raise_exception)
        y_pred.append(y)
        elapsed.append(t)
        error.append(0 if e is None else 1)
        if e:
            errors.append((fname, e))
        if y != 1:
            fns.append(fname)

    for i, (fname, bytez) in tqdm.tqdm(enumerate(file_bytes_generator(benignfiles, maxfilesize, recursive=recursive)), desc="benign", disable=silent):
        if stop_after and i >= stop_after:
            break
        y_true.append(0)
        y, t, e = get_result(bytez, url, timeout, raise_exception)
        y_pred.append(y)
        elapsed.append(t)
        error.append(0 if e is None else 1)
        if e:
            errors.append((fname, e))
        if y != 0:
            fps.append(fname)

    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    elapsed = np.array(elapsed)
    error = np.array(error)

    n_malicious = int(np.sum(y_true == 1))
    n_benign = int(np.sum(y_true == 0))
    if n_malicious == 0 or n_benign == 0:
        which = "malicious" if n_malicious == 0 else "benign"
        raise ValueError(
            f"no {which} samples were tested: only files that start with b'MZ' and are at most "
            f"{maxfilesize} bytes are used (see --max), and folders are only searched in depth "
            f"with --recursive")

    summary = {
        'tested': len(y_true),
        'malicious': n_malicious,
        'benign': n_benign,
        'fp': float(len(fps) / n_benign),    # false positive rate
        'fn': float(len(fns) / n_malicious),  # false negative rate
        'tpr': float(1 - len(fns) / n_malicious),  # true positive rate (detection rate)
        'false_positives': len(fps),
        'false_negatives': len(fns),
        'errors': int(sum(error)),  # includes timeouts and other errors
        'max_time': float(elapsed.max()),
        'avg_time': float(np.mean(elapsed))
    }

    return summary, fps, fns, errors


def informational(url, timeout):
    def get_json_string_result_for(bytez):
        res = get_raw_result(bytez, url, timeout)
        try:
            return json.dumps(res.json())
        except ValueError:
            # not JSON: show what came back instead of crashing the whole run
            return f'HTTP {res.status_code}, not JSON: {res.text[:80]!r}'

    result = f'''
    Preliminary tests:
    \tMZ header: {get_json_string_result_for(MZHEADER)}
    \tTiny PE FILE with no imports: {get_json_string_result_for(TINYPE97)}
    \tTiny PE FILE with import: {get_json_string_result_for(TINYIMPORT)}'''

    return result
