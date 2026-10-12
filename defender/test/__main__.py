import argparse
from test import (informational, measure_efficacy, MAXFILESIZE, TIMEOUT, TINYIMPORT, get_raw_result,
                  GOAL_MAX_FPR, GOAL_MIN_TPR)
import json
import pathlib
import requests
import sys


def main():
    parser = argparse.ArgumentParser(
        description="Test defense ML docker image", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        '-m', required=True, type=str, help='folder or archive (ZIP or TAR.GZ or TAR.BZ2) containing malicious samples')
    parser.add_argument(
        '-b', required=True, type=str, help='folder or archive (ZIP or TAR.GZ or TAR.BZ2) containing benign samples')
    parser.add_argument('--url', type=str, default='http://127.0.0.1:8080/',
                        help='URL address of ML detection service')
    parser.add_argument('--max', type=int, default=MAXFILESIZE,
                        help="maximum file size to read from folder/archive (larger files are skipped)")
    parser.add_argument('--stopafter', type=int, default=5000,
                        help="test up to this many files in each folder/archive")
    parser.add_argument('--timeout', type=float,
                        default=TIMEOUT, help="timeout for requests, in seconds")
    parser.add_argument('--recursive', action='store_true',
                        help="also test the files in sub-folders of a samples folder")
    args = parser.parse_args()

    for flag, location in (('-b', args.b), ('-m', args.m)):
        if not (pathlib.Path(location).is_file() or pathlib.Path(location).is_dir()):
            parser.error(f'{flag}: samples path does not exist: {location}')

    # check the format of responses
    try:
        res = get_raw_result(TINYIMPORT, args.url, args.timeout)
    except requests.RequestException as e:
        sys.exit(f'Error calling service at {args.url}: {e}')

    try:
        json_result = res.json()
    except ValueError:
        sys.exit(f'Expected json response, but received HTTP {res.status_code} "{res.text[:200]}"')

    if not isinstance(json_result, dict) or 'result' not in json_result:
        sys.exit(f'Expected JSON with "result" key, but received {json.dumps(json_result)}')

    # check that the response is an integer (0 or 1)
    if type(json_result['result']) is not int or json_result['result'] not in (0, 1):
        sys.exit(f'Expected the integer 0 or 1 as "result" but received {json.dumps(json_result)}')

    # provide information on some benign corner cases
    print(informational(args.url, args.timeout))

    # efficacy test: malicious files are tested first, which helps measure FP rate for stateful defenses
    try:
        summary, fps, fns, errors = measure_efficacy(
            args.b, args.m, args.url, args.max, args.timeout, stop_after=args.stopafter,
            recursive=args.recursive)
    except ValueError as e:
        sys.exit(f'Error: {e}')

    with open('fps.txt', 'w') as outfile:
        for fp in fps:
            outfile.write(f'{fp}\n')

    with open('fns.txt', 'w') as outfile:
        for fn in fns:
            outfile.write(f'{fn}\n')

    with open('errors.txt', 'w') as outfile:
        for fn, e in errors:
            outfile.write(f'{fn}\t{e}\n')

    print('Summary:')
    print(json.dumps(summary, indent=2))

    # errors and timeouts are already counted as "benign" answers above, so a
    # crash or a slow answer on a malicious file lowers the TPR
    def verdict(ok):
        return 'PASS' if ok else 'FAIL'

    print('Goals:')
    print(f"  FPR {summary['fp']:.2%} (goal <= {GOAL_MAX_FPR:.0%}): {verdict(summary['fp'] <= GOAL_MAX_FPR)}")
    print(f"  TPR {summary['tpr']:.2%} (goal >= {GOAL_MIN_TPR:.0%}): {verdict(summary['tpr'] >= GOAL_MIN_TPR)}")
    print(f"  slowest answer {summary['max_time']:.2f}s (limit {args.timeout:g}s): "
          f"{verdict(summary['max_time'] <= args.timeout)}")
    print('Files listed in fps.txt (false positives), fns.txt (false negatives) and errors.txt.')


if __name__ == '__main__':
    main()