import argparse
import sys
from encryptor import encrypt_file, decrypt_file, encrypt_directory

def main():
    parser = argparse.ArgumentParser(
        description="AES-GCM 文件加密工具",
        epilog="示例:\n  加密: cli.exe encrypt file.txt pass\n  解密: cli.exe decrypt file.txt.enc pass\n  批量: cli.exe encrypt-dir ./docs pass --ext .txt",
        formatter_class=argparse.RawTextHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", help="命令")

    enc = sub.add_parser("encrypt")
    enc.add_argument("file")
    enc.add_argument("password")

    dec = sub.add_parser("decrypt")
    dec.add_argument("file")
    dec.add_argument("password")

    enc_dir = sub.add_parser("encrypt-dir")
    enc_dir.add_argument("directory")
    enc_dir.add_argument("password")
    enc_dir.add_argument("--no-recursive", action="store_true")
    enc_dir.add_argument("--ext", nargs="*")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "encrypt":
        encrypt_file(args.file, args.password)
    elif args.command == "decrypt":
        decrypt_file(args.file, args.password)
    elif args.command == "encrypt-dir":
        recursive = not args.no_recursive
        extensions = args.ext
        encrypt_directory(args.directory, args.password, recursive, extensions)

if __name__ == "__main__":
    main()
