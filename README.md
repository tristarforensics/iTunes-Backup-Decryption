# iTunes-Backup-Decryption
Python tools for decrypting iOS backups. Tested up to iOS 14.3. The script will decrypt an encrypted iOS backup and output it to a specified directory in the directory structure specified in the Manifest.db file.
I saw most of this code posted by the Stack Exchange user andrewdotn, who got the main code base from security researchers Jean-Baptiste Bedrune and Jean Sigwald. I had to fix some broken dependencies, as well as change the input/output of the script to work better for my purposes, so the previously mentioned individuals deserve all the credit. The aes_keywrap python functions are from GitHub user kurtbrose. Special thanks to these individuals.

Usage:
decryptor_CLI.py InputDirectory OutputDirectory Password. 
You must download both of these files, as the decryptor script utilizes functions from the aes_keywrap script. The aes_keywrap.py file must be in the same directory as decryptor_CLI.py.

Dependencies:
pycryptodome and biplist.
pip install both of these to get latest version. The latest versions tested with this script are kept in the dependencies folder. There is a wheel for pycryptodome, and the source code for biplist.

Issues:
Let me know if you have any questions or need help getting it to work!
