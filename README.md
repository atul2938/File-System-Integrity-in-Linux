# File-System-Integrity-in-Linux
Implemented a secure library (SecureFS) on top of the existing file system interfaces that raises the alarm if the integrity of the files created through the secure library APIs is compromised. At the high-level, SecureFS maintains a Merkle tree for every file to check the consistency of file blocks before every read and write. The root of the Merkle tree is saved on disk to verify the integrity of files after reboot.

# 1. Cryptographic hash function
A cryptographic hash function generates a 20 bytes hash value of a given string of any length. The hash is computed in such a manner that it is infeasible to and two strings whose hash value are the same.

# 2. Merkle tree
A Merkle tree is a tree of hashes of data blocks. The file is divided into data blocks (you have to use 64 bytes data blocks) of fixed size. The leaf nodes of a Merkle tree are the hash values of file blocks. An internal node of a Merkletree is the hash of concatenation of hashes of its child nodes. The root of the Merkel tree is the unique hash of entire file.

# 3. Integrity check
To check the integrity of file, SecureFS computes a unique hash value from the file contents and store in secure.txt file. SecureFS assumes that secure.txt cannot be tampered. When a file is opened, SecureFS creates a Merkle tree (in memory) from the file blocks. secure.txt contains the root of the Merkle tree corresponding to every file created by the SecureFS interface. Whenever a file is modified the Merkle tree is updated, and the root of the Merkle tree is synced with the secure.txt. The in-memory Merkle tree is deleted when the file is closed.

# 4. Implementation
get sha1 hash returns a 20 bytes hash value of an input buffer of a given length. The nodes of the Merkle tree contains the 20 bytes hash returned through get sha1 hash API. To create a Merkle tree, you have to divide the files into 64 bytes blocks. You are to implement the following interfaces in filesys.c.
* filsys init: filesys init creates the secure.txt file if it doesn't exist. It also checks the integrity of all the files whose hashes are present in secure.txt. If a file doesn't exist, filesys init removes the corresponding entry from secure.txt. If the integrity of an existing file is compromised filesys init returns 1. filesys init returns 0 on success.
* s open: s open builds the Merkle tree from the file data and compares the root hash with the one stored in secure.txt. s open returns -1, if the integrity check fails. If the file doesn't exist, a new entry is created in secure.txt. If the file is going to be truncated, s open updates the Merkle tree and secure.txt entry accordingly.
* s read: s read computes the blocks of the file that need to be read. After reading these blocks s read checks the integrity using the Merkle tree. If the integrity check fails, then -1 is returned to the caller.
* s write: Before writing, s write checks the integrity of file blocks that are going to be modified. On failing the integrity check, -1 is returned to the caller. s write updates the Merkle tree, synchronize root hash with
secure.txt and write modified blocks of the file.
* s lseek: s lseek ensures that SEEK END points to the size of the file updated through the SecureFS APIs.

Install "libssl-dev" package by running **sudo apt-get install libssl-dev**

To execute, run following command : **make and make run**

Contributors : Atul Anand, Dashmesh Singh, Kanupriya Singh
