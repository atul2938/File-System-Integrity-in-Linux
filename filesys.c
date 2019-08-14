#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "filesys.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include<stdlib.h>
#include<math.h>

static int filesys_inited = 0;

int fs[8];

/* returns 20 bytes unique hash of the buffer (buf) of length (len)
 * in input array sha1.
 */
void get_sha1_hash (const void *buf, int len, const void *sha1)
{
	SHA1 ((unsigned char*)buf, len, (unsigned char*)sha1);
}

// creates merkel tree and return root hash
char * merkel(char hashes[][21], int total_blocks){

	if(total_blocks==1)
	{
		return hashes[0];
	}

	int pcount=total_blocks/2;
	if(total_blocks%2!=0){
		pcount+=1;
	}
	
	char pHashes[pcount][21];
	char ghashes[41];

	for(int i=0; i<total_blocks-1;i+=2)
	{
		char *g=ghashes;
		char *h=hashes[i];
		for(int j=0;j<20;j++){
			*(g++)=*(h++);
		}
		h=hashes[i+1];
		for(int j=0;j<20;j++){
			*(g++)=*(h++);
		}
		get_sha1_hash(ghashes,40,pHashes[i/2]);
	}

	if(total_blocks%2!=0){
		get_sha1_hash(hashes[total_blocks-1],20,pHashes[total_blocks/2]);
	}

	return merkel(pHashes, pcount);
}

// calls merkel after calculating the hashes of all the blocks
char * merkel_tree(char blocks[][65], int total_blocks){
	char hashes[total_blocks][21];

	for(int i=0;i<total_blocks;i++)
	{
		if(i==total_blocks-1)
		{
			//manually for last block since it may have less than 64 bytes.
			int numchar=0;
			for(int ctr=0;blocks[i][ctr]!='\0';ctr++)
			{
				numchar++;
			}
			get_sha1_hash(blocks[i],numchar,hashes[i]);
		}
		else
		{
			get_sha1_hash(blocks[i],64,hashes[i]);
		}
		hashes[i][20]='\0';
	}

	return merkel(hashes, total_blocks);
}


/* Build an in-memory Merkle tree for the file.
 * Compare the integrity of file with respect to
 * root hash stored in secure.txt. If the file
 * doesn't exist, create an entry in secure.txt.
 * If an existing file is going to be truncated
 * update the hash in secure.txt.
 * returns -1 on failing the integrity check.
 */
int s_open (const char *pathname, int flags, mode_t mode)
{
	struct stat buffer;
	int x=stat(pathname,&buffer);

	if( x== 0 )
	{
		//file exists in the directory
		int fd_file= open(pathname, O_RDWR, mode,0666);
		struct stat buf;
		fstat(fd_file, &buf);
		int size=buf.st_size;

		if(size!=0)							// if file is not empty
		{
			//build merkel tree of the file
			int total_blocks=size/64;
			if(size%64!=0)
			{
				total_blocks+=1;
			}

			char block[total_blocks][65];
			int i=0;
			char *dataValues= (char *)malloc( 65*sizeof(char));
			int r;

			while((r=read(fd_file,dataValues,64))==64)
			{
				dataValues[64]='\0';
				strcpy(block[i],dataValues);
				block[i][64]='\0';
				i++;
			}

			if(r!=0)
			{	
				
				dataValues[r]='\0';
				char *b=block[i];
				for(int pt=0; pt<r;pt++)
				{
					*(b++)=*(dataValues++);
				}	
			}
			free(dataValues);

			char *roothash=merkel_tree(block, total_blocks);

			//get hash entry of file from secure.txt
			int fd_secure = open("secure.txt", O_RDWR | O_CREAT, 0666);		//opening the secure.txt file to check corresponding entry

			char name[11];
			char hash[21];

			int flag=0;
			while(read(fd_secure, name,10)==10)
			{
				read(fd_secure,hash,20);
				name[10]='\0';
				hash[20]='\0';
				if(strcmp(name,pathname)==0)
				{						
					// filename is found in secure.txt
					flag=1;
					break;
				}
			}		

			if(flag==1)
			{
				//file exists in the secure.txt --> compare hashes
				if(strcmp(roothash, hash)!=0)
				{
					//Integrity check failed
					close(fd_secure);
					close(fd_file);
					
					return -1;
				}
				else
				{
					//Integrity check passed
					close(fd_secure);
					close(fd_file);

					return open(pathname, flags, mode,0666);
				}

			}
			else
			{

				//Update the size of the file in theh secure_size.txt file
				int sfd=open("secure_size.txt", O_RDWR|O_CREAT,0666);
				
				char filePath[11];
				char sizePath[7];
				
				int s;
				int flag=0;
				while((s=read(sfd,filePath,10))==10)
				{
					if(strcmp(filePath,pathname)==0){
						flag=1;
						break;
					}
					read(sfd,sizePath,6);
				}
				
				char sizeString[7];
				
				struct stat file;
			 	fstat(fd_file, &file);

				char filename[10];
				int tempfd;									// file descriptor for the matched filename
				struct stat tempfile;					
				int i;
				for(i=0;i<8;i++){
					sprintf( filename, "foo_%d.txt",i);
					tempfd=open(filename, O_RDWR,0);		
					fstat(tempfd, &tempfile);
					if(file.st_dev==tempfile.st_dev && file.st_ino ==tempfile.st_ino){

						break;
					}
					close(tempfd);
				}
				close(tempfd);

				sprintf(sizeString,"%d",fs[i]);

				if(flag==0){
					write(sfd,pathname,10);
					write(sfd,sizeString,6);	
				}
				else{
					write(sfd,sizeString,6);	
				}
				
				close(sfd);			

				// add entry of file hash to end of secure .txt
				lseek(fd_secure,0, SEEK_END);
			
				write(fd_secure,pathname,10);
				write(fd_secure,roothash,20);
				
				close(fd_secure);
				close(fd_file);

				return open(pathname, flags, mode,0666);
			}
			
		}
	}
	else
	{		
		//File doesn't exist. Remove its entry from secure.txt if it exists.
		int lineNum=-1;
		int fd_secure = open("secure.txt", O_RDWR | O_CREAT, 0666);		//opening the secure.txt file to check corresponding entry

		char name[11];
		char hash[21];

		int i=0;

		while(read(fd_secure, name,10)==10)
		{
			read(fd_secure,hash,20);
			name[10]='\0';
			hash[20]='\0';

			if(strcmp(name,pathname)==0){						// filename is found in secure.txt	
				lineNum=i;
				break;
			}
			i++;
		}

		//remove line number lineNum from the file.
		if(lineNum!=-1)
		{
			//reset offset of fd_secure to beginning
			lseek(fd_secure,0,SEEK_SET);

			char *entry=(char *) malloc(30*sizeof(char));	
			int fd_temp=open("temp.txt", O_RDWR | O_CREAT,0666);
			i=0;
			while(read(fd_secure,entry,30)==30)
			{
				if(lineNum!=i)
					write(fd_temp,entry,30);
				i++;
			}
			free(entry);
			
			close(fd_secure);
			close(fd_temp);
			
			remove("secure.txt");
			rename("temp.txt", "secure.txt");

			//File not found in directory but it is present in secure.txt
			return open(pathname, flags, mode,0666);
		}
		else
		{
			//File not found in directory. Also it is not present in secure.txt
			close(fd_secure);

			return open(pathname, flags, mode,0666);

		}
	}

	return open(pathname, flags, mode,0666);
}

/* SEEK_END should always return the file size 
 * updated through the secure file system APIs.
 */
int s_lseek (int fd, long offset, int whence)
{
	assert (filesys_inited);

	struct stat file;
 	fstat(fd, &file);

	char filename[10];
	int tempfd;								// file descriptor for the matched filename
	struct stat tempfile;					
	int i;
	for(i=0;i<8;i++){
		sprintf( filename, "foo_%d.txt",i);
		tempfd=open(filename, O_RDWR,0);		
		fstat(tempfd, &tempfile);
		if(file.st_dev==tempfile.st_dev && file.st_ino ==tempfile.st_ino)
		{
			break;
		}
		close(tempfd);
	}
	close(tempfd);

	int sfd=open("secure_size.txt", O_RDWR|O_CREAT,0666);
				
	char filePath[11];
	char sizePath[7];
	
	int s;

	while((s=read(sfd,filePath,10))==10)
	{
		read(sfd,sizePath,6);
		if(strcmp(filePath,filename)==0){
			break;
		}
	}

	return atoi(sizePath);
}

/* read the blocks that needs to be updated
 * check the integrity of the blocks
 * modify the blocks
 * update the in-memory Merkle tree and root in secure.txt
 * returns -1 on failing the integrity check.
 */
ssize_t s_write (int fd, const void *buf, size_t count)
{
	
	assert (filesys_inited);

 	struct stat file;
    fstat(fd, &file);
    int s=lseek(fd,0,SEEK_CUR);

	char filename[10];
	int tempfd;							// file descriptor for the matched filename
	struct stat tempfile;					
	int i;
	for(i=0;i<8;i++){
		sprintf( filename, "foo_%d.txt",i);
		tempfd=open(filename, O_RDWR,0);		
		fstat(tempfd, &tempfile);
		if(file.st_dev==tempfile.st_dev && file.st_ino ==tempfile.st_ino){

			break;
		}
		close(tempfd);
	}

	int f=tempfile.st_size;
	if(s!=f)
	{
		int fd_file= open(filename, O_RDWR,0666);
		struct stat buffer;
		fstat(fd_file, &buffer);
		int size=buffer.st_size;	//size of the file

		if(size!=0)					// if file is not empty
		{
			//build merkel tree of the file
			int total_blocks=size/64;
			if(size%64!=0)
			{
				total_blocks+=1;
			}

			char block[total_blocks][65];
			int i=0;
			char *dataValues= (char *)malloc( 65*sizeof(char));
			int r;

			while((r=read(fd_file,dataValues,64))==64)
			{
				dataValues[64]='\0';
				strcpy(block[i],dataValues);	
				block[i][64]='\0';
				i++;
			}
			
			if(r!=0)
			{	
				dataValues[r]='\0';
				char *b=block[i];
				for(int pt=0; pt<r;pt++)
				{
					*(b++)=*(dataValues++);
				}	
			}
			free(dataValues);

			char *roothash=merkel_tree(block, total_blocks);

			//get hash entry of file from secure.txt
			int fd_secure = open("secure.txt", O_RDWR | O_CREAT, 0666);		//opening the secure.txt file to check corresponding entry
			
			char name[11];
			char hash[21];

			int flag=0;

			while(read(fd_secure, name,10)==10)
			{

				read(fd_secure,hash,20);
				name[10]='\0';
				hash[20]='\0';

				if(strcmp(name,filename)==0)
				{						
					// filename is found in secure.txt
					flag=1;
					break;
				}
			}			

			if(flag==1)
			{
				//file exists in the secure.txt --> compare hashes
				if(strcmp(roothash, hash)!=0)
				{
					//Integrity check failed
					close(fd_secure);
					close(fd_file);
					
					return -1;
				}
				else
				{
					//Integrity check passed
					close(fd_secure);
					close(fd_file);
				}

			}
			else{

				int ret=write(fd, buf, count);

				lseek(tempfd,0,SEEK_SET);
				struct stat buf;
				fstat(tempfd, &buf);
				int filesize=buf.st_size;

				//build merkel tree of the file
				int total_blocks=size/64;
				if(filesize%64!=0)
				{
					total_blocks+=1;
				}

				char block[total_blocks][65];
				int i=0;

				int x;
				while((x=read(tempfd,dataValues,64))==64)
				{
					dataValues[64]='\0';
					strcpy(block[i],dataValues);
					block[i][64]='\0';
					i++;
				}
	
				
				if(x!=0)
				{	
					dataValues[x]='\0';
					char *b=block[i];
					char *d=dataValues;
					for(int pt=0; pt<x;pt++)
					{
						*(b++)=*(d++);
					}	
				}

				char *roothash=merkel_tree(block, total_blocks);

				lseek(fd_secure,0, SEEK_END);
				
				write(fd_secure,filename,10);
				write(fd_secure,roothash,20);
				
				close(fd_secure);
				close(fd_file);
				close(tempfd);

				fs[i]+=count;

				return ret;

			}
		}
				
	}
	close(tempfd);

	fs[i]+=count;

	return write (fd, buf, count);
}

/* check the integrity of blocks containing the 
 * requested data.
 * returns -1 on failing the integrity check.
 */
ssize_t s_read (int fd, void *buf, size_t count)
{
	assert (filesys_inited);
	return read (fd, buf, count);
}

/* destroy the in-memory Merkle tree */
int s_close (int fd)
{
	assert (filesys_inited);
	return close (fd);
}

/* Check the integrity of all files in secure.txt
 * remove the non-existent files from secure.txt
 * returns 1, if an existing file is tampered
 * return 0 on successful initialization
 */
int filesys_init (void)
{
	filesys_inited = 1;
	int fd_secure = open("secure.txt", O_RDWR | O_CREAT, 0666);
	
	char name[11];
	char hash[21];

	int lineNum[8];							// To store lines that needs to be deleted from secure.txt
	int flagFault=0;

	int m=0;
	while(read(fd_secure,name,10)==10)
	{
		read(fd_secure,hash,20);			//reading the hash value
		int fd_file=open(name, O_RDWR);		//opening the corresponding file for integrity check

		if(fd_file==-1)						//file not present
		{								
			//delete entry from secure.txt
			lineNum[m]=1;
			//Invalid file found. delete from secure!
		}
		else
		{	
			if(flagFault!=1)				// Integrity check using merkel tree
			{
				struct stat buf;
				fstat(fd_file, &buf);
				int size=buf.st_size;

				//build merkel tree of the file
				int total_blocks=size/64;
				if(size%64!=0)
				{
					total_blocks+=1;
				}

				char block[total_blocks][65];
				int i=0;
				char *dataValues= (char *)malloc( 65*sizeof(char));
				int x;
				while((x=read(fd_file,dataValues,64))==64)
				{
					dataValues[64]='\0';
					strcpy(block[i],dataValues);
					block[i][64]='\0';
					
					i++;
				}
				if(x!=0)
				{
					dataValues[x]='\0';

					char *b=block[i];
					for(int pt=0; pt<x;pt++)
					{
						*(b++)=*(dataValues++);
					}	
				}
				free(dataValues);

				char *roothash=merkel_tree(block, total_blocks);

				if(strcmp(hash, roothash)!=0){
					//Roothash Not Matched!!!
					flagFault=0;
				}
				else{
					//Roothash Matched
				}
			}
			close(fd_file);
		}
		m++;
	}


	close(fd_secure);						//fd of secure.txt

	fd_secure=open("secure.txt", O_RDWR|O_CREAT, 0666);
	char *entry=(char *) malloc(30*sizeof(char));	
	
	int fd_temp=open("temp.txt", O_RDWR | O_CREAT,0666);
	
	int i=0;
	while(read(fd_secure,entry,30)==30){
		if(lineNum[i]==0)
		{
			write(fd_temp,entry,30);
		}
		i++;
	}

	free(entry);

	lseek(fd_secure,0,SEEK_SET);
	struct stat buf1;
	fstat(fd_secure, &buf1);

	lseek(fd_temp,0,SEEK_SET);
	struct stat buf2;
	fstat(fd_temp, &buf2);
	
	close(fd_secure);
	close(fd_temp);
	
	remove("secure.txt");
	rename("temp.txt", "secure.txt");

	if(flagFault==1)
	{
		//filesys_init integrity check failed
		return 1;
	}

	//filesys_init integrity check passed
	return 0;
}

//secure.txt
//10 bytes for file name and 20 for hash value
//format : <filename><hashvalue>

//secure_size.txt
//10 bytes for file name and 6 for filesize
//format : <filename><filesize>