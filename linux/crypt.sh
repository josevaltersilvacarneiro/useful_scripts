#!/bin/bash
#                               
# crypt.sh - It encrypts and decrypts files and storages your hashs
#
# Author   - José V S Carneiro
#
# ------------------------------------------------------------------
#
# This program receives as parameter what the user want to make (en-
# crypt, decrypt, delete non-existent files or inform the repeated
# files) and the path to which the user want to apply.
#
# Examples:
#       $ encrypt.sh -c /home/jose
#	$ encrypt.sh -d /home/jose
#
# ------------------------------------------------------------------
#
# History:
#
#       Version 0.1 2022-09-13, José V S Carneiro git@josevaltersilvacarneiro.net:
#               - First Version
#	Version 0.2 2023-03-25, José V S Carneiro git@josevaltersilvacarneiro.net:
#		- Now only one operation is allowed at a time
#	Version 0.3 2023-07-01, José V S Carneiro <git@josevaltersilvacarneiro.net>:
#		- The password|passphrase used to encrypt the files|file is hidden
#
#
# Copyright: GPLv3

OLD_IFS=$IFS

trap "echo The script was successful" EXIT

function command_not_found_handle()
{
	echo "Error on line ${BASH_LINENO[0]}: $(head -${BASH_LINENO[0]} $0 | tail -1)"
	echo "Try installing it using the following command: \`apt install $0\` or \`sudo apt install $0\`"
	exit 5
}

function change_IFS()
{
        IFS=$(echo -ne "\n\b")
}

function retriev_IFS()
{
        IFS=$OLD_IFS
}

function get_password()
{
        while true
        do
                PASSWORD=$(zenity --password --title "Crypt")
                [[ -n "$PASSWORD" ]] && break
        done

	echo "$PASSWORD"
}

function file_doenst_exist()
{
	echo "The file \"$1\" doens't exist"
}

function is_file_encrypted()
{
        file="$1"

        [ "$file" != "${file%*.gpg}" ]

        return $?
}

function encrypt_file()
{
	backup="$1"                                  
        file="$2"               
	password="$3"
        
        if [ -e "$file.gpg" ]
        then                                                 
                echo "The file \"$file.gpg\" already exists"
        else
                echo "Encrypting \"$file\""
                gpg --batch -c --s2k-cipher-algo "aes256" --passphrase "$password" -- "$file"
                
                if [ $? -eq 0 ]
                then
                        wipe -f "$file" >&1                 
                        sha512sum "$file.gpg" >> $backup
                else                                                           
                        echo "Could not encrypt the file \"$file\""
                fi
        fi
}

function decrypt_file()
{
	backup="$1"
	file="$2"
	password="$3"

	stored_file=`grep -E -n -m 1 "$file$" "$backup"`
	line_number=`echo ${stored_file%%:*}`
	
	stored_file=`echo ${stored_file##*:}`

	if [[ -n "$stored_file" ]]
	then
		test_file=`sha512sum "$file"`

		if [[ $(echo ${stored_file:0:128}) == $(echo ${test_file:0:128}) ]]
		then
			echo "Decrypting \"$file\""

			new_file=`echo ${file%%".gpg"}`	# Creating a new name for the file
			
			gpg --batch -d --s2k-cipher-algo "aes256" --passphrase "$password" -o "$new_file" -- "$file"

			if [ $? -eq 0 ]			# If the file was decrypted, delete the old file
			then
				rm "$file"
				sed -i "${line_number}d" "$backup"
			else
				echo "Could not decrypt the file \"$file\""
			fi
		else
			echo "The file \"$file\" was modified"
		fi
	fi
}

function encrypt()
{
        backup="$1"
        filename="$2"
	password=`get_password`

        if [ -d "$filename" ]
        then
                change_IFS
                for file in $(find "$filename" -mindepth 2 -type f)
                do
                        is_file_encrypted "$file" || encrypt_file "$backup" "$file" "$password"
                done
                retriev_IFS
        elif [ -f "$filename" ]
        then
                is_file_encrypted "$filename" || encrypt_file "$backup" "$filename" "$password"
        else
                file_doenst_exist "$filename"
        fi
}

function decrypt()
{
        backup="$1"
        filename="$2"
	password=`get_password`

        if [ -d "$filename" ]
        then
                change_IFS
                for file in $(find "$filename" -mindepth 2 -type f)
                do
                        is_file_encrypted "$file" && decrypt_file "$backup" "$file" "$password"
                done
                retriev_IFS
        elif [ -f "$filename" ]
        then
                is_file_encrypted "$filename" && decrypt_file "$backup" "$filename" "$password"
        else
                file_doenst_exist "$filename"
        fi
}

function delete()
{
	backup="$1"

        i=0
        while read line
        do
                let i++

                file=${line##* }

                if [ ! -e "$file" ]
                then
                        echo "The file $file will be deleted of $backup because it doens't exist"
                        sed -i "${i}d" "$backup"
                fi
        done < $backup
}

function show_duplicate_files()
{
        backup="$1"

        change_IFS
        for sha in `sort "$backup" | uniq -d -w 128`
        do
                file=${sha:130}
                echo "The file \"$file\" are repeated"
        done
        retriev_IFS
}

function support()
{
        echo "
		usage: encrypted.sh [option] [path]
		Options and arguments:
		-c	: encrypts the file or directory
		-d	: decrypts the file or directory
		-e	: deletes removed files and that their hashes are still stored
		-r	: shows repeated files
		-h	: displays the help message
		path	: the file or directory where the operation will be performed
	"
}


function main()
{
	flag_encrypt=0
	flag_decrypt=0
	flag_delete=0
	flag_show=0
	flag_help=0

	if [ $# -ne 2 ]
	then
		echo "The program requires two arguments to work" >&2
		support
		exit 1
	fi

	# FILENAME receives the name of the file or direc- #
        # tory that should be encrypted. First the eval    #
        # command replaces the number of parameters passed #
        # as arguments to get the last argument which is   #
        # path to the file or directory.                   #

        FILENAME=`eval tr -s '/' \<\<\< \"\$\{$#\}\"`

        if [ -e "$FILENAME" ]
        then
                BACKUP="${FILENAME%/*}/.backup.sha512sum"
        else
                file_doenst_exist "$FILENAME"
                exit 1
        fi

	# It verifies the pattern and delete the others    #
        # files that aren't in the pattern.                #

        [ -s "$BACKUP" ] && sed -i -r '/^[a-z0-9]{128}  .+$/!d' "$BACKUP"

	while getopts :cderh opt
        do
                case $opt in
                        c)
                                flag_encrypt=1
                                ;;
                        d)
                                flag_decrypt=1
                                ;;
                        e)
                                flag_delete=1
                                ;;
                        r)
                                flag_show=1
                                ;;
                        h)
                                flag_support=1
                                ;;
                        \?)
                                echo "The option '-$OPTARG' doens't exist" >&2
				support
                                exit 2
                esac
        done

	xor=$(($flag_encrypt ^ $flag_decrypt ^ $flag_delete ^ $flag_show ^ $flag_help))
        
        if [ $xor -eq 1 ]
        then
                if [ $flag_encrypt -eq 1 ]
		then
			encrypt "$BACKUP" "$FILENAME"
		elif [ $flag_decrypt -eq 1 ]
		then
			decrypt "$BACKUP" "$FILENAME"
		elif [ $flag_delete -eq 1 ]
		then
			delete "$BACKUP"
		elif [ $flag_show -eq 1 ]
		then
			show_duplicate_files "$BACKUP"
		elif [ $flag_help -eq 1 ]
		then
			support
		fi
        else
                echo "There was an error: only one operation is allowed at a time" >&2
        fi
}

main $@
