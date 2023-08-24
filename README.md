# git-essentials
#!/bin/ksh

# Check if LOGFILE variable is set
if [[ -z "$LOGFILE" ]]; then
    echo "LOGFILE variable is not set."
    exit 1
fi

# Check for the existence of the file
if [[ ! -e "$LOGFILE" ]]; then
    touch "$LOGFILE"
    if [[ $? -ne 0 ]]; then
        echo "Error creating $LOGFILE."
        exit 2
    fi
    chmod 666 "$LOGFILE"
    if [[ $? -ne 0 ]]; then
        echo "Error setting permissions for $LOGFILE."
        exit 3
    fi
    echo "$LOGFILE created with 666 permissions."
else
    echo "$LOGFILE already exists."
fi

exit 0
