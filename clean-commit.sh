#!/bin/bash

# Get the current commit message
original_msg=$(git log --format=%B -n 1)

# Remove Claude co-author lines and clean up
clean_msg=$(echo "$original_msg" | \
    sed '/^Co-Authored-By: Claude <noreply@anthropic\.com>$/d' | \
    sed '/^🤖 Generated with \[Claude Code\]/d' | \
    sed -e :a -e '/^\s*$/N; s/\n\s*$//; ta')

# Only amend if the message actually changed
if [ "$original_msg" != "$clean_msg" ]; then
    echo "Cleaning commit message..."
    git commit --amend --message "$clean_msg" --no-edit
else
    echo "No changes needed for this commit."
fi