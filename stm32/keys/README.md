# Firmware Signing Keys

Only the zero key is public, the others are ultra super secret.

But if you had them, they would go in this directory, and be excluded
by git by the .gitignore file.

Public keys listed here are also in the bootrom source and binary.

However, only room for first 5 or so ... perhaps later revs of the bootrom
will support higher numbers.

# Key zero -- for Devs

Key zero (`00.pem` here) is shared on the Internet so anyone can 
build experiemental code for the Coldcard and give it to their friends.

However, booting such code is very painful! Long delay and very scary
warning is shown to user.


