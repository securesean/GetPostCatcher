# GetPostCatcher

Nothing fancy, just a simple Python Webhosting Script to catch and display all GET and POST request info. It should capture all normal file POST requests, all GET request information, their headers, display POST'd pictures and text files. No Security - there's probably a vulnerability somewhere in there.

Made to be self-hosted/offline.

Made with Flask, SQLite, JQuery, & DataTables.

Only page is /view. Which is backed by `/logs` that returns json version of the database. There's also a test page for `/uploadfile`

And directories to serve files in:
`/static`
`/uploads`