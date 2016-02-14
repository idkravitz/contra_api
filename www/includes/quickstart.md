### Quick start

**Step 1:** Pack, compress and upload data and command files to our server.
Accepted data file formats: \*.tar.gz, \*.7z. A command file needs not to be compressed.  
**Step 2:** Click "use" on data and command files.  
**Step 3:** Click "Execute" and enjoy the results.  

Your command file will be run by *bash* from the root of the data archive.
In other words, if your file tree after unpacking looks like

    /my-archive/
    /my-archive/file2


then the script is expected to run from `/my-archive/`
Or if you have:

    /a/b/c/file1
    /a/b/d/file2


Then the script is expected to run from `/a/b/`
