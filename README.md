## Part 1: Multi-threaded API web server

### Running the Web Server

#### 1. Setup:
Make sure the following files in the same folder:
- `TreeOne_Webserver.py`
- `index.html`

#### 2. Start the Server:
Open a terminal and run:
```
python3 TreeOne_Webserver.py
```

The console should display a message:
```
Web server listening on <actual_ip>:8298
# Example: Web server listening on 10.0.0.186:8298 (my local machine dont hack me)
```

#### Connect via Browser:
Open google chrome and navigate to:
```
http://<actual_ip>:8298/
```
Replace `<actual_ip>` with the IP address displayed on the console.

### Using the Web Application

#### Login:
Enter your username and click **"Login"**. A welcome message (e.g., "Welcome! Fry") will appear next to the Logout button.

#### File Operations:
Use the provided UI buttons to:
- List files
- Upload a file
- Download a file
- Delete a file
- View download statistics

All files uploading and downloading are stored under **files** folder

#### Logout:
Click **"Logout"** to end your session without affecting the files.

### Bonus Features Completed:

- **BonusV1:** I have Implemented the `GET /api/stats` endpoint returning download statistics (number of downloads and average download time).
- **BonusV2:** I have Implemented caching for `/api/list`, `/api/stats`, and small file downloads via `/api/get`), with console messages displayed when cached data is used (large file will not be cached to avoid excessive memory usage but will still be downloaded).
Be careful when you test it with multiple users as fast clicking on random button somehow make my fragile cache crashed. For example, if you do not see the stats updated, try logout and then log in back and it should work.

---

## Part 2: Screen Scrapper

### Building the Screen Scrapper

#### 1. Setup:
Make sure the following files in the same folder:
- `scrapper.c`
- `Makefile`

#### 2. Compile:
Open a terminal and run:
```
make
```
This compiles the code and produces an executable named `scrapper`.

### Running the Screen Scraper

Use the following command-line syntax:
```
./scrapper [host] [port] [username] [file_to_push]
```

**Example:**
```
./scrapper hawk.cs.umanitoba.ca 8298 Roblo TEST.txt
./scrapper 130.179.28 8298 Roblo TEST.txt
```

The host can be the actual ip that displayed when you run the server or the host name depends on the aviary machine you are assigned. Choose any style you like!

The scraper will:
- Verify that unauthenticated requests are rejected.
- Log in using the provided username and capture the session cookie.
- Check that the file is not present in the initial file list.
- Upload the file and assert that it appears in the file list.
- Verify the file is in the file list.

If all tests pass, the program outputs:
```
Test end without core dump :p.
```
If you see a core dump, before deduct my mark please check the host and port as any misspell would lead to it. 
