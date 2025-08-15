# Steps to Run the App

## Installation
- Install Python
- Install Flask: `pip install flask-socketio`
- `python app.py`

## Network Setup
Give members the second link that pops up: 
```
Running on http://192.168.1.189:5000
```

**Note:** They have to be connected to the same WiFi

## Configuration Requirements

### Video Setup
- Have to update the video directory path `VIDEO_DIRECTORY`
- Need minimum of 3 videos, 9 candidates (can change this in code)

### How It Works
- Candidates are figured out by stripping name of video file
- Number of minimum candidates each member can judge is 5 (can change)
- Members can choose one candidate over another through the 5 different candidates
- All number 1's are displayed together
- All number 2's are displayed together
- etc.

## Admin Access
Admin is in lines 42-50:
- **User:** `admin`
- **Pass:** `admin123` (can change password)

## User Management
- Usernames have to be the same when they leave and come back from the page
- You have to send the "generated password" out to all of the members

## Browser Considerations
- Figure out how to not save info "cookies" every time you open the web
- Open in private browser

## TO DO

### Things that need to change:
- Add edge cases for less than 3 videos
- Change code so candidates don't depend on the name of the file
- Split app.py into different files
- Make app usable for mac 