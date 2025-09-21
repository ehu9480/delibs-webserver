# Steps to Run the App

## Installation
- Install Python
- run `pip install -r requirements.txt`


### Starting the server
- Run `python app.py`

## Network Setup
There will be two links, one will look like http://120.0.0.1:5000
that is the one that will run locally, provide the second one (which contains your IP address) to the team

**Note:** Admin and users have to be connected to the same WiFi

## Configuration Requirements

### Video Setup
- Add candidacy videos to the `videos` directory
- Need minimum of 3 videos, 9 candidates (can change this in code)

### How It Works
- Candidates are detected by parsing the numbers in the video filenames
- When a new member joins, they are assigned about 30% of the total candidates, with a minimum of 1 candidate
- When the admin resets and redistributes by setting the total number of auditionees, each candidate is assigned to 50% of the users currently logged in (rounded up)
- Members compare candidates in a binary search–style process, choosing which one ranks higher until all their assigned candidates are placed
- Progress is tracked in real time: comparisons completed vs. total comparisons
- Final rankings are aggregated across users by averaging candidate positions

## User Management
- Usernames have to be the same when they leave and come back from the page
- You have to send the "daily generated password" out to all of the members for logging in

## Recent Updates (September, 2025)
✅ Mac & Windows compatible  
✅ Unified storage place for candidate videos, `videos` directory, just needs to be filled upon beginning delibs  
✅ Updated algorithm guarantees that all candidates are viewed by the same number of members  
✅ Updated UI  

## TO DO
### Browser Considerations
1. Fix requirements.txt for easier package download
1. Stream videos in lower quality
    * converting the videos with handbrake is the current solution
1. Add progress bar
1. Change code so candidates don't depend on the name of the file (specifically the formatting with underscores)
1. Figure out how to not save info "cookies" every time you open the web
    - The current solution to this is to ask the team to open the server in private browser
1. Fix minimum dependency/Add edge cases for less than 3 videos
1. Split app.py into different files