Shepherd – Open‑Source Security Notice TrackerA lightweight, pure‑HTML/CSS/JavaScript web app that lets a client keep an eye on security advisories affecting the open‑source components they use.
The tracker pulls vulnerability announcements from the Canadian Cyber Centre RSS feed (or any client‑provided RSS endpoint) and matches them against a list of projects supplied by the user.

Table of Contents

Features
Demo
Installation & Running
How It Works
Adding Projects

Manual URL entry
Popular shortcuts
GitHub search


Viewing Advisories
Refresh Button
Custom RSS Sources
URL‑Based Stack Persistence
Folder Structure
Customization & Extending
Contributing
License


Features

Zero‑dependency – only static HTML, CSS, and vanilla JavaScript. No build tools or server required.
Project stack stored in the URL (?stack=) – shareable links that recreate the exact list of tracked projects.
Add projects from any URL (GitHub repos, self‑hosted packages, internal services).
Built‑in popular‑project shortcuts (React, Vue, Angular, Django, Flask, Node.js, TensorFlow, Apache Kafka).
GitHub repository search – find a repo by keyword and add it with one click.
Live vulnerability feed – consumes the Canadian Cyber Centre RSS feed, parses it client‑side, and filters entries that mention the selected project.
Refresh button – forces a fresh fetch of the RSS feed for the currently selected project.
Client‑provided RSS feeds – replace the default feed URL in script.js with any custom endpoint.


Demo
Open index.html in a browser (or host the folder on any static web server). The UI will look like this:
 (illustrative only)

Installation & Running

Clone / download the repository.
Ensure the folder structure matches the one described below.
Open shepherd/index.html in any modern browser (Chrome, Firefox, Edge, Safari).
No server is required – the app runs entirely client‑side.

If you want to serve it over HTTP (e.g., for testing CORS‑related behaviour), a simple static server works:
# Python 3
python -m http.server 8000 --directory shepherd
# Then visit http://localhost:8000/

How It Works

Stack persistence – The list of project URLs is encoded in the query string (?stack=).
RSS retrieval – When a project is selected, the app fetches the Canadian Cyber Centre RSS feed (https://www.cyber.gc.ca/rss/alerts.xml).
Keyword matching – The project URL is reduced to a simple keyword (GitHub repo name or hostname). The feed items are filtered for that keyword in their title or description.
Display – Matching advisories are rendered in a readable bullet list, showing title, date, link, and description.

All processing happens locally in the browser; no data is sent to a backend.

Adding Projects
Manual URL entry

Paste a full URL (e.g., https://github.com/expressjs/express) into the Add a project field.
Click Add. The URL appears in the Tracked projects list and is stored in the URL query string.

Popular shortcuts
Click any button under Popular projects (React, Vue, etc.) to instantly add that repository to the stack.
GitHub search

Enter a keyword in the Search GitHub for projects box (e.g., “markdown editor”).
Press Search – the first five matching repositories appear.
Click Add next to a result to insert its GitHub URL into the stack.


Viewing Advisories

Click a project in the Tracked projects list.
The app fetches the RSS feed (or uses the cached copy) and displays any matching advisories under Vulnerability notices.
If no matches are found, a friendly “No advisories found” message appears.


Refresh Button
After selecting a project, the Refresh button becomes active. Clicking it clears the cached RSS feed for the current session and forces a fresh network request, ensuring you see the very latest advisories.

Custom RSS Sources
If a client wants to use a private or alternative feed:

Open script.js.
Locate the constant near the top:

const CYBER_CENTRE_RSS = 'https://www.cyber.gc.ca/rss/alerts.xml';

Replace the URL with the desired RSS endpoint (must return a standard RSS 2.0 XML document).
Save the file – the app will now pull advisories from the new source.


URL‑Based Stack Persistence
The stack is encoded as a comma‑separated, URL‑encoded list:
https://yourdomain.com/shepherd/index.html?stack=https%3A%2F%2Fgithub.com%2Freactjs%2Freact,https%3A%2F%2Fgithub.com%2Fvuejs%2Fvue


Sharing: Copy the full URL and send it to teammates; opening it restores the exact same project list.
Editing: Adding/removing projects automatically updates the query string without a page reload.


Folder Structure
shepherd/
│
├─ index.html   ← UI markup
├─ style.css    ← Styling
└─ script.js    ← All interactive logic (stack handling, RSS fetch, GitHub search)

All files are static and can be placed on any web server or served locally.

Customization & Extending

Styling: Modify style.css to match corporate branding.
Additional data sources: Extend loadVulnerabilities() to fetch from multiple RSS feeds and merge results.
More project shortcuts: Add new buttons in the Popular projects section and update the HTML accordingly.
Advanced filtering: Replace the simple substring match with regular‑expression or CVE‑ID detection for higher precision.

Because the code is plain JavaScript, you can integrate any further client‑side logic without changing the overall architecture.

Contributing

Fork the repository.
Create a feature branch (git checkout -b feature/my‑feature).
Make your changes, ensuring the app still works without a server.
Submit a Pull Request with a clear description of the enhancement or bug fix.

Please keep contributions dependency‑free – avoid adding build tools or external libraries unless absolutely necessary.

License
This project is released under the MIT License. See the LICENSE file for details.

Enjoy tracking security notices with Shepherd – a simple, shareable, and privacy‑preserving solution for open‑source dependency monitoring.