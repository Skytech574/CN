COMPUTER NETWORK PROJECT


project_root/
├── server.py
├── sniffer.py
├── templates/
│   ├── index.html
│   ├── quiz.html
│   ├── dashboard.html
│   ├── files.html
│   ├── slides.html
│   ├── admin_home.html
│   ├── admin_users.html
│   ├── admin_settings.html
│   ├── 404.html
│   ├── 500.html
│
├── static/
│   ├── style.css
│   ├── slide1.jpg
│   ├── slide2.jpg
│   ├── slide3.jpg



Description

This Computer Network Project is designed to demonstrate practical applications of networking and web technologies using Python’s Flask framework.
It serves as an interactive platform that allows users to:

Participate in live quizzes

Share and download files

Communicate via a live chat interface

View dashboard analytics and network statistics

Capture and analyze network packets using a built-in sniffer module

It uses SQLite3 for database management and standard Flask templates for the frontend.


How to Run the Project
STEP 1: Setup

Download or clone the project files.
Make sure the folder structure matches exactly as shown above.

STEP 2: Run the Server

Open a terminal in the project directory and run:  -----  python server.py

This will start the Flask web server and host the website locally.

STEP 3: Run the Packet Sniffer

Open a new terminal and run: --------- python sniffer.py

This module captures network packets and logs them into the database, which can then be viewed on the dashboard.

Requirements

Before running, make sure you have the required Python libraries installed.
You can install them using: ------- pip install -r requirements.txt

OR INSTALL THIS INDIVIDUALLY
Flask
Flask-SocketIO
eventlet
Flask-SQLAlchemy
Flask-HTTPAuth


Key Concepts Demonstrated

Flask Web Framework

Client-Server Communication

Socket Programming Basics

Packet Sniffing and Data Logging

Database Management (SQLite)

Web Frontend Integration (HTML/CSS)


Conclusion

This project effectively combines web development and network monitoring concepts into a unified educational tool.
It’s perfect for demonstrating computer network principles, real-time communication, and Flask-based web application development.

