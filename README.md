Cyber Security Incident Tracking System

📌 Overview

The Cyber Security Incident Tracking System is a database-driven solution designed to log, track, and manage cybersecurity incidents efficiently. This system enables security teams to document security breaches, categorize incidents by severity, and monitor incident statuses in real-time.

🛠 Features

Incident Logging: Track security incidents with descriptions and severity levels.

Incident Status Management: Monitor the progress of each security event.

User Role-Based Access: Define user roles (e.g., security analyst, administrator) to manage access control.

Timestamps: Automatically record the time of incident creation for auditing purposes.

📂 Database Schema

The system is built on PostgreSQL and consists of the following tables:

1. incidents (Stores security incidents)

CREATE TABLE incidents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(50),  -- Can also be INTEGER if using numeric levels
    status VARCHAR(50) DEFAULT 'Open',
    reporter_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

id: Unique identifier for each incident.

title: Short description of the incident.

description: Detailed information about the incident.

severity: Severity level (e.g., Low, Medium, High, Critical).

status: Incident status (default is Open).

reporter_id: ID of the user who reported the incident.

created_at: Timestamp of incident creation.

2. users (Manages system users)

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL,
    password_hash TEXT NOT NULL
);

id: Unique identifier for each user.

full_name: Full name of the user.

email: Unique email address of the user.

role: Defines the user's role (e.g., admin, analyst).

password_hash: Securely stored hashed password.

Schema Modification

ALTER TABLE users DROP COLUMN name;

The name column was removed to avoid redundancy.

🚀 Installation & Setup

Clone the Repository

git clone https://github.com/Ayesha00-9/database-project-cyber-incident-tracking-system-/blob/main/README.md
cd CyberSecurityIncidentTracking

Set Up PostgreSQL Database

psql -U your_user -d your_database -f schema.sql

Configure Database Connection
Modify .env file with your database credentials:

DB_HOST=localhost
DB_USER=your_user
DB_PASSWORD=your_password
DB_NAME=your_database

Run the Application (If applicable)

python app.py

📜 License

This project is licensed under the  Apache License. See LICENSE for more details.

🤝 Contributing

Feel free to fork this repository and submit pull requests to enhance the system.

📧 Contact

For queries or suggestions, reach out via ayeshaamjadali7801@gmail.com
