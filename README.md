# 🌲 Forest Guardian

<div align="center">

### AI-Powered Forest Monitoring, Patrol Tracking & Emergency Response

**A mobile-first intelligent platform for forest departments to monitor patrols, detect incidents, analyze forest risks, and coordinate emergency response — even in low-connectivity environments.**

<br/>

![Flutter](https://img.shields.io/badge/Flutter-02569B?style=for-the-badge\&logo=flutter\&logoColor=white)
![Dart](https://img.shields.io/badge/Dart-0175C2?style=for-the-badge\&logo=dart\&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge\&logo=node.js\&logoColor=white)
![Express](https://img.shields.io/badge/Express-000000?style=for-the-badge\&logo=express\&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge\&logo=mongodb\&logoColor=white)
![Firebase](https://img.shields.io/badge/Firebase-FFCA28?style=for-the-badge\&logo=firebase\&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge\&logo=python\&logoColor=white)

</div>

---

## 🌳 Overview

**Forest Guardian** is an AI-powered forest monitoring and field-operations platform designed to help forest departments monitor patrol activities, manage incidents, respond to emergencies, and make data-driven decisions.

The platform combines:

* 📍 Real-time GPS patrol tracking
* 🗺️ GIS-based forest mapping
* 🤖 AI-powered risk analysis
* 🔥 Fire-risk prediction
* 🚨 Emergency SOS response
* 📸 AI-assisted incident classification
* 🛰️ Geofencing
* 📡 Offline-first field operations
* 💬 Real-time communication
* 📊 Operational analytics
* 📄 Automated reports
* 🔐 Role-based security

Forest Guardian is designed as a **single cross-platform Flutter mobile application** for Android and iOS. Officers, Range Officers, and Administrators use the same application with different capabilities based on their roles.

---

# 🎯 Problem

Forest officers often operate in environments where:

* Internet connectivity is unreliable.
* Patrol activities are difficult to monitor in real time.
* Incident reporting is manual or delayed.
* Emergency response coordination is slow.
* Forest fire risks are difficult to predict.
* Patrol coverage gaps are difficult to identify.
* Data is scattered across multiple systems.
* Administrators lack real-time operational visibility.

Traditional monitoring systems often fail when officers enter remote forest areas with limited connectivity.

### Forest Guardian addresses this by creating a connected, intelligent and offline-capable ecosystem.

---

# 💡 Solution

Forest Guardian provides a unified platform where:

**Officer**

→ Patrols the forest
→ GPS tracks the route
→ Reports incidents
→ Receives alerts
→ Uses offline mode
→ Can trigger SOS

**Range Officer**

→ Monitors officers
→ Assigns patrols
→ Reviews incidents
→ Tracks patrol coverage
→ Manages range operations

**Admin**

→ Manages users
→ Manages forest hierarchy
→ Monitors department-wide activity
→ Configures geofences
→ Views analytics
→ Manages AI thresholds
→ Generates reports

The SRS defines these three roles and their corresponding permissions.

---

# 🚀 Key Features

## 📍 1. Intelligent GPS Patrol Tracking

Track officers during active patrols with background GPS.

### Features

* Continuous GPS tracking
* Background tracking
* Lock-screen tracking
* Adaptive GPS sampling
* Route visualization
* Distance calculation
* Patrol duration
* Average speed
* Altitude
* Bearing
* GPS accuracy
* Route history
* Patrol playback
* Checkpoint tracking

GPS points can be stored locally during connectivity loss and synchronized later.

---

# 🗺️ 2. Advanced Forest Map

A GIS-enabled map provides operational visibility.

### Map Layers

* 🌲 Forest boundaries
* 🏞️ Division boundaries
* 📍 Patrol routes
* 👮 Officer locations
* 🚨 Incident locations
* 🔥 Fire hotspots
* ⚠️ Risk zones
* 📌 Checkpoints
* 🛰️ Geofences
* 🔥 Heatmaps

### Map Modes

* Standard
* Satellite
* Terrain

Marker clustering is used to prevent map overcrowding.

---

# 🛰️ 3. Geofencing

Administrators can define virtual forest boundaries.

Supported concepts include:

* Polygon boundaries
* Radius-based geofences
* Entry detection
* Exit detection
* Boundary violations
* Automated notifications
* Event logging

When an officer enters or exits a configured zone, Forest Guardian can notify the relevant users and record the event.

---

# 🥾 4. Patrol Management

Officers can manage complete patrol sessions.

### Patrol Lifecycle

```text
START
  ↓
PAUSE
  ↓
RESUME
  ↓
END
```

The system calculates:

* Distance
* Duration
* Average speed
* Route
* Checkpoints reached
* Estimated area covered
* Patrol completion
* Patrol efficiency

Patrol state is persisted locally so that an app restart does not unnecessarily destroy an active patrol.

---

# 🚨 5. Incident Management

Officers can report incidents directly from the field.

### Supported Incident Types

* 🔥 Forest Fire
* 🪓 Illegal Logging
* 🐾 Poaching
* 🦌 Wildlife Sighting
* 🏗️ Encroachment
* 🧪 Pollution
* 🌳 Fallen Trees
* 🛣️ Damaged Roads
* ⛏️ Illegal Mining
* 🌊 Flood
* ⛰️ Landslide

Each incident can contain:

* GPS location
* Description
* Photos
* Videos
* Voice recordings
* Timestamp
* Reporting officer
* Incident category

Incomplete reports can be saved as drafts and submitted later.

---

# 🤖 6. AI Forest Intelligence

Forest Guardian integrates AI/ML capabilities to support forest operations.

### AI Capabilities

#### 🔥 Fire Risk Prediction

Identify areas with elevated fire risk using factors such as:

* Historical incidents
* Weather
* Vegetation dryness
* Environmental conditions

#### 🪓 Illegal Logging Hotspot Detection

Identify locations with a higher probability of illegal logging based on historical operational data.

#### 🕳️ Patrol Gap Detection

Identify:

* Under-patrolled zones
* Patrol gaps
* Unusual coverage reductions
* Missed areas

#### 🧭 Patrol Route Optimization

Generate AI-assisted patrol recommendations based on:

* Risk zones
* Checkpoints
* Officer location
* Patrol priorities
* Travel distance/time

#### 📸 Image Classification

Analyze incident images for potential:

* Fire
* Smoke
* Wildlife
* Illegal activity
* Other incident evidence

#### 📊 Risk Scoring

Generate numerical risk scores for forest zones.

AI outputs remain **advisory** and require human confirmation before operational decisions such as dispatch or escalation.

---

# 🧠 7. Forest Intelligence Assistant

The platform can provide an AI assistant capable of answering authorized operational questions.

Examples:

```text
Which zones currently have the highest fire risk?

Which officers are currently on patrol?

Which beat has the lowest patrol coverage?

Show unresolved critical incidents.

Which officer is closest to this emergency?

Summarize today's forest activity.

Why is this zone considered high risk?
```

The assistant should respect role-based access and never expose information outside the user's authorization scope.

---

# 🔥 8. Fire Risk Engine

Forest Guardian can calculate a fire-risk score for forest zones.

Example scale:

|  Score | Risk        |
| -----: | ----------- |
|   0–20 | 🟢 Low      |
|  21–40 | 🟡 Moderate |
|  41–60 | 🟠 Elevated |
|  61–80 | 🔴 High     |
| 81–100 | 🚨 Critical |

Potential inputs include:

* Temperature
* Humidity
* Rainfall
* Wind
* Historical fire incidents
* Vegetation dryness
* Patrol coverage

---

# 🆘 9. SOS Emergency System

Forest Guardian includes a one-tap emergency mechanism.

When SOS is triggered:

```text
Officer
   ↓
SOS Trigger
   ↓
Live Location
   ↓
Emergency Event
   ↓
Admin + Nearby Officers
   ↓
Response Coordination
```

The emergency event can include:

* Officer identity
* Current GPS
* Battery level
* Timestamp
* High-frequency tracking
* Emergency status

The system supports emergency lifecycle states such as:

```text
TRIGGERED
    ↓
ACKNOWLEDGED
    ↓
DISPATCHED
    ↓
RESPONDING
    ↓
RESOLVED
```

SOS cancellation can require additional authentication to reduce accidental cancellation.

---

# 💬 10. Real-Time Communication

Forest Guardian supports communication between authorized users.

### Channels

* Officer ↔ Range Officer
* Officer ↔ Admin
* Range Officer ↔ Admin

### Supported Content

* Text
* Images
* Voice notes
* Files
* GPS location

Also supports:

* Delivery status
* Read receipts
* Typing indicators
* Offline message queue

---

# 📡 11. Offline-First Architecture

One of the most important capabilities of Forest Guardian is **offline operation**.

Forest environments may have little or no network connectivity.

The application therefore supports local storage for:

* GPS points
* Patrols
* Incidents
* Photos
* Videos
* Voice notes
* Chat messages

When connectivity returns:

```text
OFFLINE
   ↓
LOCAL DATABASE
   ↓
PENDING SYNC
   ↓
NETWORK AVAILABLE
   ↓
AUTOMATIC SYNC
   ↓
SERVER
```

The system maintains synchronization state and retry behavior rather than simply discarding data.

---

# 📊 12. Analytics

Administrators and Range Officers can access operational analytics.

### Patrol Analytics

* Active officers
* Patrol count
* Patrol coverage
* Patrol efficiency
* Distance travelled
* Completion percentage

### Incident Analytics

* Incident count
* Incident categories
* Severity
* Trends
* Resolution status

### Fire Analytics

* Fire incidents
* Fire-risk trends
* Fire hotspots
* High-risk areas

### Officer Analytics

* Patrol activity
* Coverage
* Performance
* Incident reporting

Analytics support:

* Daily
* Monthly
* Yearly
* Custom date ranges

The SRS specifies native in-app charts rather than web-based dashboards.

---

# 👥 User Roles

## 👮 Forest Officer

Can:

* Start/stop patrols
* Track GPS
* View assigned areas
* Report incidents
* View maps
* Receive alerts
* Chat with authorized users
* Trigger SOS
* View patrol history

---

## 🧑‍✈️ Range Officer

Can:

* Monitor officers within their range
* Assign patrol areas
* Assign patrol schedules
* Review incidents
* Approve/reject reports
* Track patrol completion
* Generate range reports

---

## 🛡️ Admin

Can:

* Manage users
* Manage roles
* Manage forest hierarchy
* Monitor officers department-wide
* Configure AI thresholds
* Manage geofences
* View analytics
* Generate reports
* Configure notification rules
* Review audit logs

---

# 🏞️ Forest Hierarchy

Forest Guardian supports:

```text
Circle
   │
   └── Division
         │
         └── Range
               │
               └── Beat
                     │
                     └── Zone
```

Administrators can manage this hierarchy and associate officers and boundaries with the appropriate operational level.

---

# 🌦️ Weather Intelligence

Weather information can include:

* Temperature
* Humidity
* Rainfall
* Wind speed
* Fire Risk Index

Latest weather data can be cached for offline viewing.

---

# 🔔 Smart Notifications

Notifications can be generated for:

* 🆘 SOS
* 🔥 Fire alerts
* 🚨 Incidents
* 🌦️ Weather
* 📍 Geofence violations
* 🥾 Patrol reminders
* 💬 Messages
* 📢 Emergency broadcasts

Users can configure notification preferences by category.

---

# 📄 Reports

Forest Guardian supports operational report generation.

### Reports

* Patrol Report
* Incident Report
* Officer Performance Report
* Forest Activity Report
* Monthly Analytics Report
* Emergency/SOS Report
* AI Risk Report

### Formats

* PDF
* Excel
* CSV

Reports can be shared through the native mobile OS share sheet.

---

# 🔐 Security

Security is a first-class requirement.

Forest Guardian uses:

* HTTPS/TLS
* JWT authentication
* Refresh tokens
* Server-side RBAC
* Secure token storage
* Encrypted offline data
* Database encryption at rest
* Signed media URLs
* Rate limiting
* Authentication abuse protection
* Audit logging

Sensitive actions such as:

* user management
* report approvals
* data exports
* AI threshold changes

are recorded in audit logs.

---

# 🏗️ System Architecture

```text
                  ┌─────────────────────────┐
                  │     Flutter Mobile      │
                  │     Android + iOS       │
                  └────────────┬────────────┘
                               │
                        HTTPS / WebSocket
                               │
                               ▼
                  ┌─────────────────────────┐
                  │   Node.js + Express     │
                  │      REST API           │
                  └───────┬─────────┬───────┘
                          │         │
                ┌─────────┘         └──────────┐
                ▼                              ▼
       ┌────────────────┐             ┌─────────────────┐
       │    MongoDB     │             │   AI/ML Service │
       │  Primary DB    │             │     Python      │
       └────────────────┘             └─────────────────┘
                │                              │
                └──────────────┬───────────────┘
                               │
                ┌──────────────┴──────────────┐
                ▼                             ▼
        ┌───────────────┐             ┌────────────────┐
        │    Firebase   │             │ Google Maps SDK│
        │ Auth / FCM /  │             │ Maps / GIS     │
        │    Storage    │             └────────────────┘
        └───────────────┘
```

The architecture follows the project's SRS: Flutter mobile client, Node.js/Express backend, MongoDB, Python AI/ML service, Firebase services, and native Google Maps integration.

---

# 🛠️ Technology Stack

| Layer                   | Technology                          |
| ----------------------- | ----------------------------------- |
| Mobile                  | Flutter                             |
| Language                | Dart                                |
| Backend                 | Node.js                             |
| API                     | Express.js                          |
| Database                | MongoDB                             |
| Authentication          | Firebase Authentication             |
| Storage                 | Firebase Storage                    |
| Notifications           | Firebase Cloud Messaging            |
| Maps                    | Google Maps SDK                     |
| AI/ML                   | Python                              |
| Computer Vision         | OpenCV                              |
| ML                      | TensorFlow / Scikit-learn           |
| Offline Storage         | SQLite / Hive / Isar                |
| Real-time Communication | WebSockets / Socket.IO              |
| Deployment              | Google Play Store / Apple App Store |
| Cloud                   | AWS / Firebase                      |

The technology stack is aligned with the project's SRS.

---

# 📁 Recommended Project Structure

```text
forest-guardian/
│
├── mobile/
│   └── lib/
│       ├── core/
│       ├── config/
│       ├── constants/
│       ├── theme/
│       ├── routing/
│       ├── networking/
│       ├── storage/
│       ├── security/
│       ├── utils/
│       ├── widgets/
│       │
│       ├── features/
│       │   ├── authentication/
│       │   ├── dashboard/
│       │   ├── patrol/
│       │   ├── gps_tracking/
│       │   ├── forest_map/
│       │   ├── incidents/
│       │   ├── geofencing/
│       │   ├── sos/
│       │   ├── notifications/
│       │   ├── chat/
│       │   ├── analytics/
│       │   ├── ai/
│       │   ├── weather/
│       │   ├── reports/
│       │   ├── users/
│       │   └── divisions/
│       │
│       ├── models/
│       ├── repositories/
│       └── services/
│
├── backend/
│   └── src/
│       ├── config/
│       ├── controllers/
│       ├── middleware/
│       ├── models/
│       ├── routes/
│       ├── services/
│       ├── repositories/
│       ├── validators/
│       ├── sockets/
│       ├── security/
│       └── utils/
│
├── ai-service/
│   ├── models/
│   ├── inference/
│   ├── prediction/
│   ├── computer_vision/
│   ├── risk_engine/
│   └── route_optimization/
│
├── docs/
│
├── .env.example
├── README.md
└── LICENSE
```

---

# ⚙️ Installation

## 1. Clone the Repository

```bash
git clone https://github.com/srakshitha0802/forest-guardian.git

cd forest-guardian
```

---

# 📱 Mobile Setup

```bash
cd mobile

flutter pub get

flutter run
```

Build Android:

```bash
flutter build apk
```

Production Android build:

```bash
flutter build appbundle
```

iOS:

```bash
flutter build ios
```

---

# 🖥️ Backend Setup

```bash
cd backend

npm install

npm run dev
```

Example environment configuration:

```env
PORT=5001

MONGODB_URI=mongodb://localhost:27017/forest_guardian

JWT_SECRET=your_secret
JWT_REFRESH_SECRET=your_refresh_secret

FIREBASE_PROJECT_ID=
FIREBASE_CLIENT_EMAIL=
FIREBASE_PRIVATE_KEY=

GOOGLE_MAPS_API_KEY=

WEATHER_API_KEY=

AI_SERVICE_URL=
```

Never commit real secrets to Git.

---

# 🤖 AI Service Setup

```bash
cd ai-service

python -m venv venv
```

Activate environment:

### Windows

```bash
venv\Scripts\activate
```

### macOS/Linux

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the AI service:

```bash
python main.py
```

---

# 🔑 Required Services

Depending on the modules enabled, Forest Guardian requires configuration for:

* Firebase Authentication
* Firebase Storage
* Firebase Cloud Messaging
* Google Maps Platform
* MongoDB
* Weather API
* AI/ML service

Firebase services are intended to be consumed through native mobile SDKs rather than a browser SDK.

---

# 🔄 Data Flow

### GPS Tracking

```text
Officer
   ↓
GPS Sensor
   ↓
Flutter App
   ↓
Local Database
   ↓
Sync Queue
   ↓
Node.js API
   ↓
MongoDB
   ↓
Analytics
```

### Incident + AI

```text
Officer
   ↓
Capture Incident
   ↓
Photo / Video
   ↓
Firebase Storage
   ↓
AI Service
   ↓
Classification
   ↓
Risk Score
   ↓
MongoDB
   ↓
Admin / Range Officer
```

### SOS

```text
Officer
   ↓
SOS
   ↓
Live GPS
   ↓
Backend
   ↓
FCM
   ├── Admin
   └── Nearby Officers
        ↓
   Emergency Response
```

---

# 🧪 Testing

The project should include:

```text
Unit Tests
     ↓
Widget Tests
     ↓
Integration Tests
     ↓
API Tests
     ↓
Offline Sync Tests
     ↓
GPS Tests
     ↓
SOS Tests
     ↓
Security Tests
     ↓
Load Tests
```

Critical scenarios include:

* Authentication
* RBAC
* GPS tracking
* Offline → Online synchronization
* Incident creation
* Media upload
* SOS response
* AI inference
* Notification delivery
* API authorization

The SRS specifically calls for testing of offline sync, background GPS, backend load, authentication, and role authorization.

---

# 📈 Scalability Target

The backend architecture is designed toward supporting:

**5,000+ concurrent active patrol sessions**

with GPS points ingested approximately every:

**5–10 seconds per officer**

The database should therefore use appropriate indexing and scalable GPS-log storage/query strategies.

---

# 🌐 Offline-First Philosophy

Forest Guardian is designed around one core principle:

> **No signal should not mean no protection.**

Even when officers lose connectivity, the application should continue supporting critical field operations such as:

* GPS tracking
* Patrol management
* Incident capture
* Evidence collection
* Local data storage

Once connectivity returns, synchronization happens automatically.

---

# 🎨 UI/UX Philosophy

The interface is designed for actual forest field conditions.

### Design Principles

**Fast**

Officers should complete critical actions quickly.

**Readable**

Information must remain visible in sunlight.

**Accessible**

Large touch targets and scalable typography.

**Reliable**

Important operations should work offline.

**Professional**

The application should feel like an enterprise/government operational system.

**Emergency-first**

SOS must always remain easily accessible.

The SRS specifies Material 3, forest-themed styling, dark mode, responsive layouts, gesture-friendly maps, and sunlight-readable typography.

---

# 🔮 Future Enhancements

Potential future capabilities include:

* 🛰️ Satellite imagery analysis
* 🚁 Drone integration
* ⌚ Smartwatch SOS
* 🌍 Advanced deforestation detection
* 🛰️ Satellite-based vegetation monitoring
* 🧠 Advanced predictive models
* 📡 Improved low-connectivity synchronization
* 🗺️ Advanced terrain intelligence

Satellite-based deforestation detection, drone feeds, and wearable integration are identified as future enhancements in the project requirements.

---

# 🏆 Why Forest Guardian?

Forest Guardian is not just another tracking application.

It combines:

```text
                    FOREST GUARDIAN
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
      GIS                  AI              EMERGENCY
       │                   │                   │
   GPS Tracking       Risk Prediction        SOS
   Geofencing         Image Analysis         Dispatch
   Forest Maps        Hotspots               Alerts
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                    OFFLINE-FIRST
                           │
                    FIELD OPERATIONS
```

The goal is to transform forest protection from **reactive monitoring** into **intelligent, data-driven and proactive forest management**.

---

# 📌 Project Status

**Status:** 🚧 Active Development

Forest Guardian is currently being developed as an advanced production-oriented prototype.

### Current Development Focus

* [x] Core mobile architecture
* [x] Multi-role application concept
* [x] Forest monitoring foundation
* [ ] Advanced offline synchronization
* [ ] Production GPS tracking
* [ ] AI risk engine
* [ ] AI image classification
* [ ] Advanced SOS response
* [ ] Real-time communication
* [ ] Analytics
* [ ] Automated reporting
* [ ] Security hardening
* [ ] Production deployment

---

# 👩‍💻 Development Philosophy

Forest Guardian follows these principles:

```text
Build for the field.
Design for low connectivity.
Automate intelligently.
Keep humans in control.
Protect sensitive data.
Measure everything.
Respond faster.
```

---

# 📜 Scope

Forest Guardian is currently designed as a **native/cross-platform mobile application**.

A browser-based dashboard and desktop client are **not part of the current release scope**.

---

# 🌲 Forest Guardian

### Protecting forests with intelligence, connectivity and technology.

**Monitor. Predict. Respond. Protect.**

---

<div align="center">

🌲 **Forest Guardian**

*AI-Powered Forest Monitoring & Emergency Response*

**Built for the future of forest protection.**

</div>
